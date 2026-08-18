"""The registry that maps ``vaults.*.type`` to a module (#130, #134).

Everything here is about **telling three failures apart**. All three arrive as
``ModuleNotFoundError``, only one of them is "install the extra", and the one
that is easiest to get wrong -- a bad import inside a backend module -- is the
expensive one: collapsing it into the first sends somebody to `pip` forever over
a typo of ours.

The backends are faked rather than real. `sopuli.store.hashicorp` does not exist
yet, so with the real mapping every case here would take the same branch (the
module is missing) and the test would prove nothing about the branch it claims
to be about. Fake modules written into ``tmp_path`` let each failure be produced
deliberately, one at a time.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from sopuli.config.model import Vault
from sopuli.config.vaults import VAULT_TYPES
from sopuli.exit_codes import ExitCode
from sopuli.store.registry import (
    BACKEND_NOT_INSTALLED,
    BACKENDS,
    Backend,
    BackendNotImplementedError,
    BackendNotInstalledError,
    installed,
    resolve,
)

#: A top-level module name nothing will ever install.
ABSENT = "sopuli_absent_client_xyz"


def vault(name: str = "vault-prod", backend: str = "hashicorp") -> Vault:
    return Vault(name=name, type=backend)


#: Writes a module and returns the name to import it by.
MakeModule = Callable[[str], str]


@pytest.fixture
def module_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MakeModule:
    """Writes an importable module and returns its name.

    Each gets a name of its own: :func:`importlib.import_module` caches in
    ``sys.modules``, so a shared name would make the second test in a run assert
    against the first one's module.
    """
    monkeypatch.syspath_prepend(str(tmp_path))
    made: list[str] = []

    def make(body: str) -> str:
        name = f"sopuli_fake_backend_{len(made)}"
        (tmp_path / f"{name}.py").write_text(body, encoding="utf-8")
        made.append(name)
        monkeypatch.delitem(sys.modules, name, raising=False)
        return name

    return make


# --------------------------------------------------------------- the mapping ---


def test_every_configurable_type_has_a_backend() -> None:
    """A type the config layer accepts and this one has never heard of would
    reach a `KeyError` at connect time -- the traceback rule 2 exists to
    prevent, arriving from the one place that promised to prevent it."""
    assert set(VAULT_TYPES) == set(BACKENDS)


def test_no_backend_module_is_importable_at_package_import_time() -> None:
    """Rule 1, from the registry's side: the mapping is strings, not imports.

    If this module had imported the backends to build the table, every extra
    would be a base dependency and the rest of the design would be decoration.
    """
    assert not [name for name in sys.modules if name.startswith("sopuli.store.hashicorp")]


# ------------------------------------------------------------------ installed ---


def test_a_backend_whose_client_is_present_is_installed() -> None:
    # `json` stands in for a vendor client: always importable, so the assertion
    # is about the lookup rather than about anybody's install.
    assert installed(Backend(module="x", extra="stdlib", provides=frozenset({"json"})))


def test_a_backend_whose_client_is_absent_is_not_installed() -> None:
    assert not installed(Backend(module="x", extra="e", provides=frozenset({ABSENT})))


def test_a_backend_with_no_extra_is_vacuously_installed() -> None:
    """`file` and `keyring` have no client to look for (ADR-006's named gap).

    Vacuously true rather than false, so `config validate` stays quiet about
    them instead of warning that something unnamed is missing. Their real state
    -- no module in this build -- is `resolve`'s to report.
    """
    assert installed(BACKENDS["file"])
    assert installed(BACKENDS["keyring"])


def test_installed_does_not_import_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Asking must not run a vendor package's import side effects: for an SDK
    that can mean reading a config file or calling a metadata service, which is
    exactly what rule 3 says base does not do."""
    monkeypatch.delitem(sys.modules, "wave", raising=False)

    assert installed(Backend(module="x", extra="e", provides=frozenset({"wave"})))
    assert "wave" not in sys.modules


# -------------------------------------------------------------------- resolve ---


def test_resolve_imports_the_backend_module(
    module_factory: MakeModule, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = module_factory("MARKER = 'imported'\n")
    monkeypatch.setitem(BACKENDS, "hashicorp", Backend(module=name, extra="hashicorp"))

    assert resolve(vault()).MARKER == "imported"


def test_a_missing_client_names_the_extra(
    module_factory: MakeModule, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = module_factory(f"import {ABSENT}\n")
    monkeypatch.setitem(
        BACKENDS,
        "oci",
        Backend(module=name, extra="oci", provides=frozenset({ABSENT})),
    )

    with pytest.raises(BackendNotInstalledError) as caught:
        resolve(vault(name="oci-prod", backend="oci"))

    error = caught.value
    # The message §3a and the root README both quote, word for word.
    assert str(error.message) == (
        'vault "oci-prod" declares type "oci", but that backend is not installed'
    )
    assert error.hint == 'install it with:  pip install "sopuli-dba[oci]"'


def test_a_missing_client_is_config_and_exit_nine() -> None:
    """E5: `config`, not `capability`. `capability` names what a *target* cannot
    do -- a property of the far end that no local action changes. This is fixed
    on this machine by the person reading the message."""
    error = BackendNotInstalledError("x")

    assert error.category == "config"
    assert error.exit_code == ExitCode.CONFIG_INVALID
    assert error.code == BACKEND_NOT_INSTALLED == "SOPULI-20001"


def test_an_unwritten_backend_is_not_a_pip_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live right now: §3a accepts four types and no backend module exists yet.

    The distinction is the whole point of having two classes. Nothing the
    operator installs fixes this one, so the message must not carry an install
    line -- and it must not be reported as the other case, which would send them
    to `pip` for something `pip` cannot supply.
    """
    monkeypatch.setitem(
        BACKENDS,
        "hashicorp",
        Backend(
            module="sopuli.store.definitely_not_written",
            extra="hashicorp",
            provides=frozenset({ABSENT}),
        ),
    )

    with pytest.raises(BackendNotImplementedError) as caught:
        resolve(vault())

    assert "no hashicorp backend yet" in caught.value.message
    assert "pip install" not in (caught.value.hint or "")
    assert caught.value.code is None


def test_a_broken_import_inside_a_backend_is_re_raised(
    module_factory: MakeModule, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The expensive mistake, asserted directly.

    A module that exists and cannot import itself is a bug in this project. A
    bare `except ImportError` would report it as "install the extra" and the
    stack trace -- the only thing that locates the typo -- would be gone.
    """
    name = module_factory("from sopuli.store.not_a_real_module import Store\n")
    monkeypatch.setitem(
        BACKENDS,
        "hashicorp",
        Backend(module=name, extra="hashicorp", provides=frozenset({"httpx"})),
    )

    with pytest.raises(ModuleNotFoundError) as caught:
        resolve(vault())

    assert caught.value.name == "sopuli.store.not_a_real_module"


def test_a_missing_symbol_inside_a_backend_is_re_raised(
    module_factory: MakeModule, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same rule for the other shape of the mistake: a plain `ImportError`
    rather than a `ModuleNotFoundError`, which a client-was-not-installed match
    must not swallow either."""
    name = module_factory("from sopuli.store.protocol import NotAThingThatExists\n")
    monkeypatch.setitem(
        BACKENDS,
        "hashicorp",
        Backend(module=name, extra="hashicorp", provides=frozenset({"httpx"})),
    )

    with pytest.raises(ImportError):
        resolve(vault())


def test_the_client_match_is_on_the_module_that_was_missing(
    module_factory: MakeModule, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: a backend importing *some other* absent third-party module
    is not evidence that its own extra is uninstalled.

    Without the `provides` check this would report "install sopuli-dba[hashicorp]"
    for a dependency `sopuli-dba[hashicorp]` does not contain, and installing it
    would change nothing.
    """
    name = module_factory("import some_unrelated_absent_package\n")
    monkeypatch.setitem(
        BACKENDS,
        "hashicorp",
        Backend(module=name, extra="hashicorp", provides=frozenset({"httpx"})),
    )

    with pytest.raises(ModuleNotFoundError) as caught:
        resolve(vault())

    assert caught.value.name == "some_unrelated_absent_package"
