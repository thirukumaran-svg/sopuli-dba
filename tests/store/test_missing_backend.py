"""What a configured-but-uninstalled backend does, end to end (#130, #134).

Two answers, and the whole of ADR-006's E4/E5 is that they are different:

* ``config validate`` **warns and exits 0**. The config is valid; the install is
  incomplete. Validating on a laptop a config that runs elsewhere is the common
  case, and a validator that calls a good file broken is less trustworthy for
  exactly the case it exists to serve.
* anything that resolves the store to a client **fails**, with ``SOPULI-20001``,
  ``error.category: "config"`` and exit 9.

**E4 reads "uninstalled" as "this machine cannot serve it"** since #238, so both
of its halves warn: a client `pip` can supply, and a backend nobody has written.
They are one code and one finding, differing in the remedy the message names.
The narrow reading -- the client alone -- left the validator saying ``0
warnings`` about a file whose every store was unusable, which is the one thing a
validator must not do.

The backend is forced absent by pointing its entry at a module nothing will ever
install, rather than by relying on this machine's install shape: the developer
environment is meant to be `sopuli-dba[all]`, where the real `hashicorp` entry is
installed and none of this would fire.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from sopuli import cli as cli_module
from sopuli import invocation as invocation_module
from sopuli.cli import cli
from sopuli.config.model import Config, Vault
from sopuli.diagnostics import MISSING_BACKEND, WARNINGS, install_diagnostics
from sopuli.exit_codes import ExitCode
from sopuli.install_shape import survey
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store.registry import BACKENDS, Backend, BackendNotInstalledError

SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

CONFIG = """version: 1
vaults:
  vault-prod:
    type: hashicorp
    mount: secret
  vault-dev:
    type: hashicorp
    mount: secret
"""

WriteConfig = Callable[[str], Path]


@pytest.fixture
def uninstalled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `hashicorp` name a client that is certainly not installed."""
    monkeypatch.setitem(
        BACKENDS,
        "hashicorp",
        Backend(
            module="sopuli.store.hashicorp",
            extra="hashicorp",
            provides=frozenset({"sopuli_absent_client_xyz"}),
        ),
    )


@pytest.fixture
def unwritten(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `hashicorp` name a backend with an extra and **no module**.

    ``oci``'s real shape, injected rather than used, for the reason this module
    already gives: the developer environment is `sopuli-dba[all]` and CI runs a
    base cell, so a test reading the machine's real install shape would assert
    different things in the two places.
    """
    monkeypatch.setitem(
        BACKENDS,
        "hashicorp",
        Backend(
            module="sopuli.store.absent_backend_xyz",
            extra="hashicorp",
            provides=frozenset({"sopuli_absent_client_xyz"}),
        ),
    )


def _validate_json(path: Path) -> dict[str, Any]:
    result = CliRunner().invoke(
        cli, ["--config", str(path), "--output", "json", "config", "validate"]
    )
    return dict(json.loads(result.output))


def _refuse(*_: object, **__: object) -> None:
    """Stand in for the first thing that resolves a store to a client.

    Raised from `discover` because nothing resolves a store yet (#104). What the
    tests below are about is what the boundary does with it, which does not
    depend on where inside the run it was raised.
    """
    raise BackendNotInstalledError(
        'vault "oci-prod" declares type "oci", but that backend is not installed',
        hint='install it with:  pip install "sopuli-dba[oci]"',
    )


# --------------------------------------------------- validate: warn, exit 0 ---


def test_validate_warns_and_exits_zero(uninstalled: None, write_config: WriteConfig) -> None:
    path = write_config(CONFIG)

    result = CliRunner().invoke(cli, ["--config", str(path), "config", "validate"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "2 warnings" in result.output
    assert 'vault "vault-prod" declares type "hashicorp"' in result.output
    assert 'pip install "sopuli-dba[hashicorp]"' in result.output


def test_the_warning_carries_its_code_in_json(uninstalled: None, write_config: WriteConfig) -> None:
    """A consumer branches on the code and never on the prose (J3's spelling)."""
    document = _validate_json(write_config(CONFIG))
    diagnostics = document["diagnostics"]

    assert [entry["code"] for entry in diagnostics] == [MISSING_BACKEND, MISSING_BACKEND]
    assert all(entry["level"] == "warning" for entry in diagnostics)
    assert document["exit_code"] == ExitCode.SUCCESS
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(document)


def test_one_warning_per_store_not_per_backend_type(
    uninstalled: None, write_config: WriteConfig
) -> None:
    """Two stores of the same missing type are two lines in the file to fix.

    Deliberately unlike the advisory-locking warning, which is one entry for a
    whole run: there the weakening is a property of the store, and here the unit
    the operator acts on is the entry they wrote.
    """
    document = _validate_json(write_config(CONFIG))
    messages = [entry["message"] for entry in document["diagnostics"]]

    assert len(messages) == 2
    assert any("vault-prod" in message for message in messages)
    assert any("vault-dev" in message for message in messages)


def test_an_unwritten_backend_is_not_sent_to_pip(
    unwritten: None, write_config: WriteConfig
) -> None:
    """#238's unambiguous half: `pip` cannot supply a backend nobody has written.

    The install line ran, succeeded, and left the store exactly as unusable --
    and moved the config from "warns wrongly" into "installed, and silent about a
    store that still cannot work", so following the advice made the validator
    quieter rather than the machine better.

    The warning's level and code are the same either way; what is fixed here is
    what it says. `file` and `keyring` -- which have no client to look for at all
    -- reach the same sentence through
    :func:`test_a_backend_with_no_module_warns_though_pip_cannot_help`.
    """
    document = _validate_json(write_config(CONFIG))
    messages = [entry["message"] for entry in document["diagnostics"]]

    assert document["exit_code"] == ExitCode.SUCCESS
    assert all(entry["code"] == MISSING_BACKEND for entry in document["diagnostics"])
    assert all(entry["level"] == "warning" for entry in document["diagnostics"])
    assert all("pip install" not in message for message in messages)
    assert all("this build has no hashicorp backend yet" in message for message in messages)


def test_the_unwritten_wording_is_the_one_doctor_uses(
    unwritten: None, write_config: WriteConfig
) -> None:
    """One definition of "this machine cannot serve it", not two (#237, #238).

    `config validate` warns and `doctor` errors -- the level is each command's own
    call and is meant to differ -- but the half of the sentence that states the
    fact is the same fact, and the two disagreeing about it is what produced the
    defect #237 fixed one layer up.
    """
    shape = survey(
        Config(version=1, vaults=(Vault(name="vault-prod", type="hashicorp", mount="secret"),))
    )
    (from_doctor,) = install_diagnostics(shape)
    from_validate = _validate_json(write_config(CONFIG))["diagnostics"][0]["message"]

    assert from_doctor.level == "error"
    assert "but this build has no hashicorp backend yet" in from_doctor.message
    assert from_doctor.message.split(", ", 1)[1] == from_validate.split(", ", 1)[1]


def test_a_backend_with_no_module_warns_though_pip_cannot_help(
    write_config: WriteConfig,
) -> None:
    """The case that was wrong for every user, and that no amount of installing
    fixed (#238).

    `file` and `keyring` have no extra -- ADR-006's named gap -- so the narrow
    reading found nothing to look for and said nothing, on every machine,
    unconditionally. A file declaring only those validated as ``0 warnings`` and
    could not work anywhere.

    Warning about it is not actionable by `pip`, and that is not the same as not
    actionable: the action is *do not deploy this yet*, and it is the fact its
    reader most needs before shipping a config they cannot test locally. The cost
    is temporary by construction -- it goes away backend by backend as they are
    written -- where the silence it replaces was permanent.

    **No fixture.** This is the one assertion in the module that needs none: the
    answer does not depend on what is installed, only on what is written, so it
    is the same on a developer machine and in CI's base cell.
    """
    document = _validate_json(write_config("version: 1\nvaults:\n  local:\n    type: file\n"))
    (found,) = document["diagnostics"]

    assert document["exit_code"] == ExitCode.SUCCESS
    assert found["level"] == "warning"
    assert found["code"] == MISSING_BACKEND
    assert "pip install" not in found["message"]
    assert "this build has no file backend yet" in found["message"]


def test_every_store_this_machine_cannot_serve_is_named(write_config: WriteConfig) -> None:
    """The report `config validate` owes its reader, and did not give (#238).

    Three of the four types in ``01-configuration.md`` §3a have no module, so a
    config declaring all four is a config whose stores are three-quarters
    unusable. It reported **one** warning before this -- and which one depended
    on whether the machine happened to have the OCI SDK, which is a fact about
    the laptop and not about the file.

    Asserted as a set rather than a list: the order is the survey's, sorted by
    backend name, and pinning it here would be pinning `doctor`'s table through a
    test about warnings.
    """
    document = _validate_json(
        write_config(
            "version: 1\n"
            "vaults:\n"
            "  vault-hc:\n    type: hashicorp\n    mount: secret\n"
            "  vault-dr:\n    type: oci\n"
            "  vault-local:\n    type: file\n"
            "  vault-desktop:\n    type: keyring\n"
        )
    )
    named = {
        name
        for name in ("vault-dr", "vault-local", "vault-desktop")
        if any(f'"{name}"' in entry["message"] for entry in document["diagnostics"])
    }

    assert named == {"vault-dr", "vault-local", "vault-desktop"}
    assert document["exit_code"] == ExitCode.SUCCESS


def test_the_warning_code_is_in_the_registry() -> None:
    """`03-json-output.md` §3: a code is contract, and the registry is what says
    what it means. `tests/test_lock_view.py` asserts nothing emits a code the
    registry does not describe; this asserts the entry is there to be found, and
    that it points at the error code for the case that does fail."""
    assert MISSING_BACKEND in WARNINGS
    assert "SOPULI-20001" in WARNINGS[MISSING_BACKEND]


# ------------------------------------------------- resolving one: exit 9 ---


def test_resolving_an_uninstalled_backend_exits_nine_with_the_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: WriteConfig,
) -> None:
    """E5, at the boundary that turns the exception into an exit code.

    **No command resolves a store to a client yet** -- the first one arrives with
    #104 -- so the error is raised from the first thing `config validate` calls.
    What is under test is what the boundary does with it, which is the same
    wherever inside a run it is raised: exit 9, `config`, and the code.

    Through `main` rather than the runner, because the exit code is the contract
    and `main` is what maps a `ConfigError` onto it.
    """
    path = write_config(CONFIG)
    monkeypatch.setattr(invocation_module, "discover", _refuse)
    monkeypatch.setattr(sys, "argv", ["sopuli", "config", "validate", "--config", str(path)])

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main()

    assert exit_info.value.code == ExitCode.CONFIG_INVALID
    captured = capsys.readouterr()
    assert 'pip install "sopuli-dba[oci]"' in captured.err


def test_the_failure_document_carries_the_error_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: WriteConfig,
) -> None:
    """The reason the code exists at all: a scheduler branches on *this* failure
    rather than on config errors generally, without parsing the message."""
    path = write_config(CONFIG)
    monkeypatch.setattr(invocation_module, "discover", _refuse)
    monkeypatch.setattr(
        sys,
        "argv",
        ["sopuli", "--output", "json", "config", "validate", "--config", str(path)],
    )

    with pytest.raises(SystemExit):
        cli_module.main()

    document = json.loads(capsys.readouterr().out)
    assert document["error"]["code"] == "SOPULI-20001"
    assert document["error"]["category"] == "config"
    assert document["exit_code"] == ExitCode.CONFIG_INVALID
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(document)


def test_an_ordinary_config_error_still_has_no_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    write_config: WriteConfig,
) -> None:
    """`code` is omitted rather than nulled when absent, which is what the rest
    of the document already does -- and what keeps a consumer testing
    `"code" in error` and one testing `error["code"] is not None` from
    disagreeing."""
    path = write_config("version: 1\ntargts: []\n")
    monkeypatch.setattr(
        sys,
        "argv",
        ["sopuli", "--output", "json", "config", "validate", "--config", str(path)],
    )

    with pytest.raises(SystemExit):
        cli_module.main()

    document = json.loads(capsys.readouterr().out)
    assert document["exit_code"] == ExitCode.CONFIG_INVALID
    assert "code" not in document["error"]
