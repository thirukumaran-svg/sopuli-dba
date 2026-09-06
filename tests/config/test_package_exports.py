"""`sopuli.config`'s lazy re-exports resolve to exactly what the eager ones did (#363).

The package stopped importing its submodules at module scope so that importing
`sopuli.config.errors` no longer drags in `bindings` and `sharing` -- which is
what made `sopuli.payload` unimportable, since those two import it back.

What that trades away is the compiler's help. An eager
`from sopuli.config.model import Config` is checked by the interpreter on every
import of the package; a name in a table is checked by nobody. So it is checked
here, in both directions and against the real objects:

* every name in ``__all__`` resolves, and to the *same object* its submodule
  holds -- not merely to something;
* every name in ``_EXPORTS`` is in ``__all__``, so the table cannot quietly grow
  a name the package does not advertise;
* the `TYPE_CHECKING` block, which is what keeps mypy exact, names the same set
  -- a name present there and missing from the table type-checks and then fails
  at run time, which is the worst of the two failure modes and the one this
  arrangement makes possible.
"""

from __future__ import annotations

import ast
from importlib import import_module
from pathlib import Path

import pytest

import sopuli.config as package
from sopuli.config import _EXPORTS

INIT = Path(package.__file__ or "")


def _type_checking_names() -> set[str]:
    """What the `if TYPE_CHECKING:` block imports, read from the source.

    Read rather than imported, because the whole point of that block is that it
    does not execute. `ast` is how a test asks what a branch would have done.
    """
    tree = ast.parse(INIT.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        guard = node.test
        if not (isinstance(guard, ast.Name) and guard.id == "TYPE_CHECKING"):
            continue
        for statement in node.body:
            if isinstance(statement, ast.ImportFrom):
                found.update(alias.name for alias in statement.names)
    return found


def test_every_advertised_name_resolves() -> None:
    """`__all__` is a promise, and `__getattr__` is now the only thing keeping it."""
    missing = [name for name in package.__all__ if not hasattr(package, name)]

    assert not missing, f"advertised in `__all__` and not resolvable: {missing}"


def test_each_name_is_the_submodule_s_own_object() -> None:
    """Resolving is not enough: it has to be the *same* object.

    A table mapping `Config` to the wrong module would still resolve -- to a
    different class with the same name, in the case of anything re-exported
    twice -- and every `isinstance` check downstream would start answering
    `False` for reasons nobody could see from the import.
    """
    wrong = {}
    for name, module in _EXPORTS.items():
        expected = getattr(import_module(f"sopuli.config.{module}"), name)
        if getattr(package, name) is not expected:
            wrong[name] = module

    assert not wrong, f"resolved to something other than the submodule's object: {wrong}"


def test_the_table_and_the_advertised_set_agree() -> None:
    """Neither list may grow a name the other does not have."""
    assert set(_EXPORTS) == set(package.__all__)


def test_the_type_checking_block_names_the_same_set() -> None:
    """The half a type checker sees must match the half that runs.

    A name imported under `TYPE_CHECKING` and absent from `_EXPORTS` passes mypy
    and raises `AttributeError` in production -- the failure this arrangement
    invents, and the reason it is worth a test of its own.
    """
    assert _type_checking_names() == set(_EXPORTS)


def test_an_unknown_name_still_raises_attribute_error() -> None:
    """`__getattr__` must not turn a typo into `None` or an import error."""
    with pytest.raises(AttributeError, match="has no attribute 'nosuch'"):
        package.nosuch  # noqa: B018 -- the attribute access *is* the assertion


def test_dir_answers_for_the_lazy_names_too() -> None:
    """`__getattr__` alone leaves `dir()` and tab-completion blank, which is a
    worse REPL than the eager version this replaced."""
    listed = dir(package)

    assert set(package.__all__) <= set(listed)
