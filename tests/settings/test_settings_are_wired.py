"""Every declared setting either reaches a consumer or says why it does not.

A setting or a field can be resolved, ratcheted, validated and rendered by
`config show`, and still be read by nothing. Four real cases had that shape:

* `safety.confirm_environments`, parsed and ratcheted and consulted by no
  command;
* `UserState.password_file_member`, typed and read by guardrail 3 and populated
  by nothing;
* `locking.break_expired`, cross-checked in two places and implemented in
  `decide()`, with no `LockManager` built with it (decision #348);
* `lock_diagnostics`, written and unit-tested and called by nothing.

Each looks like protection and is not, and only somebody reading the code would
find it. The registry knows every setting, so this sweep runs on every commit
instead of waiting for the next person who happens to look.

**A tripwire, not a proof.** What it checks is that the *name* reaches a module
that is not the settings machinery -- not that the value changes behaviour. A
setting read into a variable and then dropped would pass, and so would one
mentioned in the wrong branch. Catching those needs dataflow analysis; all four
cases above are the simpler thing, and so is `db.query_timeout_s`.

**Both directions are checked, and the second is the one that lasts.** A setting
carrying `inert_reason` must have *no* consumer, so wiring one up fails this
suite until somebody deletes the reason -- which is the moment to ask whether the
design documents still say the right thing. A document can call a setting
inert after code has started to read it, as `_timeouts()` reads
`db.query_timeout_s`; prose alone cannot hold that claim, because it decays
without failing anything.
"""

from __future__ import annotations

import ast
from functools import cache
from pathlib import Path

import pytest

from sopuli.config.vault_layers import REACH_KEYS, TLS_KEYS, setting_name
from sopuli.invocation import RESOLVED_SETTINGS
from sopuli.settings.registry import SETTINGS

SRC = Path(__file__).resolve().parents[2] / "src" / "sopuli"

#: The settings machinery itself. A name here is being *declared*, mapped to an
#: environment variable, or resolved -- never acted on.
DECLARING_PACKAGE = SRC / "settings"

INVOCATION = SRC / "invocation.py"

#: `invocation.py` is both halves, which is why the exclusion is by *region*
#: rather than by file. `RESOLVED_SETTINGS` lists every name, and
#: `_cli_contributions` supplies values from argv -- both the source side. The
#: same file's `Invocation.dry_run` reads `safety.dry_run` and is a genuine
#: consumer, so excluding the whole file would report `safety.dry_run` as an
#: orphan when it is the most consulted setting in the tool.
DECLARING_IN_INVOCATION = ("RESOLVED_SETTINGS", "_cli_contributions")


def _constructed() -> set[str]:
    """Per-store names, which are built rather than written.

    `vaults.*.addr` and its ten siblings appear as a literal nowhere:
    `config/vault_layers.py` calls `resolve(setting_name(key), ...)` over
    `REACH_KEYS` and `TLS_KEYS`, so the `*` is filled in at run time and a search
    for the spelling finds only the registry. Computed here from the same two
    tuples the consumer walks, so a key added to one is covered without an edit
    here -- and a *new* family built some other way fails this test, which is the
    right way to find out that the sweep needs widening.
    """
    return {setting_name(key) for key in REACH_KEYS} | {
        setting_name(f"tls.{key}") for key in TLS_KEYS
    }


def _docstrings(tree: ast.AST) -> set[int]:
    """Every docstring node, by identity.

    Prose is not a consumer. Several modules name a setting in a docstring to
    explain what they do near it, and counting those would make the sweep report
    a wired setting for every key anybody wrote a sentence about.
    """
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def _declaring_spans(path: Path, tree: ast.Module) -> list[tuple[int, int]]:
    """Line ranges in ``path`` that declare settings rather than consume them."""
    if path.parent == DECLARING_PACKAGE:
        return [(0, 10**9)]
    if path != INVOCATION:
        return []
    spans = []
    for node in tree.body:
        assigned = isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in DECLARING_IN_INVOCATION
            for target in node.targets
        )
        defined = isinstance(node, ast.FunctionDef) and node.name in DECLARING_IN_INVOCATION
        if assigned or defined:
            spans.append((node.lineno, node.end_lineno or node.lineno))
    return spans


@cache
def _readable_strings() -> tuple[tuple[str, str], ...]:
    """Every string literal in `src/` that could name a setting, with where.

    Parsing the tree is the expensive half and it does not depend on which names
    are being asked about, so it happens once for the module rather than once per
    test. 123 files under `src/sopuli` today, four tests, and the difference is
    about 1.8 s of parsing down to about 0.5 s -- small against an eight-minute
    suite, and free.

    Docstrings and the declaring regions are dropped *here*, so what comes back
    is only the places a name is being used for something.
    """
    found: list[tuple[str, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        spans = _declaring_spans(path, tree)
        prose = _docstrings(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in prose:
                continue
            if any(low <= node.lineno <= high for low, high in spans):
                continue
            found.append((node.value, f"{path.relative_to(SRC).as_posix()}:{node.lineno}"))
    return tuple(found)


def consumers(names: set[str]) -> dict[str, list[str]]:
    """Where each of ``names`` is read, outside the settings machinery.

    Public and taking its names as an argument so the tests below can point it
    at something whose answer is already known -- see
    `test_the_sweep_reports_a_name_that_nothing_reads`. A sweep that can only be
    run over the real registry is one whose failure mode nobody has seen.
    """
    found: dict[str, list[str]] = {name: [] for name in names}
    for name in _constructed() & names:
        found[name].append("config/vault_layers.py (built by setting_name)")

    for value, where in _readable_strings():
        if value in names:
            found[value].append(where)
    return found


def test_every_setting_that_is_not_declared_inert_has_a_consumer() -> None:
    """A key nobody reads is a key that lies about what it does."""
    wired = consumers(set(SETTINGS))
    orphans = {
        name: definition.inert_reason
        for name, definition in SETTINGS.items()
        if definition.inert_reason is None and not wired[name]
    }

    assert not orphans, (
        f"resolved, ratcheted, and read by nothing: {sorted(orphans)}. Wire it to "
        f"whatever should act on it, or declare `inert_reason=` on it saying why "
        f"it is accepted and ignored"
    )


def test_every_setting_declared_inert_really_is() -> None:
    """The direction that stops the marking rotting.

    Without it `inert_reason` would be the same claim `01-configuration.md` §5
    was making in prose, in a different file -- true when written and quietly
    false a release later. This way, wiring an inert key up breaks the suite
    until the reason is deleted, and deleting it is what sends somebody to the
    documents.
    """
    wired = consumers(set(SETTINGS))
    contradicted = {
        name: wired[name]
        for name, definition in SETTINGS.items()
        if definition.inert_reason is not None and wired[name]
    }

    assert not contradicted, (
        f"declared inert and read anyway: {contradicted}. Something now consults "
        f"these -- delete `inert_reason=` and check that the design documents still "
        f"describe what the key does"
    )


def test_every_wired_setting_can_actually_be_resolved() -> None:
    """The hole the sweep above cannot see (decision #360).

    A consumer is half a wire. `_timeouts()` read `db.connect_timeout_s` off
    `Invocation.resolved` while the name was absent from `RESOLVED_SETTINGS`, so
    it was never *in* that mapping: the read returned `None` on every run and the
    built-in was used whatever the profile said. The sweep above reported it as
    wired, correctly by its own rule -- the name does reach a module -- and
    that rule is exactly what its docstring warns is not a proof.

    This is the other end, and it is structural rather than textual: a run
    setting that is not resolved at run time cannot be read at run time,
    whoever mentions it. `vaults.*` is exempt because it is resolved inside the
    file by `config/vault_layers.py`, which is the same exemption the sweep makes
    for it and for the same reason -- it describes a store, not a run.
    """
    resolvable = set(RESOLVED_SETTINGS) | _constructed()
    wired = consumers(set(SETTINGS))
    stranded = {
        name: wired[name]
        for name, definition in SETTINGS.items()
        if definition.inert_reason is None and wired[name] and name not in resolvable
    }

    assert not stranded, (
        f"read at run time and never resolved into `Invocation.resolved`, so the read "
        f"returns None every time: {sorted(stranded)}. Add the name to "
        f"`invocation.RESOLVED_SETTINGS` and contribute it in "
        f"`settings/sources.py`, or the consumer is reading a mapping it is not in"
    )


def test_a_reason_that_says_nothing_is_refused() -> None:
    """The reason is the point: it is what a reader needs in order to judge
    whether the marking is still true."""
    from sopuli.settings.registry import Layer, MergePolicy, Setting

    with pytest.raises(ValueError, match="marked inert with no reason"):
        Setting(
            name="db.query_timeout_s",
            type=int,
            layers=frozenset({Layer.PROFILE}),
            policy=MergePolicy.OVERRIDE,
            inert_reason="   ",
        )


def test_the_sweep_reports_a_name_that_nothing_reads() -> None:
    """The sweep can fail, which is not obvious from a suite where it passes.

    A detector that answered "wired" to everything would make both tests above
    green for ever and catch the sixth instance never. So it is asked about a
    name no module contains, and has to say so.
    """
    assert consumers({"db.query_timeout_s.nonesuch"}) == {"db.query_timeout_s.nonesuch": []}


def test_the_sweep_does_not_count_the_registry_as_a_consumer() -> None:
    """The other way it could be vacuous. Every setting is a literal in
    `settings/registry.py` by construction, so a sweep that counted the
    declaration would report the whole registry wired -- which is exactly the
    answer that let those four through."""
    wired = consumers(set(SETTINGS))

    assert not [where for found in wired.values() for where in found if "settings/" in where]
