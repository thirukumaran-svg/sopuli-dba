"""A store's settings in `--explain` and in `config.vaults[]` (#428).

`config show` reported **which** key a layer wrote and never **which layer**.
Three different layers redirecting `addr` produced one indistinguishable
`layered: addr` in the `NOTE` column, a profile's block and `defaults.vaults:`
produced the same line, and the JSON said less again: `--explain` emitted
`config.declared`, which is the address the *file* wrote, and `--resolved`
dropped stores entirely. So no mode of the command answered "which vault will
this run talk to", let alone "why".

Tier 0: a document in, rendered lines and a JSON dict out.

The value is the substantive half here and the provenance rides along with it,
which is the ordering worth keeping in mind while reading the JSON assertions --
you cannot report where `addr` came from before reporting what `addr` is.

Four things are worth asserting rather than the rows appearing:

* **the store is concrete**, `vaults.vault-dev.addr` and never the registry's
  `vaults.*.addr`, which stands for every store at once and is nothing an
  operator can act on;
* **a store nobody layered reports its own declaration**, because otherwise an
  absent row means either *nobody wrote it* or *only the file did*;
* **the rows are `--explain`'s**, not `config show`'s -- the table is where a
  location can be shown untruncated, which is the reason that view is laid out
  by hand;
* **`auth:` never reaches either view**, being replaced whole rather than
  resolved -- and being the one part of a store entry that addresses credentials.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from sopuli.config.loading import build_config
from sopuli.config.model import Config
from sopuli.invocation import RESOLVED_SETTINGS
from sopuli.output.config_view import build_section, render_text
from sopuli.settings import Contribution, Resolved, resolve_all
from sopuli.settings.sources import config_contributions

STORE = "vault-dev"
PROFILE = "standby"

DECLARED = {"type": "hashicorp", "addr": "https://vault-dev.example.com:8200", "mount": "kv"}


def document(vault: dict[str, Any] | None = None, **sections: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "vaults": {STORE: {**DECLARED, **(vault or {})}},
        "defaults": {"vault": STORE, **sections.pop("defaults", {})},
        "accounts": ["acme_app_user"],
        "secret_template": f"{STORE}:acme/dev/db#{{account}}",
        "targets": [
            {
                "name": "alpha-0",
                "type": "oracle",
                "dsn": "192.0.2.10:1521/ALPHA",
                "environment": "dev",
                "admin": {"username": "SOPULI_SVC", "auth": {"method": "env"}},
            }
        ],
        **sections,
    }


def built(vault: dict[str, Any] | None = None, **kwargs: Any) -> Config:
    """One config, with whatever `build_config` takes for the outer layers."""
    passed = {key: kwargs.pop(key) for key in ("profile", "env", "vault_addr") if key in kwargs}
    return build_config(document(vault, **kwargs), **passed)


def run_settings(config: Config) -> dict[str, Resolved]:
    """The run's own settings, as the boundary resolves them.

    Real ones rather than an empty mapping with one row bolted on: the store's
    rows share a table with these, and asserting on alignment or ordering against
    a table of one row would assert nothing about the one an operator reads.

    Seeded with :data:`~sopuli.invocation.RESOLVED_SETTINGS` the way the boundary
    seeds it, so the built-in defaults are in the table too -- a setting nothing
    supplied is absent from ``config_contributions`` and is still a row.
    """
    supplied: dict[str, list[Contribution]] = {name: [] for name in RESOLVED_SETTINGS}
    for name, contributions in config_contributions(config).items():
        supplied[name].extend(contributions)
    return resolve_all(supplied)


def explained(config: Config, *, resolved: bool = False) -> list[str]:
    """The `settings` block of the rendered view, its heading dropped."""
    text = click.unstyle(
        render_text([Path("estate.yaml")], config, resolved=resolved, settings=run_settings(config))
    )
    body = text.split("\nsettings\n")
    return [] if len(body) == 1 else body[1].split("\n\n")[0].splitlines()


def rows(config: Config, *, resolved: bool = False) -> dict[str, str]:
    """Store rows only, as `name -> [source]`."""
    found = {}
    for line in explained(config, resolved=resolved):
        if not line.strip().startswith("vaults."):
            continue
        name, _, rest = line.strip().partition("=")
        found[name.strip()] = rest.rsplit("[", 1)[1].removesuffix("]")
    return found


def json_vaults(config: Config, *, resolved: bool = False) -> list[dict[str, Any]]:
    section = build_section([Path("estate.yaml")], config, {"version": 1}, resolved=resolved)
    vaults: list[dict[str, Any]] = section["vaults"]
    return vaults


# -------------------------------------------------------------------- the rows ---


def test_a_store_row_names_the_concrete_store() -> None:
    """`vaults.*.addr` is the registry's key and stands for every store at once
    (`sopuli/settings/registry.py`). The row has to name the one an operator
    would grep their file for -- which is also the spelling of the config key, so
    the name and the location agree."""
    assert set(rows(built())) == {f"vaults.{STORE}.addr", f"vaults.{STORE}.mount"}


def test_a_store_nobody_layered_reports_its_own_declaration() -> None:
    """`[vaults.vault-dev.addr]` is the answer "the file wrote it, here", and the
    row is the only thing that distinguishes it from "nobody wrote it".

    The bracket repeats the row name exactly in this one case, which is not noise
    -- it is what that sentence looks like. `[defaults.safety.readonly]` under
    `safety.readonly` is the same shape one word longer, and the alternative is a
    view where the absence of a bracket has to be read as a layer.
    """
    assert rows(built()) == {
        f"vaults.{STORE}.addr": f"vaults.{STORE}.addr",
        f"vaults.{STORE}.mount": f"vaults.{STORE}.mount",
    }


def test_the_flag_the_variables_and_the_file_are_told_apart() -> None:
    """The gap this closes, in the view that closes it. Every one of these was
    `layered: addr` before, and two of them are not even in the file."""
    assert rows(built(vault_addr="https://standby.example.com"))[f"vaults.{STORE}.addr"] == (
        "cli --vault-addr"
    )
    assert rows(built(env={"VAULT_ADDR": "https://exported.example.com"}))[
        f"vaults.{STORE}.addr"
    ] == ("env_thirdparty VAULT_ADDR")
    assert (
        rows(
            built(
                profiles={PROFILE: {"vaults": {STORE: {"addr": "https://p.example.com"}}}},
                profile=PROFILE,
            )
        )[f"vaults.{STORE}.addr"]
        == f"profiles.{PROFILE}.vaults.{STORE}.addr"
    )


def test_the_layer_word_is_dropped_where_the_location_is_a_config_key() -> None:
    """`object vaults.vault-dev.addr` says nothing twice: "object" is this
    chain's word for a layer's rank and appears in nobody's YAML, while the path
    already names the store and the key. The same rule `defaults.…` gets, which
    cannot be reached by matching here because the section a store lives in is
    not named after the layer."""
    assert "object" not in " ".join(explained(built()))


def test_the_rows_are_absent_without_explain() -> None:
    """`config show` answers what the file says; where a value came from is
    `--explain`'s question, and a store's keys do not change the split."""
    text = click.unstyle(render_text([Path("estate.yaml")], built(), resolved=False))

    assert "settings" not in text
    assert f"vaults.{STORE}.addr" not in text


def test_the_store_rows_share_one_aligned_table_with_the_run_s() -> None:
    """One table rather than a second section under its own heading: they are
    settings of one chain, resolved by one resolver, and P3's own worked example
    of this view is a vault key. A column that wanders is a column nobody scans.
    """
    lines = explained(built())

    assert any(line.strip().startswith("output") for line in lines)
    assert len({line.index("=") for line in lines}) == 1
    assert len({line.index("[") for line in lines}) == 1


def test_the_rows_survive_the_resolved_view() -> None:
    """`--resolved` replaces the file's sections with the estate's, and the
    settings table is appended to either (`render_text`)."""
    assert rows(built(), resolved=True) == rows(built())


def test_a_defeated_relaxation_is_named_under_the_store_s_own_row() -> None:
    """`tls.verify` is the one vault key under the ratchet, so it is the one that
    can have a loser. The row reports the floor -- the layer to go and edit --
    and the note names the layer that asked."""
    config = built(
        {"tls": {"verify": True}},
        profiles={PROFILE: {"vaults": {STORE: {"tls": {"verify": False}}}}},
        profile=PROFILE,
    )
    lines = explained(config)
    verify = next(i for i, line in enumerate(lines) if f"vaults.{STORE}.tls.verify" in line)

    assert f"[vaults.{STORE}.tls.verify]" in lines[verify]
    assert "asked for false" in lines[verify + 1]
    assert "ratchet toward safe" in lines[verify + 1]
    # The note names the concrete store, not the registry's `vaults.*.tls.verify`
    # (found in review). The first version of this test asserted the two fragments
    # above and passed while the continuation line read `vaults.*.tls.verify stays
    # true` directly beneath a row named `vaults.vault-dev.tls.verify` -- one
    # three-line block disagreeing with itself about what the key is called.
    assert "vaults.*" not in lines[verify + 1]
    assert f"vaults.{STORE}.tls.verify stays true" in lines[verify + 1]


def test_auth_gets_no_row() -> None:
    """It is replaced whole rather than resolved key by key, so no layer *won* a
    key -- and it is the one part of a store entry that addresses credentials.
    The store's `NOTE` column still says it was layered."""
    config = built(
        {"auth": {"method": "token"}},
        defaults={"vaults": {STORE: {"auth": {"method": "instance_principal"}}}},
    )

    assert "auth" in config.vaults[0].patched
    assert not [name for name in rows(config) if "auth" in name]


# -------------------------------------------------------------------- the JSON ---


def test_the_effective_settings_reach_json_in_both_shapes() -> None:
    """The half of #428 that was not a provenance question at all: `--explain`
    emitted `config.declared`, the address the *file* wrote, and `--resolved`
    emitted targets and bindings with no store among them. A consumer could not
    ask which vault a run would use, under any layer."""
    for resolved in (False, True):
        [store] = json_vaults(built(vault_addr="https://standby.example.com"), resolved=resolved)

        assert store["name"] == STORE
        assert store["type"] == "hashicorp"
        assert store["settings"]["addr"]["value"] == "https://standby.example.com"


def test_a_setting_carries_the_layer_and_the_location() -> None:
    """The same `value` / `source` / `source_detail` triple `invocation.options`
    carries, pointed at the same `$defs/resolved_setting`: one question about one
    resolver, so a second grammar for it would be two shapes for one fact."""
    [store] = json_vaults(built(env={"SOPULI_VAULT__VAULT_DEV__ADDR": "https://n.example.com"}))

    assert store["settings"]["addr"] == {
        "value": "https://n.example.com",
        "source": "env",
        "source_detail": "SOPULI_VAULT__VAULT_DEV__ADDR",
    }
    assert store["settings"]["mount"] == {
        "value": "kv",
        "source": "object",
        "source_detail": f"vaults.{STORE}.mount",
    }


def test_a_key_no_layer_wrote_is_absent_rather_than_null() -> None:
    """A store with no namespace has no provenance for one, and a null would
    invite a consumer to branch on a field that is empty almost always."""
    [store] = json_vaults(built())

    assert set(store["settings"]) == {"addr", "mount"}


def test_auth_is_not_in_the_settings_object() -> None:
    """Whole-block replacement, so there is no `Resolved` to report -- and the
    block names where auth material lives, which has no business in a section
    whose every value is a setting."""
    [store] = json_vaults(built({"auth": {"method": "token", "token": {"env": "VAULT_TOKEN"}}}))

    assert "auth" not in store["settings"]
    assert "VAULT_TOKEN" not in str(store)


def test_an_estate_with_no_stores_reports_an_empty_array() -> None:
    """Always present, the way `doctor`'s own `vaults[]` is: every estate that
    does anything has stores, so `[]` is a real answer rather than the negative
    finding an absent `shared_secrets` would be."""
    config = build_config({"version": 1, "targets": []})

    assert json_vaults(config) == []


def test_the_ratcheted_key_reports_the_value_that_held() -> None:
    """Not the one the highest layer asked for. A contract carrying
    `verify: false` for a connection the tool then verifies would be the lie this
    section was added to remove -- the same argument `config.targets[].safety`
    makes about a flattened `readonly` (#426)."""
    [store] = json_vaults(
        built(
            {"tls": {"verify": True}},
            profiles={PROFILE: {"vaults": {STORE: {"tls": {"verify": False}}}}},
            profile=PROFILE,
        )
    )

    assert store["settings"]["tls.verify"] == {
        "value": True,
        "source": "object",
        "source_detail": f"vaults.{STORE}.tls.verify",
    }
