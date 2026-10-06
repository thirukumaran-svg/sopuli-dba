"""`reset_records:` -- where UC-2 journals a reset (H2, #450, #468).

Tier 0, pure: everything builds from a dict, so there is no filesystem and no
I/O. Fixtures use the fictional vocabulary the provenance note requires --
tenants ``alpha``…``theta``, and ``jdoe`` for a person, who is a placeholder and
not anybody.

One accept and one reject per rule, and the rejects assert on the *message*: a
rule that fires without saying which key is wrong has not finished its job.

**What is deliberately not tested here** is the degradation itself -- that a
reset with no block configured warns and runs. That needs a run, so the verb's
tests hold it. This layer tests what it can see: an absent block produces
``None`` rather than an empty destination.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.reset_records import build_reset_records


def document(**block: Any) -> dict[str, Any]:
    return {"version": 1, "reset_records": block}


def built(**block: Any) -> Any:
    section = build_reset_records(document(**block))
    assert section is not None
    return section


# --------------------------------------------------------------- declaring ---


def test_a_section_that_is_absent_is_none_rather_than_an_empty_destination() -> None:
    """``None`` and "configured but empty" are different answers, and the warning
    site has to tell them apart: no block means keep no journal, warn and carry
    on, while a block naming nothing is a file to refuse."""
    assert build_reset_records({"version": 1}) is None


def test_the_block_is_a_store_and_a_prefix() -> None:
    section = built(vault="kv", prefix="sopuli/personal-resets")
    assert section.vault == "kv"
    assert section.prefix == "sopuli/personal-resets"


def test_a_prefix_is_normalised_the_way_a_lock_key_path_is() -> None:
    """Two spellings of one prefix have to become one, or two runs would write
    their records into places that never find each other -- which is two
    concurrent resets not colliding."""
    assert built(vault="kv", prefix="/sopuli//personal-resets/").prefix == (
        "sopuli/personal-resets"
    )


# --------------------------------------------------------------- refusing ---


def test_a_block_with_no_vault_is_refused_naming_the_key() -> None:
    with pytest.raises(ConfigError) as raised:
        build_reset_records(document(prefix="sopuli/personal-resets"))
    assert "reset_records.vault" in str(raised.value)


def test_a_block_with_no_prefix_is_refused_and_offers_one() -> None:
    """Required rather than defaulted: a default would put records somewhere the
    file does not say, in a store the file does name."""
    with pytest.raises(ConfigError) as raised:
        build_reset_records(document(vault="kv"))
    message = str(raised.value)
    assert "reset_records.prefix" in message
    assert "sopuli/personal-resets" in message


def test_a_prefix_that_normalises_to_nothing_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_reset_records(document(vault="kv", prefix="///"))
    assert "reset_records.prefix" in str(raised.value)


@pytest.mark.parametrize("prefix", ["sopuli/../secrets", "../secrets", "sopuli/./resets"])
def test_a_traversal_segment_is_refused_rather_than_normalised_away(prefix: str) -> None:
    """#344's rule applied to the one other place a file names a store path. A
    ``..`` under a prefix walks out of it, and what it walks into here is
    whatever else the estate keeps in that store -- so it is refused with a
    location rather than silently rewritten."""
    with pytest.raises(ConfigError) as raised:
        build_reset_records(document(vault="kv", prefix=prefix))
    message = str(raised.value)
    assert "reset_records.prefix" in message
    assert "path segment" in message


def test_an_unknown_key_is_refused() -> None:
    with pytest.raises(ConfigError) as raised:
        build_reset_records(document(vault="kv", prefix="sopuli/resets", ttl="7d"))
    assert "ttl" in str(raised.value)


def test_the_block_is_a_mapping_not_a_list() -> None:
    with pytest.raises(ConfigError) as raised:
        build_reset_records({"version": 1, "reset_records": [{"vault": "kv"}]})
    assert "reset_records" in str(raised.value)


# ------------------------------------------------------ the store it names ---


def estate(**block: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "vaults": {"kv": {"type": "hashicorp", "addr": "https://vault.example.com"}},
        "targets": [
            {
                "name": "appdb-dev-alpha",
                "type": "oracle",
                "dsn": "db-dev.example.com:1521/ALPHA.pdb.example.com",
            }
        ],
        "reset_records": block,
    }


def test_the_vault_it_names_is_resolved_with_every_other_store_reference() -> None:
    config = build_config(estate(vault="kv", prefix="sopuli/personal-resets"))
    assert config.reset_records is not None
    assert config.reset_records.vault == "kv"


def test_a_store_that_is_not_declared_is_refused_at_load() -> None:
    """Checked while the file is open rather than left to the verb that writes a
    record. The failure it would otherwise produce arrives *after* a password has
    already changed (UC-2 §3.4), which is the worst moment to learn that a store
    name is misspelled."""
    with pytest.raises(ConfigError) as raised:
        build_config(estate(vault="kv-typo", prefix="sopuli/personal-resets"))
    message = str(raised.value)
    assert "kv-typo" in message
    assert "reset_records.vault" in message
