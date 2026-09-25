"""The committed schemas and samples, checked as artefacts in their own right.

Invariant 12: "Samples must validate against ``docs/schemas/*.schema.json`` --
this runs in CI." ``tests/test_run_document.py`` covers one half of that, the
document a command actually emits. This file covers the other half, which was
until now only asserted in prose in ``docs/README.md``:

* every committed schema is a valid Draft 2020-12 schema, including the
  superseded ``sopuli-event-1.*`` files that no build emits any more -- the
  current one is also validated line by line against what ``--output jsonl``
  writes, in ``tests/test_output_jsonl.py`` (#9)
* every committed sample validates against the schema it claims to describe

The schemas are found by glob rather than listed. A schema added later is then
covered by having been committed, which is the only way this stays true --
a hand-maintained list is a list someone forgets to extend.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sopuli.output.document import SCHEMA_VERSION

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "docs" / "schemas"

#: Sample file -> the schema it must validate against. Samples are documentation
#: that can rot; the ones in the repo are cited from the design documents, so
#: they have to stay true as the schemas evolve.
SAMPLES = {
    "example-creds-check-drift.json": f"sopuli-run-{SCHEMA_VERSION}.schema.json",
}


def _load(name: str) -> Any:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def _schema_files() -> list[str]:
    return sorted(path.name for path in SCHEMA_DIR.glob("*.schema.json"))


def test_there_are_schemas_to_check() -> None:
    """Guards the glob itself.

    A moved directory or a renamed suffix would otherwise turn every test below
    into a vacuous pass over an empty list -- green, and checking nothing.
    """
    assert _schema_files()


@pytest.mark.parametrize("name", _schema_files())
def test_schema_is_valid_draft_2020_12(name: str) -> None:
    """A schema with a typo in a keyword does not fail -- it silently allows.

    ``check_schema`` is what turns that into an error, so an unused schema like
    the event one cannot quietly stop meaning anything before the first consumer
    arrives.
    """
    Draft202012Validator.check_schema(_load(name))


@pytest.mark.parametrize(("sample", "schema"), SAMPLES.items())
def test_sample_validates_against_its_schema(sample: str, schema: str) -> None:
    validator = Draft202012Validator(_load(schema))
    errors = [
        f"{list(error.path)}: {error.message}" for error in validator.iter_errors(_load(sample))
    ]
    assert errors == [], f"{sample} does not validate against {schema}"


def test_every_committed_sample_is_covered() -> None:
    """The mapping above has to keep up with the directory.

    A sample committed and not listed would be documentation nobody checks,
    which is the exact failure mode invariant 12 exists to prevent.
    """
    samples = {
        path.name for path in SCHEMA_DIR.glob("*.json") if not path.name.endswith(".schema.json")
    }
    assert samples == set(SAMPLES), "add new samples to SAMPLES with the schema they describe"
