"""`--target`, `--account`, `--group` and `--application`.

`01-configuration.md` §2 and §3 show these in their command examples. Two things
depend on them:

* an operator following the documentation must not get "no such option";
* `02-oracle-privileges.md` §4's guardrail rule has two halves, and the half that
  turns on the operator having **named** an account needs a flag that can express
  the condition.

This file covers the flags. `tests/config/test_selection.py` covers the filtering
underneath them, and `tests/test_cli_guardrails.py` the §4 rule they make
expressible.

The property worth stating: **names are refused when they name nothing, and
labels are not.** A `--select` that matches nothing is an empty run, because
labels describe an estate that changes. A `--target` that names nothing is a
typo — and the run that quietly did nothing and exited 0 is how a scheduled
rotation stops rotating without anybody noticing.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.cli import cli
from sopuli.config import ArgumentError
from sopuli.exit_codes import ExitCode

#: Two targets in two environments, two applications, one shared account name --
#: enough for every selector to narrow to a different subset.
CONFIG = """\
version: 1
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
groups:
  prod-pdbs:
    match: { env: prod }
  dev-pdbs:
    match: { env: dev }
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: alpha }
    vault: vault-prod
  - name: appdb-beta
    type: oracle
    dsn: db-dev.example.com:1521/beta.pdb.example.com
    environment: dev
    labels: { env: dev, tenant: beta }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/{target}#DB_CREDENTIALS/{account}"
  - name: reporting
    accounts: [report_reader]
    targets: [appdb-alpha]
    secret_template: "apps/rep/{target}#DB_CREDENTIALS/{account}"
  - name: dormant
    accounts: [dormant_user]
    targets: { match: { env: staging } }
    secret_template: "apps/dor/{target}#DB_CREDENTIALS/{account}"
"""


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def listed(runner: CliRunner, config: Path, *args: str) -> list[str]:
    """The target names `target list` printed, in order."""
    result = runner.invoke(cli, ["target", "list", "--config", str(config), *args])
    assert result.exit_code == ExitCode.SUCCESS, result.output
    return [line.split()[0] for line in result.output.splitlines() if line.startswith("appdb-")]


def document(runner: CliRunner, config: Path, *args: str) -> dict[str, Any]:
    result = runner.invoke(
        cli, ["target", "list", "--config", str(config), "--output", "json", *args]
    )
    return dict(json.loads(result.output))


def refused(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["target", "list", "--config", str(config), *args])


# ------------------------------------------------------------ what each one does ---


def test_no_selector_is_the_whole_estate(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    assert listed(runner, write_config(CONFIG)) == ["appdb-alpha", "appdb-beta"]


def test_target_names_one(runner: CliRunner, write_config: Callable[[str], Path]) -> None:
    assert listed(runner, write_config(CONFIG), "--target", "appdb-beta") == ["appdb-beta"]


def test_target_repeats_to_add_more(runner: CliRunner, write_config: Callable[[str], Path]) -> None:
    found = listed(
        runner, write_config(CONFIG), "--target", "appdb-beta", "--target", "appdb-alpha"
    )
    # Estate order, not the order they were typed: two runs selecting the same
    # targets different ways must produce the same list, which is what makes
    # plan output comparable between them.
    assert found == ["appdb-alpha", "appdb-beta"]


def test_group_resolves_to_its_labels(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """A group is a named match (§4), so selecting by group is selecting by its
    labels -- and `--group prod-pdbs` must agree with `--select env=prod`."""
    config = write_config(CONFIG)

    assert listed(runner, config, "--group", "prod-pdbs") == listed(
        runner, config, "--select", "env=prod"
    )


def test_an_application_narrows_to_the_targets_its_accounts_live_on(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """`reporting` declares only `appdb-alpha`, so selecting it drops the other.

    This is the decision worth asserting: an account-level selector narrows
    *targets* too, by dropping the ones left with no bindings. Otherwise the
    plan's blast radius would count twenty targets for a run reaching three, and
    `max_targets` and `confirm_environments` would answer about work the run is
    not going to do.
    """
    assert listed(runner, write_config(CONFIG), "--application", "reporting") == ["appdb-alpha"]


def test_app_is_an_accepted_alias(runner: CliRunner, write_config: Callable[[str], Path]) -> None:
    """§3 has documented `--app` as an alias since before either existed."""
    config = write_config(CONFIG)

    assert listed(runner, config, "--app", "reporting") == listed(
        runner, config, "--application", "reporting"
    )


def test_an_account_narrows_the_same_way(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    assert listed(runner, write_config(CONFIG), "--account", "report_reader") == ["appdb-alpha"]


def test_an_account_is_matched_case_folded(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The file writes `report_reader` where Oracle stores `REPORT_READER`, and
    an operator copying a name out of a database is doing the obvious thing."""
    assert listed(runner, write_config(CONFIG), "--account", "REPORT_READER") == ["appdb-alpha"]


# ------------------------------------------------------------------ combining ---


def test_selectors_combine_as_and(runner: CliRunner, write_config: Callable[[str], Path]) -> None:
    """`--application acme --select env=dev` is acme's accounts on dev targets,
    not their union. An *or* would need a language, and C2 records why this file
    does not have one."""
    found = listed(runner, write_config(CONFIG), "--application", "acme", "--select", "env=dev")

    assert found == ["appdb-beta"]


def test_a_combination_selecting_nothing_is_an_empty_run(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Both names exist; their intersection is empty. That is a real answer about
    the estate rather than a mistake in the command, so it is not refused."""
    assert (
        listed(runner, write_config(CONFIG), "--application", "reporting", "--target", "appdb-beta")
        == []
    )


def test_a_selector_cannot_resurrect_what_another_removed(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Invariant 5: every member narrows and none extends."""
    found = listed(
        runner, write_config(CONFIG), "--target", "appdb-beta", "--account", "report_reader"
    )

    assert found == []


# ------------------------------------- each flag unions, flags intersect ---


def test_two_groups_are_a_union(runner: CliRunner, write_config: Callable[[str], Path]) -> None:
    """Repeatable flags union within themselves.

    Merging both groups' labels into one match would make `env=prod` and
    `env=dev` a conjunction that matches nothing -- turning "either of these two
    populations" into "neither".
    """
    found = listed(runner, write_config(CONFIG), "--group", "prod-pdbs", "--group", "dev-pdbs")

    assert found == ["appdb-alpha", "appdb-beta"]


def test_a_group_does_not_overwrite_an_explicit_label(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """`--select env=dev --group prod-pdbs` asks for both and gets neither.

    The bug this guards is worse than an empty result: merging let the group's
    labels silently *replace* the ones the operator typed, so this would have
    listed the prod target -- a selector quietly answering a question nobody
    asked.
    """
    found = listed(runner, write_config(CONFIG), "--select", "env=dev", "--group", "prod-pdbs")

    assert found == []


# ------------------------------------------------- names refused, labels not ---


def test_an_unknown_target_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    result = refused(runner, write_config(CONFIG), "--target", "appdb-gamma")

    assert result.exit_code != ExitCode.SUCCESS
    assert "appdb-gamma" in str(result.exception)


def test_an_unknown_group_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    result = refused(runner, write_config(CONFIG), "--group", "nosuch")

    assert result.exit_code != ExitCode.SUCCESS


def test_an_unknown_application_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The failure this prevents: somebody renames the entry, the scheduled
    `--application acme` selects nothing, does nothing, exits 0, and goes on
    reporting success for a credential that has stopped being rotated."""
    result = refused(runner, write_config(CONFIG), "--application", "acme-web")

    assert result.exit_code != ExitCode.SUCCESS
    assert "acme-web" in str(result.exception)


def test_an_unknown_account_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    result = refused(runner, write_config(CONFIG), "--account", "acme_web_usr")

    assert result.exit_code != ExitCode.SUCCESS


def test_an_application_reaching_no_target_is_still_a_declared_name(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Declared names come from `applications:`, not from the bindings they
    produced.

    `dormant` selects on `env: staging`, which no target carries, so it yields no
    binding at all. Deriving the declared set from bindings would refuse its name
    as a typo the operator did not make -- while the thing they actually want to
    know, that the entry currently reaches nothing, is what the empty run says.
    """
    assert listed(runner, write_config(CONFIG), "--application", "dormant") == []


def test_an_account_of_a_dormant_application_is_declared_too(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The same argument one level down: an account is declared by the entry
    that lists it, whether or not that entry reaches a target today."""
    assert listed(runner, write_config(CONFIG), "--account", "dormant_user") == []


def test_the_refusal_names_what_is_declared(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """A typo is cleared by seeing the right spelling, so the hint carries it."""
    result = refused(runner, write_config(CONFIG), "--target", "appdb-gamma")

    assert isinstance(result.exception, ArgumentError)
    assert "appdb-alpha" in str(result.exception.hint)


def test_a_label_matching_nothing_is_not_refused(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """The asymmetry, stated as a test: labels describe an estate that changes
    underneath them, and a name is a claim that a particular thing exists."""
    assert listed(runner, write_config(CONFIG), "--select", "env=staging") == []


def test_an_unknown_name_is_refused_before_the_estate_is_narrowed(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """Checked against the unfiltered config, so a name that exists but was
    excluded by another selector is not reported as a misspelling -- those are
    different mistakes with different fixes."""
    result = refused(
        runner, write_config(CONFIG), "--target", "appdb-beta", "--account", "report_reader"
    )

    assert result.exit_code == ExitCode.SUCCESS


# --------------------------------------------------------- the run document ---


def test_the_document_reports_the_selectors_as_given(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """`invocation.selection` has a slot for each of these, and each is
    populated, not only `select`."""
    body = document(
        runner,
        write_config(CONFIG),
        "--application",
        "acme",
        "--select",
        "env=dev",
    )

    assert body["invocation"]["selection"] == {
        "select": {"env": "dev"},
        "applications": ["acme"],
    }


def test_unused_members_are_omitted_rather_than_empty(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """An empty array would claim the run considered a selector nobody gave it."""
    body = document(runner, write_config(CONFIG), "--target", "appdb-alpha")

    assert body["invocation"]["selection"] == {"targets": ["appdb-alpha"]}


def test_an_unnarrowed_run_omits_the_object(
    runner: CliRunner, write_config: Callable[[str], Path]
) -> None:
    """A consumer counting 3 targets cannot otherwise tell a small estate from a
    filtered one, so the presence of the object is itself information."""
    body = document(runner, write_config(CONFIG))

    assert "selection" not in body["invocation"]
