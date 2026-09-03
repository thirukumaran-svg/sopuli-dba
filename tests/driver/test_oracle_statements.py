"""The statement, and the shape it must never have.

``04-testing.md`` §5 asks for these by name, and says why they are tier 0 rather
than left to review: *a later refactor that introduces a wrapper -- batching
several rotations, say -- breaks it silently and no database test would notice,
because the DDL itself stays clean either way.*

So the assertions here are about **text**. What the statement is, what it is not
wrapped in, what it does not contain, and what the refusals say when there is no
statement to build.
"""

from __future__ import annotations

import inspect
import re

import pytest

from sopuli.driver.oracle.statements import (
    CONTAINER_ALL,
    ContainerScopeError,
    Identifier,
    IdentifierError,
    PasswordNotAdmissibleError,
    Statement,
    admissible,
    alter_user_password,
    alter_user_profile,
    container_clause,
    unlock_account,
)
from sopuli.driver.protocol import Scope
from sopuli.exit_codes import ExitCode
from sopuli.passwords import ByteLimit
from sopuli.secrets import REDACTED, Secret

UTF8 = ByteLimit(max_bytes=128, encoding="utf-8")
LEGACY = ByteLimit(max_bytes=30, encoding="utf-8")
WESTERN = ByteLimit(max_bytes=128, encoding="cp1252")

PDB = Scope(type="pdb", container="FREEPDB1")
ROOT = Scope(type="cdb_root", container="CDB$ROOT")

ACCOUNT = Identifier("ACME_WEB_USER")
COMMON = Identifier("C##ACME_MONITOR")

#: Distinctive enough that any fragment of it in a message is unmistakable, and
#: legal enough to build a statement with.
PASSWORD = Secret("Zx7-Quarry-Lantern-42")

#: Anything that would make a statement out of a block. Matched case-insensitively
#: and as whole words, so that an account legitimately called ``BEGINNER`` does
#: not read as a wrapper.
WRAPPERS = re.compile(r"\b(begin|declare|execute\s+immediate)\b", re.IGNORECASE)

#: A bind, in either of the forms Oracle takes.
BINDS = re.compile(r"(:\w+)|(\?)")

#: A double-quoted run. Matching one is trivial *here* and nowhere else, because
#: invariant 11 guarantees no quote can appear inside one: the password and the
#: identifier are both refused if they contain a ``"``, so there is no escaping
#: to reason about and no ambiguity about where a run ends.
QUOTED = re.compile(r'"[^"]*"')


def structure(sql: str) -> str:
    """``sql`` with its quoted literals removed.

    Invariants 13 and 14 are properties of the statement's **structure**, not of
    the text somebody's password happens to contain. ``printable_ascii`` allows
    both ``:`` and ``?``, so a perfectly good password can carry what looks like
    a bind marker, and ``BEGIN`` is a legal thing to call an account -- scanning
    the whole string would fail those and call it a leak.

    Stripping cannot hide a real violation, which is what makes it safe to do: a
    wrapper or a bind is by definition *outside* the quotes. That claim is not
    left as an argument -- :func:`test_the_detectors_catch_what_they_are_for`
    runs both patterns over the statements this module must never produce.
    """
    return QUOTED.sub('""', sql)


def build() -> Statement:
    return alter_user_password(ACCOUNT, PASSWORD, scope=PDB, limit=UTF8)


# ------------------------------------------------------------- the statement ---


def test_the_statement_is_the_ddl_and_nothing_else() -> None:
    assert build().reveal() == 'ALTER USER "ACME_WEB_USER" IDENTIFIED BY "Zx7-Quarry-Lantern-42"'


def test_the_statement_is_never_a_plsql_block() -> None:
    """Invariant 13, and the one that is easy to violate by accident.

    Wrapping looks like the more careful option and is the only thing that
    actually leaks: the DDL leaves no cursor on 26ai, while a block *containing*
    it is retained verbatim in ``V$SQL`` and ``V$DB_OBJECT_CACHE``.
    """
    sql = build().reveal()

    assert sql.startswith("ALTER USER ")
    assert not WRAPPERS.search(structure(sql))


def test_the_password_is_never_a_bind() -> None:
    """Invariant 14, asserted twice: in the text, and in the signature.

    The signature is the half that lasts. ``V$SQL_BIND_CAPTURE`` keeps bind
    values in clear, and the way a bind gets introduced is by someone adding a
    parameter for one -- so the assertion that there is nowhere to put it is
    worth more than the assertion that this call did not.
    """
    assert not BINDS.search(structure(build().reveal()))

    parameters = set(inspect.signature(alter_user_password).parameters)
    assert parameters == {"account", "secret", "scope", "limit"}


def test_the_detectors_catch_what_they_are_for() -> None:
    """Guards :func:`structure` and both patterns together.

    Stripping quoted literals is only safe if a real violation still shows, so
    the statements this module must never produce are run through the same
    pipeline the assertions use. Without this, a stripper that removed too much
    would leave every test above passing over an empty string.
    """
    wrapped = 'BEGIN EXECUTE IMMEDIATE \'ALTER USER "ACME_WEB_USER" IDENTIFIED BY "hunter2"\'; END;'
    bound = 'ALTER USER "ACME_WEB_USER" IDENTIFIED BY :password'

    assert WRAPPERS.search(structure(wrapped))
    assert BINDS.search(structure(bound))


def test_a_password_that_looks_like_a_bind_is_still_a_password() -> None:
    """``printable_ascii`` allows ``:`` and ``?``, so this is a password a
    policy can really produce -- and the statement carrying it is not thereby
    bound to anything."""
    statement = alter_user_password(ACCOUNT, Secret(":password?"), scope=PDB, limit=UTF8)

    assert statement.reveal().endswith('IDENTIFIED BY ":password?"')
    assert not BINDS.search(structure(statement.reveal()))


def test_the_statement_redacts_itself_everywhere_but_reveal() -> None:
    """The text carries a password, so it is as sensitive as one.

    A bare ``str`` return would put plaintext somewhere a log line could reach.
    ``reveal()`` is named for :meth:`Secret.reveal` so that grepping one method
    name still finds every place plaintext is reachable.
    """
    statement = build()
    secret = PASSWORD.reveal()

    assert secret in statement.reveal()
    assert secret not in str(statement)
    assert secret not in repr(statement)
    assert secret not in f"{statement}"
    assert str(statement) == f'ALTER USER "ACME_WEB_USER" IDENTIFIED BY {REDACTED}'


def test_the_redacted_form_is_what_a_plan_can_print() -> None:
    """`--dry-run` prints the plan (invariant 8), and a plan nobody can paste
    into a ticket is not much of one."""
    assert build().redacted == str(build())


# --------------------------------------------------------- container clauses ---


def test_a_common_user_in_the_root_gets_container_all() -> None:
    statement = alter_user_password(COMMON, PASSWORD, scope=ROOT, limit=UTF8)

    assert statement.reveal().endswith(CONTAINER_ALL)
    assert statement.redacted.endswith(CONTAINER_ALL)


def test_an_ordinary_account_gets_no_clause() -> None:
    assert container_clause(ACCOUNT, PDB) == ""
    assert container_clause(ACCOUNT, ROOT) == ""


def test_a_common_user_outside_the_root_is_refused() -> None:
    """§6.2: refuse to treat ``C##``-prefixed names as local users.

    One account with one password across the CDB, altered from a PDB, is either
    an error or a different account than the estate meant -- and ``ORA-65040``
    halfway through a rotation is a worse way to find out.
    """
    with pytest.raises(ContainerScopeError) as refused:
        container_clause(COMMON, PDB)

    assert "C##ACME_MONITOR" in str(refused.value)
    assert "pdb" in str(refused.value)
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
    assert refused.value.category == "config"


def test_an_application_root_is_refused_whatever_the_account_looks_like() -> None:
    """#204, measured: there is no safe branch to take in an application root.

    Every account there is application-common -- a local one is ``ORA-65049`` --
    and a statement with no container clause is already container-wide, confirmed
    by login across an already-synced application PDB. So the ``""`` that reads as
    the conservative branch is the dangerous one, and no property of the *name*
    distinguishes the case: ``C##`` is forbidden in an application container
    (``ORA-60534``), so the marker the CDB root relies on cannot appear.
    """
    scope = Scope(type="app_root")

    for account in (ACCOUNT, COMMON):
        with pytest.raises(ContainerScopeError) as refused:
            container_clause(account, scope)
        assert "application root" in str(refused.value)
        assert refused.value.exit_code == ExitCode.CONFIG_INVALID


def test_an_application_pdb_takes_the_ordinary_path() -> None:
    """The half of #204's refusal that the measurement removed.

    A local account in an application PDB is entirely ordinary -- ``common=NO``,
    a plain ``ALTER USER`` accepted. Refusing the scope would have blocked a
    working case to prevent one Oracle already prevents (``ORA-65066``), which is
    a guardrail costing more than it guards.
    """
    assert container_clause(ACCOUNT, Scope(type="app_pdb")) == ""


def test_a_common_name_in_an_application_pdb_is_still_refused() -> None:
    """Right answer, and now for two reasons.

    The common-user branch refuses it because ``CONTAINER=ALL`` is a claim to be
    in the root. #204 added the second: such an account cannot exist in an
    application container at all, so a config declaring one is wrong about the
    estate rather than about the scope.
    """
    with pytest.raises(ContainerScopeError) as refused:
        container_clause(COMMON, Scope(type="app_pdb"))

    assert "app_pdb" in str(refused.value)


def test_an_unresolved_scope_gets_the_conservative_reading_of_each_half() -> None:
    """No clause is the conservative clause for an ordinary account.

    For a common one it is a refusal, and the asymmetry is the point:
    ``CONTAINER=ALL`` is a claim to be in the root, and an unresolved scope is
    exactly not knowing that. Whether such a scope may be acted on at all is the
    connection's question (#177), one layer earlier than this.
    """
    assert container_clause(ACCOUNT, Scope()) == ""

    with pytest.raises(ContainerScopeError):
        container_clause(COMMON, Scope())


# ---------------------------------------------------------------- refusals ---


def test_a_password_containing_a_quote_is_refused_not_escaped() -> None:
    """Invariant 11. There is no correct escaping, so there is no escaping."""
    with pytest.raises(PasswordNotAdmissibleError) as refused:
        alter_user_password(ACCOUNT, Secret('has a " in it'), scope=PDB, limit=UTF8)

    assert refused.value.category == "policy"
    assert "escape" in str(refused.value)


def test_control_characters_are_refused() -> None:
    with pytest.raises(PasswordNotAdmissibleError, match="control characters"):
        admissible(Secret("fine\x00mostly"), UTF8)


def test_an_empty_password_is_refused() -> None:
    with pytest.raises(PasswordNotAdmissibleError, match="empty"):
        admissible(Secret(""), UTF8)


def test_the_byte_limit_is_the_targets_and_is_measured_in_its_character_set() -> None:
    """30 bytes below 12.2, 128 from 12.2, counted in the database character set.

    The same password is admissible against one target and not another, which is
    the whole reason the limit is an argument rather than a constant -- and why
    it is a *required* one: a statement cannot be built by somebody who never
    asked the database (invariant 3).
    """
    password = Secret("x" * 40)

    admissible(password, UTF8)
    with pytest.raises(PasswordNotAdmissibleError) as refused:
        admissible(password, LEGACY)

    assert "40 bytes" in str(refused.value)
    assert "30" in str(refused.value)


def test_a_password_the_database_character_set_cannot_hold_is_refused() -> None:
    """Distinct from being too long, and reported as such: a character that
    cannot be encoded at all has no byte count to compare."""
    with pytest.raises(PasswordNotAdmissibleError, match="cp1252"):
        admissible(Secret("Zx7-安全-42"), WESTERN)


def test_the_limit_cannot_be_defaulted_away() -> None:
    """It is required in the signature, which is what makes "never assumed"
    structural rather than a comment."""
    assert inspect.signature(admissible).parameters["limit"].default is inspect.Parameter.empty


def test_no_refusal_repeats_the_password_it_rejected() -> None:
    """The same rule ``test_no_violation_repeats_the_password_it_rejected``
    holds :mod:`sopuli.passwords` to, at the layer below it.

    A refusal may be logged or put in an audit event. Naming the *class* of
    problem is what makes it actionable; naming a character of the credential is
    what invariant 2 exists to prevent -- so ``"`` appears in a message as the
    rule that was broken, and never as a quotation of what was supplied.
    """
    supplied = 'Sup3rSecret!"tail'

    with pytest.raises(PasswordNotAdmissibleError) as refused:
        admissible(Secret(supplied), UTF8)

    rendered = str(refused.value)
    assert supplied not in rendered
    for fragment in ("Sup3r", "Secret", "ecre", "tail"):
        assert fragment not in rendered


# -------------------------------------------------------------- identifiers ---


def test_only_a_spelling_the_database_gave_back_reaches_a_statement() -> None:
    """``02-oracle-privileges.md`` §4, as a type rather than as a sentence.

    A plan may still name accounts as plain strings -- it is printed before
    anything connects, so what it names is what the config declared. This is the
    seam: config names accounts, the database spells them, and only the spelling
    reaches SQL.
    """
    annotations = inspect.signature(alter_user_password).parameters

    assert annotations["account"].annotation == "Identifier"
    assert annotations["secret"].annotation == "Secret"


@pytest.mark.parametrize("name", ['AC"ME', "ACME\x00", "ACME\nDROP", "", "A" * 129])
def test_an_identifier_cannot_hold_what_a_quoted_identifier_cannot(name: str) -> None:
    """A newline is in the list on purpose: it is a control character, so the
    same rule that rejects ``CHR(0)`` is what stops a name from carrying a
    second statement into the text."""
    with pytest.raises(IdentifierError):
        Identifier(name)


def test_a_malformed_name_is_not_reported_as_a_container_problem() -> None:
    """Two failures, two classes. Reusing one would have been convenient and
    would have sent an operator to look at the wrong thing -- the estate's
    container layout, for a name holding a quote."""
    assert not issubclass(IdentifierError, ContainerScopeError)
    assert not issubclass(ContainerScopeError, IdentifierError)


def test_common_users_are_recognised_in_either_case() -> None:
    """``c##app`` and ``C##APP`` are one account, and a rule that saw only one
    spelling would append ``CONTAINER=ALL`` to some of them."""
    assert Identifier("C##ACME").is_common
    assert Identifier("c##acme").is_common
    assert not Identifier("ACME_WEB_USER").is_common


def test_an_identifier_is_quoted_and_printable() -> None:
    """The name is not a secret: it appears in plans, errors and audit records,
    which is exactly why it must be safe to put in quotes."""
    assert ACCOUNT.quoted() == '"ACME_WEB_USER"'
    assert str(ACCOUNT) == "ACME_WEB_USER"


# ----------------------------------------------------------------- unlocking ---


def test_the_unlock_is_the_ddl_and_nothing_else() -> None:
    """UC-1 §5's first attribute (#300). One statement, both kinds of lock."""
    assert (
        unlock_account(ACCOUNT, scope=PDB).reveal() == 'ALTER USER "ACME_WEB_USER" ACCOUNT UNLOCK'
    )


def test_the_unlock_is_never_a_plsql_block() -> None:
    """Invariant 13 applies to a statement with nothing to hide, and that is the
    point of asserting it: the habit is what keeps the next one safe, and the
    next one carries a password."""
    sql = unlock_account(ACCOUNT, scope=PDB).reveal()

    assert sql.startswith("ALTER USER ")
    assert not WRAPPERS.search(structure(sql))
    assert not BINDS.search(structure(sql))


def test_the_unlock_has_nothing_to_redact() -> None:
    """Every other statement in this module hides something; this one does not,
    and says so by being its own redacted form rather than by omission."""
    statement = unlock_account(ACCOUNT, scope=PDB)

    assert statement.redacted == statement.reveal()
    assert REDACTED not in str(statement)


def test_the_unlock_takes_the_same_container_clause_as_the_password() -> None:
    """A common user is one account across the CDB. Unlocking it from the root
    without the clause -- or from a PDB at all -- would be unlocking something
    other than what the estate meant."""
    assert unlock_account(COMMON, scope=ROOT).reveal().endswith(CONTAINER_ALL)

    with pytest.raises(ContainerScopeError):
        unlock_account(COMMON, scope=PDB)


# --------------------------------------------------------------- the profile ---

PROFILE = Identifier("ACME_APP_PROF")


def test_the_profile_assignment_is_the_ddl_and_nothing_else() -> None:
    """UC-1 §5's second attribute (#301)."""
    statement = alter_user_profile(ACCOUNT, PROFILE, scope=PDB)

    assert statement.reveal() == 'ALTER USER "ACME_WEB_USER" PROFILE "ACME_APP_PROF"'


def test_the_profile_assignment_is_never_a_plsql_block() -> None:
    sql = alter_user_profile(ACCOUNT, PROFILE, scope=PDB).reveal()

    assert sql.startswith("ALTER USER ")
    assert not WRAPPERS.search(structure(sql))
    assert not BINDS.search(structure(sql))


def test_the_profile_name_goes_through_the_identifier_rules() -> None:
    """The same type as the account name, because the rule is the same one: a
    quoted identifier is case-sensitive and has no escape for a `"`."""
    with pytest.raises(IdentifierError):
        alter_user_profile(ACCOUNT, Identifier('we"ird'), scope=PDB)


def test_the_profile_assignment_takes_the_container_clause() -> None:
    assert alter_user_profile(COMMON, PROFILE, scope=ROOT).reveal().endswith(CONTAINER_ALL)

    with pytest.raises(ContainerScopeError):
        alter_user_profile(COMMON, PROFILE, scope=PDB)


def test_the_assignment_alters_the_user_and_never_the_profile() -> None:
    """Q4 (#88) in the one line that can be asserted: the statement's object is
    the account, not the shared profile. `ALTER PROFILE` would reach accounts
    nobody selected, and there is no function in this module that builds one."""
    sql = alter_user_profile(ACCOUNT, PROFILE, scope=PDB).reveal()

    assert sql.startswith('ALTER USER "ACME_WEB_USER" ')
    assert "ALTER PROFILE" not in sql
