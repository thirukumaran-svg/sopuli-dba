"""Resolving the admin credential. Tier 0, and no ambient environment.

Every test passes its own mapping and its own suppliers, the arrangement
`test_material.py` already uses: nothing here reads `os.environ`, opens a store,
or touches a terminal, so these run beside each other and beside everything
else.

What is being protected is not the four-way branch -- that is a match statement
and it is hard to get wrong. It is the three decisions around it, each of which
is silent when wrong:

* a prompt that falls back to stdin takes the password meant for the *account*
  and sends it to the database as the DBA's (P5, "one stream, one reader");
* a prompt cache keyed on the username sends one PDB's password to another PDB
  that happens to hold a same-named local account;
* a missing `admin.auth` that quietly picks up whatever
  `SOPULI_DB_ADMIN_PASSWORD` was left in the environment authenticates as
  something nobody chose (P2).
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from sopuli.admin import (
    ADMIN_USER_ENV,
    AdminCredentialError,
    NobodyToAskError,
    PasswordPrompt,
    Resolved,
    needs_prompt,
    prompt_key,
    resolve,
)
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.config.targets import ADMIN_METHODS, ADMIN_PASSWORD_ENV, EXTERNAL
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

REF = "ops/sopuli/qa/admin#password"


def target(
    *,
    name: str = "cdb-root-qa",
    admin: AdminCredential | None = None,
    dsn: str = "db-test.example.com:1521/CDBQA.pdb.example.com",
    index: int | None = 0,
    target_set: str | None = None,
) -> ExpandedTarget:
    """One expanded target, explicit unless a set is named."""
    return ExpandedTarget(
        target=Target(name=name, type="oracle", dsn=dsn, admin=admin),
        index=None if target_set else index,
        target_set=target_set,
    )


def admin(method: str, **keys: object) -> AdminCredential:
    username = keys.pop("username", "C##SOPULI_SVC")
    assert isinstance(username, str) or username is None
    return AdminCredential(username=username, auth=AdminAuth(method=method, **keys))  # type: ignore[arg-type]


def refuse_ref(ref: object) -> Secret:
    """A reader that must not be called. Passed where the method is not `vault`,
    so that "the wallet branch never builds a store" is asserted rather than
    described."""
    raise AssertionError(f"the store was consulted for {ref!r}")


def refuse_prompt(_: ExpandedTarget, __: str | None) -> Secret:
    raise AssertionError("the operator was asked and should not have been")


def answer(_: ExpandedTarget, __: str | None) -> Secret:
    """A prompter that types the same thing every time."""
    return Secret("typed")


def env(**values: str) -> Mapping[str, str]:
    return values


class Recorder:
    """An :data:`~sopuli.admin.Asker` that answers everything and remembers what
    it was asked, so "asked once" and "asked twice" are countable.

    Returns a bare ``str``, which is the contract and not a shortcut: every real
    terminal read does, `getpass.getpass` included.
    """

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> str:
        self.lines.append(line)
        return "typed"


# ------------------------------------------------------------------ external ---


def test_external_resolves_to_neither_a_username_nor_a_secret() -> None:
    """P2's first source: a wallet supplies both halves, so there is no material
    to resolve and `Credential.external` is the whole answer."""
    resolved = resolve(
        target(admin=AdminCredential(auth=AdminAuth(method=EXTERNAL))),
        env=env(),
        read_ref=refuse_ref,
        prompt=refuse_prompt,
    )

    assert resolved.credential.external
    assert resolved.credential.username is None
    assert resolved.credential.secret is None
    assert not resolved.low_assurance


def test_external_ignores_the_username_variable() -> None:
    """§3a refuses a `username:` written beside a wallet. The variable is the
    same claim from somewhere ambient, so it is ignored rather than refused --
    otherwise one wallet target in an estate breaks the variable for the rest."""
    resolved = resolve(
        target(admin=AdminCredential(auth=AdminAuth(method=EXTERNAL))),
        env=env(**{ADMIN_USER_ENV: "SOMEBODY_ELSE"}),
    )

    assert resolved.credential.username is None


# ----------------------------------------------------------------------- env ---


def test_env_reads_the_named_variable_and_is_flagged_low_assurance() -> None:
    """P2 supports this source and requires it be flagged wherever reported."""
    resolved = resolve(
        target(admin=admin("env", password_env="ACME_QA_ADMIN_PW")),
        env=env(ACME_QA_ADMIN_PW="hunter2"),
        read_ref=refuse_ref,
        prompt=refuse_prompt,
    )

    assert resolved.credential.secret == Secret("hunter2")
    assert resolved.low_assurance
    assert "ACME_QA_ADMIN_PW" in resolved.source


def test_env_without_password_env_falls_back_to_the_documented_pair() -> None:
    """§6's `SOPULI_DB_ADMIN_PASSWORD`, which is a default for a *declared*
    method -- see the no-source test below for why that distinction matters."""
    resolved = resolve(
        target(admin=admin("env")),
        env=env(**{ADMIN_PASSWORD_ENV: "hunter2"}),
    )

    assert resolved.credential.secret == Secret("hunter2")
    assert ADMIN_PASSWORD_ENV in resolved.source


def test_an_unset_variable_names_itself_and_exits_nine() -> None:
    with pytest.raises(AdminCredentialError) as refused:
        resolve(target(admin=admin("env")), env=env())

    assert ADMIN_PASSWORD_ENV in str(refused.value)
    assert "cdb-root-qa" in str(refused.value)
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID


def test_set_but_empty_counts_as_unset() -> None:
    """§6's rule for the whole variable table, inherited from `material.resolve`
    rather than re-decided here: clearing an inherited variable in a CI job is
    the same situation as never setting it, and gets the same message."""
    with pytest.raises(AdminCredentialError):
        resolve(target(admin=admin("env")), env=env(**{ADMIN_PASSWORD_ENV: ""}))


# --------------------------------------------------------------------- vault ---


def test_vault_resolves_its_ref_through_the_supplied_reader() -> None:
    asked: list[str] = []

    def read(ref: object) -> Secret:
        asked.append(str(ref))
        return Secret("from-the-vault")

    resolved = resolve(
        target(admin=admin("vault", secret=parse_secret_ref(REF))),
        env=env(),
        read_ref=read,
        prompt=refuse_prompt,
    )

    assert asked == [REF]
    assert resolved.credential.secret == Secret("from-the-vault")
    assert not resolved.low_assurance
    assert REF in resolved.source


def test_the_ref_is_named_when_no_reader_was_supplied() -> None:
    """A caller's omission rather than an operator's, and the message says so:
    somebody reading this in a bug report should not go and edit the file."""
    with pytest.raises(AdminCredentialError) as refused:
        resolve(target(admin=admin("vault", secret=parse_secret_ref(REF))), env=env())

    assert REF in str(refused.value)
    assert "the file is fine" in str(refused.value)


# -------------------------------------------------------------------- prompt ---


def test_prompt_asks_and_returns_what_it_was_told() -> None:
    resolved = resolve(
        target(admin=admin("prompt")),
        env=env(),
        read_ref=refuse_ref,
        prompt=answer,
    )

    assert resolved.credential.secret == Secret("typed")
    assert resolved.credential.username == "C##SOPULI_SVC"
    assert resolved.source == "an interactive prompt"


def test_no_prompter_refuses_rather_than_reading_the_pipe() -> None:
    """P5's "one stream, one reader", made structural.

    `--from-stdin` claims the pipe for the *account's* new password, so a prompt
    that fell back to stdin would read that and send it to the database as the
    DBA's. The prompter is supplied only when stdin is a terminal, and a
    terminal carries no piped password -- so the two are mutually exclusive by
    construction and there is no ordering to define.
    """
    with pytest.raises(NobodyToAskError) as refused:
        resolve(target(admin=admin("prompt")), env=env())

    assert "nobody here to ask" in str(refused.value)
    assert "cdb-root-qa" in str(refused.value)


def test_nobody_to_ask_exits_aborted_rather_than_config_invalid() -> None:
    """The file is right and the invocation is right; the run needed a human.
    Exit 9 would send a scheduler's owner to a config file with nothing wrong
    with it -- the same distinction `lock break` already draws."""
    with pytest.raises(NobodyToAskError) as refused:
        resolve(target(admin=admin("prompt")), env=env())

    assert refused.value.exit_code == ExitCode.ABORTED
    assert refused.value.category == "policy"


def test_the_refusal_names_every_source_that_needs_nobody() -> None:
    """An operator who hits this in CI has three ways out and the message has to
    carry all of them: a hint naming only one reads like the only one."""
    with pytest.raises(NobodyToAskError) as refused:
        resolve(target(admin=admin("prompt")), env=env())

    hint = refused.value.hint or ""
    assert "vault" in hint
    assert ADMIN_PASSWORD_ENV in hint
    assert "external" in hint


def test_needs_prompt_answers_the_same_question_before_anything_is_touched() -> None:
    """Invariant 4's shape: a run that cannot succeed says so at plan time.
    Resolution belongs at connect time, so the check and the read are two calls
    -- and both must agree, which is what this asserts."""
    asks = target(admin=admin("prompt"))
    does_not = target(admin=admin("env"))

    assert needs_prompt(asks)
    assert not needs_prompt(does_not)
    assert not needs_prompt(target(admin=None))


# ------------------------------------------------------------- the prompt cache ---


def test_one_target_set_is_asked_once() -> None:
    """Thirty-four generated targets are one operator writing one credential
    down once. Asking thirty-four times is what makes a tool unusable on an
    estate."""
    ask = Recorder()
    prompt = PasswordPrompt(ask=ask)

    for tenant in ("alpha", "beta", "gamma"):
        prompt(
            target(name=f"appdb-qa-{tenant}", admin=admin("prompt"), target_set="appdb"),
            "C##SOPULI_SVC",
        )

    assert len(ask.lines) == 1


def test_an_empty_answer_is_refused_before_anything_is_sent() -> None:
    """Oracle has no empty password, so one can never authenticate. Sent, it
    would come back as `DPY-4001` under `connectivity` -- the wrong place to
    look for one keystroke at the operator's own terminal. The prompt refuses it
    instead, the same way an empty `method: env` variable is refused: `config`,
    exit 9, naming the target."""
    prompt = PasswordPrompt(ask=lambda _: "")

    with pytest.raises(AdminCredentialError) as caught:
        prompt(target(name="adb-acme", admin=admin("prompt")), "ADMIN")

    assert not isinstance(caught.value, NobodyToAskError)
    assert "'adb-acme'" in str(caught.value)
    assert "answer was empty" in str(caught.value)
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert caught.value.category == "config"
    assert "nothing was sent" in (caught.value.hint or "")
    assert "type the password" in (caught.value.hint or "")
    assert "paste" in (caught.value.hint or "")


def test_an_empty_answer_is_not_cached() -> None:
    """A later target sharing the credential asks again rather than inheriting
    the empty answer -- the second attempt is the operator's chance to type it."""
    answers = iter(["", "typed"])
    lines: list[str] = []

    def ask(line: str) -> str:
        lines.append(line)
        return next(answers)

    prompt = PasswordPrompt(ask=ask)
    first = target(name="appdb-qa-alpha", admin=admin("prompt"), target_set="appdb")
    second = target(name="appdb-qa-beta", admin=admin("prompt"), target_set="appdb")

    with pytest.raises(AdminCredentialError):
        prompt(first, "C##SOPULI_SVC")
    answer = prompt(second, "C##SOPULI_SVC")

    assert answer.reveal() == "typed"
    assert len(lines) == 2


def test_whitespace_is_an_answer() -> None:
    """Oracle can hold a quoted password of spaces, so only the empty string is
    refused -- anything else is the database's to judge."""
    prompt = PasswordPrompt(ask=lambda _: "   ")

    assert prompt(target(admin=admin("prompt")), "SYSTEM").reveal() == "   "


def test_two_explicit_targets_are_asked_twice_even_when_identical() -> None:
    """Two acts of writing it down, so two credentials as far as the file says.
    The conservative side: an extra prompt is an annoyance, a shared prompt
    across credentials that are not the same one is an authentication failure
    nobody can explain."""
    ask = Recorder()
    prompt = PasswordPrompt(ask=ask)

    prompt(target(name="cdb-root-dev", admin=admin("prompt"), index=0), "C##SOPULI_SVC")
    prompt(target(name="cdb-root-qa", admin=admin("prompt"), index=1), "C##SOPULI_SVC")

    assert len(ask.lines) == 2


def test_a_templated_username_is_a_credential_per_target() -> None:
    """`username: sopuli_{tenant}` renders differently per target, so the set
    declared thirty-four credentials rather than one -- and the rendered name is
    in the key precisely so that this case separates."""
    alpha = target(
        name="appdb-alpha", admin=admin("prompt", username="sopuli_alpha"), target_set="appdb"
    )
    beta = target(
        name="appdb-beta", admin=admin("prompt", username="sopuli_beta"), target_set="appdb"
    )

    assert prompt_key(alpha, "sopuli_alpha") != prompt_key(beta, "sopuli_beta")


def test_the_key_is_not_the_username_alone() -> None:
    """The tempting key, and the unsafe one: two PDBs can hold same-named local
    accounts with different passwords. Keyed on the name, the first PDB's
    password goes to the second and the ORA-01017 reads as a rotation problem.
    """
    one = target(name="pdb-orders", admin=admin("prompt", username="sopuli_svc"), index=0)
    other = target(name="pdb-billing", admin=admin("prompt", username="sopuli_svc"), index=1)

    assert prompt_key(one, "sopuli_svc") != prompt_key(other, "sopuli_svc")


def test_the_dsn_is_not_in_the_key() -> None:
    """Targets generated from one entry point at different databases by design;
    including the DSN would defeat the cache entirely."""
    one = target(
        name="appdb-alpha", admin=admin("prompt"), dsn="a.example.com:1521/A", target_set="s"
    )
    other = target(
        name="appdb-beta", admin=admin("prompt"), dsn="b.example.com:1521/B", target_set="s"
    )

    assert prompt_key(one, "C##SOPULI_SVC") == prompt_key(other, "C##SOPULI_SVC")


def test_the_prompt_asks_about_the_account_the_connection_will_use() -> None:
    """§6's variable overrides `username:`, so a prompt built from the file
    alone would ask for one account's password and then connect as another --
    a question whose answer is wrong through no fault of the person answering
    it, and one that surfaces as ORA-01017 much later."""
    ask = Recorder()
    resolved = resolve(
        target(admin=admin("prompt", username="C##SOPULI_SVC")),
        env=env(**{ADMIN_USER_ENV: "C##OTHER_SVC"}),
        prompt=PasswordPrompt(ask=ask),
    )

    assert resolved.credential.username == "C##OTHER_SVC"
    assert "C##OTHER_SVC" in ask.lines[0]
    assert "C##SOPULI_SVC" not in ask.lines[0]


def test_the_username_variable_makes_one_credential_of_a_templated_set() -> None:
    """The other half of taking the *effective* username: the variable can make
    targets identical that the file wrote apart, and a key built from the file
    would ask thirty-four times about one account."""
    ask = Recorder()
    prompt = PasswordPrompt(ask=ask)
    override = "C##OVERRIDE"

    for tenant in ("alpha", "beta", "gamma"):
        prompt(
            target(
                name=f"appdb-{tenant}",
                admin=admin("prompt", username=f"sopuli_{tenant}"),
                target_set="appdb",
            ),
            override,
        )

    assert len(ask.lines) == 1


def test_a_typed_password_is_wrapped_where_it_is_read() -> None:
    """An asker returns a `str`, because every terminal read does -- `getpass`
    included. Wrapping it here rather than in each supplier is invariant 2's own
    argument: a supplier that forgot would put a bare `str` into `credential`,
    where `repr` prints the password in full.
    """
    resolved = resolve(
        target(admin=admin("prompt")),
        env=env(),
        prompt=PasswordPrompt(ask=lambda _: "hunter2"),
    )

    assert isinstance(resolved.credential.secret, Secret)
    assert resolved.credential.secret == Secret("hunter2")
    assert "hunter2" not in repr(resolved)


def test_the_prompt_line_names_the_account_and_the_target() -> None:
    """An estate prompts for several. "Password:" on its own is a question
    nobody can answer correctly twice."""
    line = PasswordPrompt.line(target(admin=admin("prompt")), "C##SOPULI_SVC")

    assert "C##SOPULI_SVC" in line
    assert "cdb-root-qa" in line


def test_the_prompt_line_survives_a_target_with_no_username() -> None:
    """§6 lets `SOPULI_DB_ADMIN_USER` supply it, so the file need not."""
    line = PasswordPrompt.line(target(admin=admin("prompt", username=None)), None)

    assert "cdb-root-qa" in line


# ------------------------------------------------------------------ username ---


def test_the_username_variable_outranks_the_file() -> None:
    """P3's layering on one field: the environment is layer 3, the file is 4."""
    resolved = resolve(
        target(admin=admin("env", username="C##SOPULI_SVC")),
        env=env(**{ADMIN_USER_ENV: "C##OTHER_SVC", ADMIN_PASSWORD_ENV: "hunter2"}),
    )

    assert resolved.credential.username == "C##OTHER_SVC"


def test_a_target_may_name_no_username_at_all() -> None:
    resolved = resolve(
        target(admin=AdminCredential(auth=AdminAuth(method="env"))),
        env=env(**{ADMIN_PASSWORD_ENV: "hunter2"}),
    )

    assert resolved.credential.username is None


# ------------------------------------------------------------------ no source ---


def test_a_target_naming_no_source_is_refused_rather_than_guessed_at() -> None:
    """The whole point of P2's bootstrap section. §6 calls the pair *the default
    for* `method: env` -- a statement about a declared method, not about an
    absent one -- so picking it up because it happened to be set would
    authenticate as something nobody chose."""
    with pytest.raises(AdminCredentialError) as refused:
        resolve(target(admin=None), env=env(**{ADMIN_PASSWORD_ENV: "hunter2"}))

    assert "no admin credential" in str(refused.value)


def test_the_refusal_holds_when_only_the_auth_block_is_missing() -> None:
    """`admin: { username: … }` with no `auth:` is legal config and names no
    source, which is the same situation written differently."""
    with pytest.raises(AdminCredentialError):
        resolve(
            target(admin=AdminCredential(username="C##SOPULI_SVC")),
            env=env(**{ADMIN_PASSWORD_ENV: "hunter2"}),
        )


def test_the_refusal_lists_the_methods_that_exist() -> None:
    """Read off `ADMIN_METHODS` rather than written out, so a fifth source can
    never be added without the message learning about it."""
    with pytest.raises(AdminCredentialError) as refused:
        resolve(target(admin=None), env=env())

    hint = refused.value.hint or ""
    assert all(method in hint for method in ADMIN_METHODS)


# ------------------------------------------------------------------ provenance ---


def test_the_source_never_carries_the_value() -> None:
    """Invariant 2 applies to the provenance string as much as to the secret:
    `source` is rendered into the plan and the run document."""
    resolved = resolve(
        target(admin=admin("env")),
        env=env(**{ADMIN_PASSWORD_ENV: "hunter2"}),
    )

    assert "hunter2" not in resolved.source
    assert "hunter2" not in repr(resolved)
    assert "hunter2" not in str(resolved.credential.secret)


@pytest.mark.parametrize("method", sorted(ADMIN_METHODS))
def test_every_declared_method_resolves_to_something(method: str) -> None:
    """The list in `ADMIN_METHODS` and the branch here are one list. A method
    added to the config vocabulary and not here would parse, validate, and then
    fail at the first connection -- which is exactly the failure invariant 4
    exists to move earlier."""
    keys: dict[str, object] = {}
    if method == "vault":
        keys["secret"] = parse_secret_ref(REF)
    if method == EXTERNAL:
        credential = AdminCredential(auth=AdminAuth(method=method))
    else:
        credential = admin(method, **keys)

    resolved = resolve(
        target(admin=credential),
        env=env(**{ADMIN_PASSWORD_ENV: "hunter2"}),
        read_ref=lambda _: Secret("from-the-vault"),
        prompt=answer,
    )

    assert isinstance(resolved, Resolved)
    assert resolved.method == method
    assert resolved.source
