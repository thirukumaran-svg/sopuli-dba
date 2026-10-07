"""Building `ALTER USER`, and refusing to build it (invariants 11, 13 and 14).

Every statement this tool sends to Oracle is built here, and the reason that is
worth a module of its own is that the safe construction is the counter-intuitive
one.

**Never wrap the DDL in a PL/SQL block** (invariant 13). Measured on 26ai
23.26.2.0.0: Oracle retains *no cursor at all* for `CREATE`/`ALTER USER`, so
there is nothing in `V$SQL` to mask -- but a block that merely *contains* one is
an ordinary anonymous block, and its own text is kept verbatim in `V$SQL`,
`V$SQLAREA`, `V$SQLSTATS`, `GV$SQL` and `V$DB_OBJECT_CACHE`. Wrapping does not
hide the literal. It is the only thing that exposes it. That is why the rule is
enforced by a test against the text this module produces rather than left to
review: a later refactor that batches two rotations into one block would look
tidier and would leak.

The rule holds everywhere; the "nothing in ``V$SQL`` to mask" half of it does
not. On 11.2 the plain DDL is retained as well -- not in ``V$SQL``, which has no
cursor for it there either, but in ``V$SQLSTATS``, which keeps its own copy
(``docs/design/02-oracle-privileges.md`` §4). Wrapping is still strictly
worse there, so nothing this module does changes, and nothing it could do would
help: a release that retains the statement retains what the statement contains.

**Never bind the password** (invariant 14). DDL cannot take binds anyway, so on
this statement the rule costs nothing; it is stated here because
`V$SQL_BIND_CAPTURE` samples bind values at hard parse and keeps them in clear,
and the place it could really go wrong -- comparing a password or a verifier in
a predicate -- would be written by somebody who had read this module first.

**A password containing `"` is refused, not escaped** (invariant 11). An Oracle
quoted identifier has no escape sequence for a double quote, so there is no
correct escaping and refusal is the only safe handling.

### Why this repeats checks :mod:`sopuli.passwords` already makes

It does not, quite, and the difference is the whole reason both exist.
:func:`sopuli.passwords.check` answers *does this password satisfy the site's
policy* -- and UC-1 §4 lets an operator waive that answer with
``--no-policy-check`` when an external system dictated the password. This module
answers *can this password be put in a statement at all*, which nothing may
waive. A rule that can be turned off and a rule that cannot are two rules even
when they reject the same character, and collapsing them would mean
``--no-policy-check`` quietly disabling invariant 11.

So the overlap is deliberate and the constants are shared:
:data:`sopuli.config.charsets.FORBIDDEN` is the same ``"`` in both places, and
neither module spells it twice.
"""

from __future__ import annotations

from sopuli.config import charsets
from sopuli.driver.protocol import DriverError, Scope
from sopuli.exit_codes import ExitCode
from sopuli.passwords import ByteLimit
from sopuli.secrets import REDACTED, Secret

#: What a common user's name starts with in a CDB. Oracle's default, and
#: deliberately hard-coded: ``COMMON_USER_PREFIX`` is a settable parameter, so a
#: site could in principle change it. If that ever turns out to matter it is a
#: probe on connect and not a config key -- invariant 3 says ask the
#: database, and nothing here should ask a file.
COMMON_PREFIX = "C##"

#: Appended only in the one position where it is legal and meant (UC-1 §6.2).
CONTAINER_ALL = " CONTAINER=ALL"


class PasswordNotAdmissibleError(DriverError):
    """The password cannot be expressed in a statement against this target.

    ``policy`` rather than ``database``: nothing is wrong with the connection or
    the server, and what the operator changes is the password or the policy that
    produced it.

    The message says **what class of thing** was wrong and never *what it was*.
    A :class:`~sopuli.passwords.Violation` is already written to that rule --
    counts and classes, never characters or positions -- and an error that
    quoted the offending character would put part of a credential into whatever
    logs it, which is the failure invariant 2 exists to prevent.

    **The exit code is inherited on purpose**, and the silence is worth breaking
    because an unset one reads like an oversight beside the neighbours here that
    do set theirs. P5's table has no code for a policy refusal, and inventing an
    unpublished number for a scheduler to branch on is not this module's to do:
    exit codes are a published contract. Generic failure is also the exit code of
    the server's own policy refusals (``ORA-28003``, ``ORA-28007``), so the
    family agrees; a new code for it would be a change to P5.
    """

    category = "policy"


class ContainerScopeError(DriverError):
    """The account and the container the session is in do not go together.

    Exit 9 and ``config``, because that is what the operator fixes: an estate
    that points a ``C##`` account at a PDB target, or a target whose ``dsn:``
    reaches somewhere other than the file says. It is discovered on connect
    rather than at load, which does not make it less of a config error. A
    scope-assertion mismatch on connect is the same shape and should land the
    same way.

    Refusing here rather than letting the server answer is UC-1 §6.2's rule.
    ``ORA-65040`` in the middle of a rotation is a worse version of this
    sentence, arriving later and naming neither the account nor the estate.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class IdentifierError(DriverError):
    """An account name cannot be put in a quoted identifier at all.

    Its own class rather than a reuse of :class:`ContainerScopeError`, which
    would have been convenient and would have said something false: a name
    holding a ``"`` and an account being in the wrong container are not the same
    failure, and an operator reading a container message about a malformed name
    would go and look at the wrong thing.

    ``config`` and exit 9 all the same, because it is the same *fix*. Oracle
    will happily create ``"we""ird"``, so this is reachable from a real estate
    -- and what the operator does about it is stop declaring an account no
    statement can address.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class Identifier:
    """A name, in the spelling the database itself gave back.

    A username in almost every use, and a **profile name** as well.
    One type rather than two, because the rule it exists to enforce is the same
    for both -- an Oracle quoted identifier is case-sensitive and has no escape
    for a ``"`` -- and the only part that is username-specific,
    :attr:`is_common`, is asked only where a username is meant.


    ``02-oracle-privileges.md`` §4: *the username in the statement is the
    spelling read back from* ``DBA_USERS`` *after validation, never the raw
    string from config*. This type is how that stops being a sentence somebody
    has to remember -- :func:`alter_user_password` cannot be called with a
    ``str``, so the only way to reach a statement is through a value that came
    from a dictionary read.

    **A plan may still name accounts, and does not need one of these.** A plan
    is printed before anything connects, so what it names is what the config
    declared -- a string. The two are different things said at different
    moments, and this type is the seam: config names accounts, the database
    spells them, and only the spelling reaches SQL.

    Validation is what makes it safe rather than merely typed. Whatever the
    source, the name has to be something a quoted identifier can hold: no ``"``
    -- which cannot be escaped, exactly as in a password -- no control
    characters, not empty, and inside Oracle's 128-byte limit.
    """

    __slots__ = ("_name",)

    #: Oracle's maximum identifier length from 12.2. Below that it is 30, but a
    #: name this module rejects at 128 would have been rejected by the *database*
    #: at 30 -- and this value never reaches a statement without having been read
    #: back out of one, so the shorter limit polices itself.
    MAX_BYTES = 128

    def __init__(self, name: str) -> None:
        if not name:
            raise IdentifierError("an account name cannot be empty")
        if charsets.FORBIDDEN in name:
            raise IdentifierError(
                f"account name contains `{charsets.FORBIDDEN}`, "
                "which an Oracle quoted identifier cannot escape",
                hint="this name cannot be addressed by any statement; check the estate",
            )
        if any(charsets.is_control(character) for character in name):
            raise IdentifierError("account name contains control characters")
        if len(name.encode("utf-8")) > self.MAX_BYTES:
            raise IdentifierError(
                f"account name is longer than Oracle's {self.MAX_BYTES}-byte identifier limit"
            )
        self._name = name

    @property
    def name(self) -> str:
        """The bare name, unquoted. Safe to print: it is not a secret."""
        return self._name

    @property
    def is_common(self) -> bool:
        """Whether this is a ``C##`` common user.

        Case-insensitively, because ``c##app`` and ``C##APP`` are one account
        and a rule that only recognised one spelling would append
        ``CONTAINER=ALL`` to some of them.
        """
        return self._name.upper().startswith(COMMON_PREFIX)

    def quoted(self) -> str:
        """The name as it appears in a statement."""
        return f'"{self._name}"'

    def __str__(self) -> str:
        return self._name

    def __repr__(self) -> str:
        return f"Identifier({self._name!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Identifier):
            return self._name == other._name
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._name)


class Statement:
    """SQL that carries a password, and refuses to render itself.

    The same argument as :class:`~sopuli.secrets.Secret`, one level up: the text
    of ``ALTER USER … IDENTIFIED BY "…"`` is exactly as sensitive as the
    password inside it, so handing a caller a bare ``str`` would put plaintext
    somewhere a log line could reach it. Every stringification is redacted, and
    :meth:`reveal` is the one way to the real text -- named for
    :meth:`Secret.reveal` deliberately, so that grepping one method name still
    finds every place plaintext is reachable.

    That reveal is not a fourth exception to invariant 2. It *is* the driver
    call: the statement is built, executed, and dropped.

    :attr:`redacted` is the form a `--dry-run` plan prints, which is the other
    thing this type buys. A plan that showed the statement would be a plan
    nobody could paste into a ticket.
    """

    __slots__ = ("_sql", "redacted")

    def __init__(self, sql: str, *, redacted: str) -> None:
        self._sql = sql
        self.redacted = redacted

    def reveal(self) -> str:
        """The statement as it goes on the wire. Callers are audited by review."""
        return self._sql

    def __str__(self) -> str:
        return self.redacted

    def __repr__(self) -> str:
        return self.redacted


def container_clause(account: Identifier, scope: Scope) -> str:
    """What to append for ``account`` in ``scope`` -- usually nothing.

    UC-1 §6.2's table, with its guardrails made into refusals. ``CONTAINER=ALL``
    is appended in exactly one position: a ``C##`` common user, altered from
    ``CDB$ROOT``. Everywhere else the statement is plain, and two combinations
    are refused rather than sent:

    * **a ``C##`` name anywhere but the root.** §6.2: *refuse to treat*
      ``C##``-*prefixed names as local users*. A common user is one account with
      one password across the CDB, and altering it from inside a PDB is either
      an error or a different account than the one the estate meant.
    * **an application root.** An application container is a *distinct* scope:
      ``CONTAINER=ALL`` there applies within the application container only.
      Measured against a real one
      (``sql/oracle/03_app_container_probe.sql``), the hazard is sharper than that
      and points the other way -- in an application root **every** account is
      application-common, a local one cannot be created at all (``ORA-65049``),
      and a statement carrying no container clause is already container-wide.
      Confirmed by login: after a clauseless rotation in the root the new password
      authenticates in an already-synced application PDB, with no sync between.

      So the ``return ""`` below, which reads as the conservative branch, is the
      dangerous one there -- and there is no marker to catch it on, because
      ``C##`` names cannot exist in an application container at all
      (``ORA-60534``). In ``CDB$ROOT`` the prefix is the operator saying *I know
      this account spans containers*; an application root has no such statement to
      make, so the tool cannot tell an intended container-wide rotation from an
      accidental one and refuses instead.

    **An application PDB is not refused.** Measured with
    ``sql/oracle/03_app_container_probe.sql``: a local account there is
    entirely ordinary -- ``common=NO``, a plain ``ALTER USER`` accepted
    -- and an application-common one is refused by Oracle itself, ``ORA-65066``
    with no clause and ``ORA-65040`` with ``CONTAINER=ALL``. Refusing the scope
    would block the working case in order to prevent one the server already
    prevents. It takes the ordinary path below, where a ``C##`` name is refused by
    the common-user branch -- correctly, and for a second reason: such an account
    cannot exist there either.

    An ``unknown`` scope splits, and the split is the conservative reading of
    each half. An **ordinary** account gets a plain statement, because the
    conservative clause is no clause and that is what a non-CDB would have
    produced anyway. A **common** account is refused, because appending
    ``CONTAINER=ALL`` is a claim to be in the root and an unresolved scope is
    precisely not knowing that. Whether a scope the driver could not resolve may
    be acted on at all is a question for the connection, one layer earlier
    than this.
    """
    if scope.type == "app_root":
        raise ContainerScopeError(
            f'account "{account}" is in an application root, where every account is '
            "application-common and a rotation reaches the whole application container",
            hint=(
                "an ALTER USER issued here carries no container clause and is still "
                "container-wide, so this tool cannot tell one account from all of them; "
                "point the target at an application PDB, or rotate this one directly"
            ),
        )

    if not account.is_common:
        return ""

    if scope.type != "cdb_root":
        raise ContainerScopeError(
            f'account "{account}" is a {COMMON_PREFIX} common user, '
            f'but this session is in scope "{scope.type}"',
            hint=(
                "a common user is altered from CDB$ROOT with CONTAINER=ALL; "
                "point this target at the root, or name a local account"
            ),
        )

    return CONTAINER_ALL


def admissible(secret: Secret, limit: ByteLimit) -> None:
    """Refuse ``secret`` unless it can go in a statement against this target.

    ``limit`` is required, and that is the point of it being an argument at all:
    a maximum password length is 30 bytes below 23 and 128 from 23, measured
    in the *database* character set, and invariant 3 says the answer comes from
    asking the database rather than from a version in a file. Making it
    mandatory means a statement cannot be built by somebody who never found out.

    Raises :class:`PasswordNotAdmissibleError`, whose message names a class of
    problem and never a character of the password.
    """
    text = secret.reveal()

    if not text:
        raise PasswordNotAdmissibleError("the password is empty")

    if charsets.FORBIDDEN in text:
        raise PasswordNotAdmissibleError(
            f"the password contains `{charsets.FORBIDDEN}`, "
            "which an Oracle quoted identifier cannot escape",
            hint="generate another one; the alnum_safe charset excludes it by default",
        )

    if any(charsets.is_control(character) for character in text):
        raise PasswordNotAdmissibleError("the password contains control characters")

    if not limit.encodable(text):
        raise PasswordNotAdmissibleError(
            f"the password cannot be represented in the database character set ({limit.described})"
        )

    width = limit.width(text)
    if width > limit.max_bytes:
        raise PasswordNotAdmissibleError(
            f"the password is {width} bytes in {limit.described}, "
            f"and this target's limit is {limit.max_bytes}"
        )


def alter_user_password(
    account: Identifier,
    secret: Secret,
    *,
    scope: Scope,
    limit: ByteLimit,
    expire: bool = False,
) -> Statement:
    """``ALTER USER "…" IDENTIFIED BY "…"``, and nothing around it.

    The statement is issued directly. It is never wrapped in ``BEGIN`` /
    ``DECLARE`` / ``EXECUTE IMMEDIATE`` (invariant 13) and the password is never
    a bind (invariant 14) -- see this module's own docstring for the measurement
    those two come from, because the safe form is not the one that looks safe.

    Both arguments are typed rather than stringly: ``account`` is a spelling the
    database gave back and ``secret`` is a
    :class:`~sopuli.secrets.Secret`, so neither a config string nor a bare
    password can reach SQL by accident.

    ``expire`` appends ``PASSWORD EXPIRE`` -- UC-2 §4.1's seen form, where
    the owner must change the password at first logon and the expiry is what ends
    the DBA's exposure. **A suffix here and a second statement in §4.3**, which
    is not an inconsistency: this clause is part of how the password is set, and
    closing a rollover window is a separate operation Oracle spells separately.

    Two things about the suffix are worth knowing before reading a leak result
    into it. Its retention is **unmeasured on every release**
    (unverified: expire-ddl-text): Oracle's masking is keyed to the statement
    type, which gives no reason to expect a difference from the bare form and is
    not a measurement of one. And the clause goes **before** the container
    clause, because ``CONTAINER=ALL`` is the last thing Oracle accepts on this
    statement -- the reverse order is a syntax error rather than a style choice.
    """
    admissible(secret, limit)
    clause = container_clause(account, scope)
    identifier = account.quoted()
    expiry = " PASSWORD EXPIRE" if expire else ""

    return Statement(
        f'ALTER USER {identifier} IDENTIFIED BY "{secret.reveal()}"{expiry}{clause}',
        redacted=f"ALTER USER {identifier} IDENTIFIED BY {REDACTED}{expiry}{clause}",
    )


def alter_user_profile(account: Identifier, profile: Identifier, *, scope: Scope) -> Statement:
    """``ALTER USER "…" PROFILE "…"`` -- UC-1 §5's profile assignment.

    **`ALTER USER`, never `ALTER PROFILE`.** The two differ by one word and by
    everything else: this moves one account the config already whitelists onto a
    profile that exists, while ``ALTER PROFILE`` edits a shared object and so
    reaches accounts nobody selected. `02-oracle-privileges.md` §3 keeps that
    privilege off the service account deliberately and Q4 decides that the
    tool never alters a profile -- so there is no function in this module that
    builds one, which is the form that refusal takes here.

    ``profile`` is an :class:`Identifier` for the same reason ``account`` is: the
    spelling has to be one the dictionary gave back
    (:func:`sopuli.driver.oracle.accounts.resolve_profile`), because a quoted
    identifier is case-sensitive and a config file saying ``acme_app_prof``
    would otherwise address a profile no database has.

    Nothing secret, and issued directly all the same -- see
    :func:`unlock_account` for why the habit is the point.
    """
    clause = container_clause(account, scope)
    text = f"ALTER USER {account.quoted()} PROFILE {profile.quoted()}{clause}"
    return Statement(text, redacted=text)


def unlock_account(account: Identifier, *, scope: Scope) -> Statement:
    """``ALTER USER "…" ACCOUNT UNLOCK`` -- one of UC-1 §5's attributes.

    Clears ``LOCKED`` and ``LOCKED(TIMED)`` alike: Oracle has one statement for
    both, and the timed lock a failed-login limit produced is exactly the one an
    application account is most often found in.

    Nothing secret is in it, so invariants 11 and 14 have nothing to say -- and
    invariant 13 still does. It is issued directly, for
    :func:`finish_rollover`'s reason: a block containing DDL is an ordinary block
    whose own text is retained verbatim, so wrapping is the thing that exposes.
    There is nothing here to expose, and it is written the same way anyway,
    because the habit is what keeps the next one safe.

    The container clause is the same one the password statement gets, and that is
    not a convenience: a ``C##`` account is one account across the CDB, so
    unlocking it from a PDB would either fail or unlock something other than what
    the estate meant. :func:`container_clause` already refuses both.
    """
    clause = container_clause(account, scope)
    text = f"ALTER USER {account.quoted()} ACCOUNT UNLOCK{clause}"
    return Statement(text, redacted=text)


def lock_account(account: Identifier, *, scope: Scope) -> Statement:
    """``ALTER USER "…" ACCOUNT LOCK`` -- the offboarding half of the pair.

    The write counterpart of :func:`unlock_account`, and of the refusal H4
    introduces: a personal reset refuses an account in this state, because on a
    personal account somebody chose it. It is coherent for one use case to refuse
    to clear the state and to offer the verb that sets it.

    **The state this produces is `LOCKED`, and that is a different string from
    the `LOCKED(TIMED)` a failed-login limit produces** -- measured on 26ai Free
    23.26.2.0.0 (``sql/oracle/07_lock_and_rollover_probe.sql`` Q4). The
    distinction is the whole reason a plan can tell a lock somebody chose from
    one Oracle applied, so it is a fact this statement depends on rather than a
    detail about it. Also measured there: ``ALTER USER … IDENTIFIED BY`` does not
    clear it, and a login with the new password is ``ORA-28000``.

    Nothing secret is in it, so invariants 11 and 14 have nothing to say -- and
    invariant 13 still does, for :func:`unlock_account`'s reason. It is issued
    directly, and there is nothing here to expose, and it is written that way all
    the same because the habit is what keeps the next one safe.

    The container clause is the same one the password statement gets, for the
    same reason: a ``C##`` account is one account across the CDB, so locking it
    from a PDB would either fail or lock something other than what the estate
    meant.
    """
    clause = container_clause(account, scope)
    text = f"ALTER USER {account.quoted()} ACCOUNT LOCK{clause}"
    return Statement(text, redacted=text)


def expire_password(account: Identifier, *, scope: Scope) -> Statement:
    """``ALTER USER "…" PASSWORD EXPIRE`` -- force a change, set nothing.

    The **bare** form: no ``IDENTIFIED BY``, so no password is drawn, sent or
    held. That is what separates it from :func:`alter_user_password`'s
    ``expire`` suffix, which is the seen reset's, and why `account
    expire-password` needs no delivery method.

    Measured on 26ai Free 23.26.2.0.0 (``sql/oracle/08_expire_password_probe.sql``,
    twice): ``OPEN`` becomes ``EXPIRED`` and the unchanged password answers
    ``ORA-28001``. A lock is left alone -- ``LOCKED`` becomes
    ``EXPIRED & LOCKED`` -- and an open rollover window survives it, which is why
    the driver closes the window first (see
    :meth:`~sopuli.driver.protocol.Session.expire_password`).

    Nothing secret is in it, and it is issued directly anyway, for
    :func:`unlock_account`'s reason. The container clause goes last, as it does
    after the suffix in :func:`alter_user_password`.
    """
    clause = container_clause(account, scope)
    text = f"ALTER USER {account.quoted()} PASSWORD EXPIRE{clause}"
    return Statement(text, redacted=text)


def finish_rollover(account: Identifier, *, scope: Scope) -> Statement:
    """``ALTER USER "…" EXPIRE PASSWORD ROLLOVER PERIOD`` -- end the window now.

    Measured on 26ai: it takes ``ACCOUNT_STATUS`` from ``OPEN & IN ROLLOVER``
    back to ``OPEN``, and the old password stops authenticating immediately
    while the new one continues to.

    No password is involved, so invariants 11 and 14 have nothing to say here --
    but invariant 13 still does, and this is issued directly for the same reason
    ``ALTER USER … IDENTIFIED BY`` is: a block containing DDL is an ordinary
    block whose text is kept verbatim, and wrapping is the thing that exposes
    rather than the thing that protects. There is nothing secret in this
    statement, and it is written the same way anyway, because the habit is what
    keeps the next one safe.

    Nothing is redacted, so ``redacted`` is the statement itself -- which is
    worth stating rather than leaving to be noticed, since every other
    :class:`Statement` in this module has something to hide.
    """
    clause = container_clause(account, scope)
    text = f"ALTER USER {account.quoted()} EXPIRE PASSWORD ROLLOVER PERIOD{clause}"
    return Statement(text, redacted=text)
