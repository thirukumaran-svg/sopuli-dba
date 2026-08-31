"""What a run establishes before it writes anything (UC-1 §8 step 3, #283).

Step 3 exists so that the common failures -- wrong privileges, a closed PDB, an
unreachable host -- happen *before* anything is written anywhere. Without it a
rotation discovers on target nine that target ten was never going to work, and
by then nine databases hold a password the vault has not promoted.

Pure, like :mod:`sopuli.apply` and :mod:`sopuli.check`: every function is of
values the caller already holds, so the decision table is testable without a
container. The command opens the connections and reads the facts; this says what
they mean.

**It reviews; it does not decide**, which is
:mod:`sopuli.driver.guardrails`'s arrangement and for the same reason. Whether a
finding stops the whole run or is merely reported depends on what the command
was asked to do, and that is something this layer cannot see.

**The checks are §8's own list, in §8's own order** -- reachable, correct scope,
account exists, privileges present, capability present. The order is not
cosmetic: it is the order in which each answer stops being knowable. An
unreachable target has no scope to compare, a wrong container makes every account
question meaningless, and a survey that reported them in some other order would
send somebody to the wrong problem first.

**Capability is not here**, and its absence is the decision. Invariant 4 requires
a capability refusal to name the capability and the target and to carry its own
exit code, and :class:`~sopuli.driver.protocol.UnsupportedCapabilityError`
already is that refusal -- raised by the strategy pre-flight this one shares a
connection with. A second spelling of it here would be a second thing to keep in
step with invariant 4.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sopuli.driver.protocol import Scope

#: §8's checks, in §8's order. Used as ``Finding.check``, which is what a
#: consumer branches on rather than reading the message.
REACHABLE = "reachable"
SCOPE = "scope"
ACCOUNT = "account"
PRIVILEGES = "privileges"

#: The order above, as data, so :func:`refusal` cannot drift from it.
ORDER = (REACHABLE, SCOPE, ACCOUNT, PRIVILEGES)


@dataclass(frozen=True)
class Finding:
    """One thing wrong with one target, found before anything was written.

    ``category`` is the run document's own (``03-json-output.md`` §2's closed
    enum) and travels on the finding rather than being inferred from ``check`` by
    whoever reports it. The two are not the same question: ``check`` says which
    of §8's five this is, and ``category`` says which kind of failure it is for a
    consumer that branches on `error.category` -- a missing grant is
    ``authorization`` whether it was found here or by `doctor`.

    ``account`` is set only on the findings that are about one, which is
    :data:`ACCOUNT` today. A finding about the target carries ``None`` rather
    than repeating the target name, so a reader can tell "this database is in the
    wrong container" from "this account is missing from it".

    ``blocking`` is what separates *this estate cannot do what you asked* from
    *this survey could not establish something*. A missing grant blocks; a
    privilege audit the account was not allowed to read does not, because it has
    established nothing either way -- and refusing over it would mean an estate
    that will not grant the audit view can never use a pre-flight at all. It is
    still reported, loudly, for the reason UC-1 §7 gives about the `LCOUNT`
    guard: a check that is not running has to say so rather than be silently
    skipped.
    """

    target: str
    check: str
    message: str
    hint: str | None = None
    account: str | None = None
    category: str = "database"
    blocking: bool = True


def assertion_holds(
    *, declared_scope: str | None, declared_container: str | None, scope: Scope
) -> bool:
    """Whether what the file claims about a target matches what it turned out to be.

    ``01-configuration.md`` §3a lets a target assert its ``scope`` and its
    ``container``; #177 made the driver report what is actually true. This is the
    comparison of the two, and it is the check that catches a ``dsn:`` edit that
    silently repointed a target at a different container -- the edit whose whole
    danger is that everything keeps working, against the wrong database.

    A target that asserts nothing holds trivially. The assertion is opt-in
    (§3a), and treating "said nothing" as "said something wrong" would refuse
    every estate that had not filled the field in.

    **The container comparison is case-folded and the scope one is not.** A
    container name is an Oracle identifier, upper-cased on the way in, so
    ``freepdb1`` and ``FREEPDB1`` are one name; ``scope`` is this tool's own
    vocabulary from a closed set in the config schema, where a case difference
    would be a config error the loader should have caught rather than a match to
    make generous.
    """
    if declared_scope is not None and declared_scope != scope.type:
        return False
    if declared_container is not None:
        return declared_container.upper() == (scope.container or "").upper()
    return True


def unreachable(target: str, *, message: str, hint: str | None = None) -> Finding:
    """The target could not be connected to at all (§8 step 3, first check).

    Its own constructor rather than a branch inside :func:`survey`, because the
    caller reaches it on a different path: there is no :class:`Scope` to pass and
    no session to have read anything from. ``connectivity`` is the category even
    when the driver's own message says otherwise, since what stopped the run is
    that this database could not be talked to.
    """
    return Finding(
        target=target,
        check=REACHABLE,
        message=message,
        hint=hint,
        category="connectivity",
    )


def survey(
    target: str,
    *,
    scope: Scope,
    declared_scope: str | None = None,
    declared_container: str | None = None,
    missing_accounts: Sequence[str] = (),
    missing_privileges: Sequence[str] = (),
) -> tuple[Finding, ...]:
    """Everything wrong with one reachable target, in §8's order.

    Four checks, and each is a refusal the run would otherwise have discovered
    with part of the estate already changed:

    * **the scope the file claims**, per :func:`assertion_holds`, reported with
      both values named so the reader can see which of the two is wrong;
    * **the database is not open read-write.** On a physical standby the answer
      is false, and P1 requires the refusal up front rather than a statement
      failing halfway through. ``None`` is *not* a refusal: a driver that could
      not determine the open mode has not established that the database is
      read-only, and refusing on an unknown would turn a missing probe into an
      outage;
    * **an account the config declares and the database has not got.** UC-1 §5
      step 3 already reports this per account and does not create it (Q8), and
      finding it here is the difference between reporting it and reporting it
      *before* a password was staged for it;
    * **a privilege the tool needs and the service account has not got.** The
      one worth the round trip: without it the run fails at the verb that needs
      it, several commands from here, with an error about a dictionary view
      rather than about the install.
    """
    found: list[Finding] = []

    if not assertion_holds(
        declared_scope=declared_scope, declared_container=declared_container, scope=scope
    ):
        found.append(
            Finding(
                target=target,
                check=SCOPE,
                message=(
                    f"declares scope={declared_scope!r} container={declared_container!r}, "
                    f"found scope={scope.type!r} container={scope.container!r}"
                ),
                hint=(
                    "the `dsn:` or the assertion is wrong; a target that moved container "
                    "silently keeps working against the wrong database"
                ),
            )
        )

    if scope.read_write is False:
        found.append(
            Finding(
                target=target,
                check=SCOPE,
                message=f"the database is not open read-write (open_mode {scope.open_mode!r})",
                hint="a standby or a read-only PDB cannot take an `ALTER USER`",
            )
        )

    for account in missing_accounts:
        found.append(
            Finding(
                target=target,
                check=ACCOUNT,
                message="the config declares this account; the database has no such user",
                hint=(
                    "create it, or remove it from `accounts:` -- this tool does not create accounts"
                ),
                account=account,
            )
        )

    if missing_privileges:
        found.append(
            Finding(
                target=target,
                check=PRIVILEGES,
                message=(f"the service account is missing {', '.join(sorted(missing_privileges))}"),
                hint="run the install script for this target's scope (`sql/00_install.sql`)",
                category="authorization",
            )
        )

    return tuple(found)


def refusal(findings: Sequence[Finding]) -> Finding | None:
    """The finding a refusal is reported as, or ``None`` where nothing blocks.

    Every finding is reported -- the point of a pre-flight is to fix an estate in
    one pass rather than one round trip per problem -- but a run has one exit
    code and one ``error`` object, so one of them has to be *the* reason. It is
    the earliest in :data:`ORDER`, which is the one closest to the cause: a
    target that could not be reached explains its own missing scope, and a
    container that turned out to be the wrong one explains every account that
    was not found in it.

    Ties inside a check go to the order they were surveyed in, which is the order
    the targets were walked.

    **Only blocking findings are considered**, so a run whose survey produced
    nothing but caveats goes ahead -- with the caveats in its document. This is
    also the predicate a caller uses to ask *did the pre-flight refuse*, rather
    than testing whether any finding at all came back.
    """
    blocking = [one for one in findings if one.blocking]
    if not blocking:
        return None
    return min(blocking, key=lambda one: ORDER.index(one.check))


def summarise(findings: Sequence[Finding]) -> str:
    """The run-level message: how many, over how many targets, and the first one.

    The count is the part that is not in the ``error`` object otherwise. A
    consumer reading one message needs to know whether it is looking at the whole
    problem or the first of eleven, and an operator reading the text has the
    table above it either way.
    """
    first = refusal(findings)
    if first is None:  # pragma: no cover - callers check before asking
        raise ValueError("no blocking findings to summarise")
    blocking = [one for one in findings if one.blocking]
    targets = len({one.target for one in blocking})
    plural = "" if len(blocking) == 1 else "s"
    over = "1 target" if targets == 1 else f"{targets} targets"
    return (
        f"pre-flight found {len(blocking)} problem{plural} over {over}, "
        f"and nothing was written: {first.target}: {first.message}"
    )
