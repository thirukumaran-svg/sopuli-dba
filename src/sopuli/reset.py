"""Deciding whether one personal account may have its password reset (UC-2).

:mod:`sopuli.suspend`'s shape, one verb over. The DDL is the driver's
(:meth:`~sopuli.driver.protocol.Session.reset_password`) and so is what each of
its three statements does; what is here is everything that must be answered
**before** a password is drawn, let alone delivered.

Four gates, in this order, and the order is what makes the refusals cheap:

1. **is there anywhere to deliver** -- a reset with nowhere to put the password
   must not touch the database, and this needs no connection to answer;
2. **is it declared** -- invariant 5, which H1 makes harder than a list
   lookup by allowing a predicate;
3. **is the account in a state a reset may touch** -- H4: a deliberate
   ``LOCKED`` is refused and a ``LOCKED(TIMED)`` is not;
4. **do the guardrails allow it** -- ``02-oracle-privileges.md`` §4's five
   checks, unchanged and shared with every other mutating verb.

**Pure, and it issues nothing.** It takes the :class:`UserState` the caller read
and returns a decision, so every refusal is tier 0 (``04-testing.md`` §4). That
matters more here than it did for `account suspend`: three of decision #439's
five guards are properties of a *run* -- the output format, whether stdout is a
terminal, whether ``--confirm`` was typed -- and a guard that could only be
tested by building a terminal would be a guard tested once, by hand.
:func:`refuse_seen_path` takes those three as arguments for exactly that reason.

**One account, and the plan is the whole blast radius**, as UC-2 §2 requires of
every mutating verb: the account is named on the command line and a predicate
narrows rather than widens.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.delivery import IMPLEMENTED, MANUAL
from sopuli.config.errors import ArgumentError
from sopuli.config.model import Config, Delivery
from sopuli.driver.guardrails import Review, review
from sopuli.driver.oracle.accounts import deliberately_locked
from sopuli.driver.protocol import UserState
from sopuli.exit_codes import ExitCode
from sopuli.personal import declared_on
from sopuli.safety import RefusedError

#: ``results[].state`` words this verb uses, all already in the run schema's
#: ``state`` enum. A verb needing a new one would be saying something the
#: contract has no word for, which is a schema question rather than a verb's.
RESET = "RESET"
ACCOUNT_MISSING = "ACCOUNT_MISSING"
SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class Decision:
    """Whether to reset, and what to report either way."""

    proceed: bool
    state: str
    detail: str
    #: Whether the reset expires the password -- the seen path, and never a
    #: default. Carried on the decision rather than re-derived by the caller so
    #: that one answer reaches the plan, the driver and the view.
    expire: bool = False
    #: The §4 review, where one was run. ``None`` where the account was not found
    #: or not declared -- there was nothing to review, and an empty
    #: :class:`Review` would read as *every check passed*.
    review: Review | None = None

    @property
    def refused(self) -> bool:
        """Whether this is a refusal rather than an ordinary no-op."""
        return not self.proceed and self.state == SKIPPED


def deliverable(delivery: Delivery | None) -> Delivery:
    """The delivery this run will use, or a refusal -- asked at **plan** time.

    Returns the block rather than checking and discarding it, so a caller cannot
    hold an ``Optional`` it has already proved is not ``None``: the type says the
    check happened.

    Two absences with two messages, because the operator's next move differs:
    nothing configured at all is a file to edit, and a method this build does not
    implement is a wait or a different method.

    **A refusal rather than the warning `config validate` gives.** E4/E5's shape
    -- valid file, incomplete install -- is right for the question *is this file
    usable*, and wrong for the question *reset this password now*: a reset that
    got as far as the database and then found nowhere to deliver would have
    changed a password nobody can be told, which is §6.4's lockout written the
    long way round.

    Exit 5, the capability code, rather than 9: the file is not wrong. It names a
    method UC-2 §6.2 defines and this build cannot serve, which is what exit 5
    has meant since P1 -- and what `SOPULI-W003` already says about a store whose
    backend is not installed.
    """
    if delivery is None:
        raise RefusedError(
            "no `delivery:` is configured, so a new password would have nowhere to go",
            hint=(
                "a reset hands a password to a person; without a delivery method there is "
                "nobody to hand it to. Configure `delivery:` (UC-2 6.2), or use "
                "`account expire-password` if what you want is to force a change"
            ),
        )
    if delivery.method not in IMPLEMENTED:
        raise DeliveryUnavailableError(delivery.method)
    return delivery


class DeliveryUnavailableError(RefusedError):
    """The configured delivery method is not implemented in this build.

    Its own class because the exit code differs from its parent's: this is the
    estate asking for something the *build* cannot do, which is exit 5's whole
    meaning, while `RefusedError`'s 8 is the estate correctly saying no.
    """

    exit_code = ExitCode.UNSUPPORTED_CAPABILITY
    category = "capability"

    def __init__(self, method: str) -> None:
        names = [f"`{one}`" for one in IMPLEMENTED]
        served = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"
        super().__init__(
            f"`delivery.method: {method}` is configured and is not implemented in this build",
            hint=(
                f"this build serves {served}; UC-2 §6.2 describes the others. "
                "`config validate` warns about this before a run needs it"
            ),
        )


def refuse_seen_path(
    delivery: Delivery,
    *,
    is_json: bool,
    stdout_is_terminal: bool,
    stdin_is_terminal: bool,
    confirm_given: bool,
    preview: bool = False,
) -> None:
    """Decision #439's guards 2, 3 and 4, asked before a password is drawn.

    Guard 1 is structural rather than a check -- the one ``reveal()`` lives in
    :mod:`sopuli.output.reset_view` and is reachable only from the seen path --
    and guard 5 is the config layer's, because `force_expire` is a property of
    the file (:func:`sopuli.config.delivery._build_manual`).

    Nothing here is true of an unseen delivery, so all three are skipped for one. An
    unseen delivery still prints something: §6.1 bars the wrapping token from the
    notify channel and the tool carries no other, so the token prints, to be passed
    on out of band.

    The guards are skipped because each is about a **password** on a screen: a
    prompt establishes somebody is watching one, the terminal check keeps one out of
    a log that outlives its expiry, and the JSON refusal keeps one out of the
    document. What an unseen delivery emits is a retrieval credential with a TTL of
    its own, whose single use makes interception detectable -- a different object,
    argued in `output/delivery_view.py`, which is also why it goes to stderr rather
    than being refused under `--output json`.

    **A ``--dry-run`` is skipped for the same reason.** A preview prints a plan and
    never a password -- UC-2 §2 says so of every mutating verb, and invariant 8 is
    where it comes from -- so there is no emission for any of these to guard.
    Refusing a preview for want of a terminal would make the one thing a CI job
    legitimately wants from this verb impossible: *show me what a reset would do*,
    answered by a refusal about a screen nobody needed.

    **Guard 4 needs stdin to be a terminal as well** (#853). The prompt comes
    after the DDL and reads stdin. A closed stdin would read end of input after
    the password was set, so nobody would ever see it, and a pipe such as
    `yes |` would answer the prompt that no flag may answer.

    **Checked before the password exists.** Every one of these is knowable from
    argv and the environment, so finding out after the draw -- or worse, after
    the DDL -- would mean a run that changed a password and then refused to say
    what it was.

    **The two usage errors come before the environment one.** In the order json,
    terminal, confirm, a redirected run with ``--confirm`` would be told about the
    terminal, which leaves the flag refusal unreachable from anything but a real
    console. Both orders are defensible and this one is better for the caller it is
    about: a script passing ``--confirm`` has made a mistake in its *command line*,
    and telling it about a terminal it was never going to have answers a question it
    did not ask.
    """
    if delivery.method != MANUAL or preview:
        return

    if is_json:
        # `policy sample --reveal`'s refusal, one verb over, and the same way
        # round: the machine-readable format is the safe one, so it wins and the
        # revealing path is what has to go.
        raise ArgumentError(
            "`delivery.method: manual` cannot be used with --output json or --output jsonl",
            hint=(
                "json is what gets captured and shipped to log aggregation, so a working "
                "password never appears in it -- use the text output, or an unseen "
                "delivery method"
            ),
        )

    if confirm_given:
        # The one gate in the tool that cannot be given a yes in advance (P5;
        # decision #439). A flag cannot testify to its own premise: `--confirm`
        # would be asserting that somebody is watching, when establishing that
        # somebody is watching is the entire purpose of the prompt.
        raise ArgumentError(
            "--confirm cannot answer the prompt `delivery.method: manual` asks",
            hint=(
                "that prompt is not a formality to be waived: the run is about to print a "
                "working password to a screen, and a flag cannot establish that somebody "
                "is at it. Drop --confirm and answer it -- if that is impossible, nobody "
                "is there to receive the password either"
            ),
        )

    if not stdout_is_terminal:
        # The guard the whole argument rests on, and the one `--reveal` has no
        # counterpart for. There is deliberately no flag to defeat it: a flag
        # that exists to weaken a guard ends up in scripts, which is the exact
        # place this value must never reach.
        raise RefusedError(
            "`delivery.method: manual` prints a password, and stdout is not a terminal",
            hint=(
                "a value redirected to a file or captured in a CI log outlives the single "
                "logon it is good for, and expiry does not unpublish it. Run this at a "
                "terminal and read the password off the screen -- `| clip` and `| pbcopy` "
                "do not work here, deliberately -- or use an unseen delivery method"
            ),
        )

    if not stdin_is_terminal:
        raise RefusedError(
            "`delivery.method: manual` asks before it shows the password, "
            "and stdin is not a terminal to answer from",
            hint=(
                "the prompt comes after the password is set, so a closed stdin would leave "
                "a password nobody has seen, and a pipe would answer a prompt no flag may "
                "answer. Run this at a terminal with nothing redirected into it, or use an "
                "unseen delivery method"
            ),
        )


def decide(
    state: UserState | None,
    *,
    config: Config,
    account: str,
    target: str,
    delivery: Delivery,
    force: bool = False,
) -> Decision:
    """May this run reset ``account`` on ``target``?

    :func:`sopuli.suspend.decide`'s shape, and deliberately so: the declaration
    is expressed *through* the review's check 1 rather than short-circuiting it,
    so there is one refusal vocabulary and one place that decides what ``--force``
    may waive. ``state`` is ``None`` where the account does not exist there, which
    is a finding rather than an error (Q8).

    **The deliberate lock is checked before the review and is not waivable.** It is
    not one of §4's five checks, so ``--force`` has nothing to say about it: that
    flag overrides *account guardrails*, and this is somebody's offboarding decision
    (H4). Checking it first also keeps the message specific -- reported through
    check 1 it would read as *not declared*, which is a different thing to go and
    look at.
    """
    if state is None:
        return Decision(
            proceed=False,
            state=ACCOUNT_MISSING,
            detail="the account does not exist on this target",
        )

    if deliberately_locked(state.status):
        return Decision(
            proceed=False,
            state=SKIPPED,
            detail=(
                f"the account is {state.status.lower()}; a reset does not unlock a "
                f"deliberate lock -- unlock it first if that is what you mean"
            ),
        )

    rule = declared_on(
        config,
        state.name,
        target,
        profile=state.profile,
        roles=state.roles,
    )
    found = review(state, declared=[state.name] if rule is not None else [], force=force)

    if not found.permitted:
        return Decision(
            proceed=False,
            state=SKIPPED,
            detail="; ".join(refusal.reason for refusal in found.refusals),
            review=found,
        )

    return Decision(
        proceed=True,
        state=RESET,
        detail=f"declared by {rule.label}" if rule is not None else "declared",
        expire=delivery.is_seen,
        review=found,
    )
