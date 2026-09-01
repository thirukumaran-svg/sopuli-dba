"""Which rollover regime `creds apply` runs under, and which ones it can (#262).

UC-1 §6.3 makes gradual password rollover the **default where it exists**, and it
is what makes zero-downtime rotation real: during the window both the old and the
new password authenticate, so an application picks the new one up on its own
schedule and a partial apply causes no outage at all.

`creds apply` (#259) already ran under one of these regimes; what it could not do
is let an operator name one, or refuse one the estate cannot honour. That is what
this module decides.

Pure and vendor-free. The one thing that needed vendor parsing --
``PASSWORD_ROLLOVER_TIME`` is a string in whatever the database spells -- is
:attr:`~sopuli.driver.protocol.UserState.rollover_enabled`, computed by the
driver where that parsing belongs.

**The statement is the same in all three regimes.** That is the fact worth
holding on to, and it is why this is a flag rather than three code paths:

===========  ==================================  ================================
strategy     statement                           after
===========  ==================================  ================================
``rollover``  ``ALTER USER … IDENTIFIED BY …``   the window opens; both passwords
                                                 work until it closes
``staged``    the same                           the change is immediate
``direct``    the same                           the window is closed at once, so
                                                 the old password stops working
===========  ==================================  ================================

What differs is the **precondition** and the **follow-up**.

**Oracle decides whether a window opens, not this tool.** That is the thing that
makes the feasibility table less obvious than it looks: a window opens because
the account's *profile* grants one, so ``--strategy staged`` against a
rollover-enabled profile is a request the database will not honour -- it will open
a window regardless. Refusing that is the whole reason this module exists rather
than a one-line default. Silently running ``rollover`` while reporting ``staged``
would tell an application team the old password had stopped working when it had
not.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    PASSWORD_ROLLOVER,
    AccountAttributes,
    Scope,
    UserState,
)

__all__ = [
    "DIRECT",
    "ROLLOVER",
    "STAGED",
    "STRATEGIES",
    "Unhonourable",
    "closes_window",
    "default_for",
    "extra_detail",
    "moves_profile",
    "moving_profile",
    "opens_window",
    "unhonourable",
]

#: Both passwords authenticate until the profile's window elapses (UC-1 §6.3).
ROLLOVER = "rollover"
#: The change is immediate and the operator owns the application-side restart.
STAGED = "staged"
#: The change is immediate because the window is closed as soon as it is opened.
DIRECT = "direct"

#: What ``--strategy`` accepts, in the order §5 lists them.
STRATEGIES = (ROLLOVER, STAGED, DIRECT)


@dataclass(frozen=True)
class Unhonourable:
    """Why a requested strategy cannot run here.

    A value rather than an exception, for the reason
    :mod:`sopuli.driver.oracle.errors` gives about classification: the same
    finding is a plan-time refusal when the operator asked for the strategy and
    is *nothing at all* when the tool was choosing for itself. The caller knows
    which it is doing.
    """

    #: One sentence naming what is wrong, in the shape an error message wants.
    message: str
    #: What to do about it. Never ``None`` -- every case here has an action.
    hint: str
    #: The driver capability that was missing, where one was. ``None`` where the
    #: capability is present and the *configuration* is what refuses, which is a
    #: different kind of answer and gets a different exit code.
    capability: str | None = None


def opens_window(user: UserState) -> bool:
    """Whether ``ALTER USER … IDENTIFIED BY`` will open a rollover window here.

    A property of the account's **profile**, not of the request: Oracle opens the
    window because ``PASSWORD_ROLLOVER_TIME`` is greater than zero, whatever the
    tool wanted. Unknown (``None``) reads as *no*, which is the direction that
    cannot surprise anybody -- a run that expected no window and got one is a
    grace period nobody was told about, and a run that expected one and did not
    get it reports the change as immediate, which it was.
    """
    return bool(user.rollover_enabled)


def default_for(scope: Scope, user: UserState) -> str:
    """The regime to run under when ``--strategy`` was not given.

    §6.3's own rule: ``rollover`` where the capability exists and the profile
    grants a window, ``staged`` otherwise. Never ``direct`` -- ending a grace
    window early is destructive to whoever still holds the old password, and a
    default that did it would be making that decision for an operator who did not
    know there was one.
    """
    if scope.supports(PASSWORD_ROLLOVER) and opens_window(user):
        return ROLLOVER
    return STAGED


def closes_window(strategy: str, user: UserState) -> bool:
    """Whether this run must end the window it just opened.

    Only ``direct``, and only where a window actually opens. ``direct`` against a
    profile that grants none is honoured by doing nothing extra: the change was
    already immediate, which is what the operator asked for, and issuing
    ``EXPIRE PASSWORD ROLLOVER PERIOD`` to prove it would be a statement with no
    work in it.
    """
    return strategy == DIRECT and opens_window(user)


def moves_profile(user: UserState, attributes: AccountAttributes) -> str | None:
    """The profile this run would move ``user`` onto, or ``None`` (#301).

    ``None`` covers the two cases that are not a move and are not the same thing:
    nothing was declared, and the account is already there. Only the first is
    about the config; the second is what makes the attribute idempotent, and it is
    answered here as well as in the driver because the pre-flight has to know
    *before* it connects to the next target whether this run is going to move
    anything.

    Case-folded, because Oracle stores an unquoted identifier upper-cased and a
    file writing ``acme_app_prof`` means the profile the dictionary calls
    ``ACME_APP_PROF``. An account whose profile the database did not report --
    ``None`` -- reads as a move, which is the direction that cannot mislead: the
    run says it will set something and the driver then finds it already set.
    """
    declared = attributes.profile
    if declared is None:
        return None
    if user.profile is not None and user.profile.upper() == declared.upper():
        return None
    return declared


def moving_profile(strategy: str | None, user: UserState, to: str | None) -> Unhonourable | None:
    """Why a named regime cannot be judged for an account this run will move (#301).

    The interaction that makes profile assignment more than a statement: **a
    profile decides whether a rollover window opens**, so it decides the regime a
    rotation runs under. :func:`unhonourable` answers about the profile the
    account holds *now*, and for an account this run is about to move that is the
    profile it is leaving -- so ``--strategy staged`` could be cleared against an
    old profile and then run under a new one that opens a window, which is exactly
    the silent mislabelling §6.3 exists to prevent.

    Rather than judge against a profile the account does not hold yet, the pair is
    **refused**: name a regime or move the account, not both in one run. The two
    are separate intentions and the second is a change to this account's password
    *policy* -- a thing worth its own run and its own review.

    ``None`` where there is nothing to refuse, and the first of those is the
    ordinary case: **no ``--strategy``**. The default regime is resolved per
    account *after* the attribute pass, from the profile the account ends on, so
    it is already right and there is nothing here to protect it from.
    """
    if strategy is None or to is None:
        return None
    return Unhonourable(
        message=(
            f"this run would move it from {user.profile or 'an unreported profile'} to {to}, "
            f"and the regime a rotation runs under is a property of the profile it ends on"
        ),
        hint=(
            "rotate under the profile it has, or let this run do the move and rotate "
            "afterwards -- naming a regime and changing the profile that decides one are "
            "two intentions for one run"
        ),
    )


def unhonourable(strategy: str, scope: Scope, user: UserState) -> Unhonourable | None:
    """Why ``strategy`` cannot run for this account here, or ``None``.

    **Rollover is not answered here**, and that is not an omission:
    :meth:`sopuli.driver.protocol.Session.require_rollover` already owns it
    (#181), with the two refusals it needs -- the release that has no such
    feature, and the profile that grants no window -- and the second carries the
    exact ``ALTER PROFILE`` an operator would run. A second phrasing of those
    here would be one message with two versions, and the version this module
    could write would be the worse one: the DDL is that product's SQL, and this
    module is above the driver.

    What is left is the pair the driver has no reason to know about, because
    both are about a regime the operator asked for rather than about a
    capability:

    * **``staged`` against a rollover-enabled profile.** The refusal worth
      reading twice. It looks like the safe, unambitious option and it is the one
      request Oracle will quietly ignore -- the window opens because the profile
      says so, and a run reporting ``staged`` would be telling an application
      team the old password had stopped working when it had not.
    * **``direct`` where a window opens and cannot be closed.** Ending it early
      needs :data:`~sopuli.driver.protocol.EXPIRE_PASSWORD`; without it the run
      would open a grace window the operator explicitly asked not to have.

    ``capability`` is set on the second and not the first, and the difference is
    the one invariant 4 turns into an exit code: a limitation of the release, or
    a configuration somebody can change.
    """
    if strategy == STAGED and opens_window(user):
        return Unhonourable(
            message=_will_open(user),
            hint=(
                "a window opens because the profile grants one, not because the tool "
                "asked -- use `--strategy rollover` to accept it, or `--strategy direct` "
                "to close it as soon as it opens"
            ),
        )

    if strategy == DIRECT and opens_window(user) and not scope.supports(EXPIRE_PASSWORD):
        return Unhonourable(
            message=(
                "this database cannot end a rollover window early, and this account's "
                "profile opens one"
            ),
            hint=(
                "use `--strategy rollover` and let the window elapse, or have the "
                "profile's PASSWORD_ROLLOVER_TIME set to 0 by whoever owns it"
            ),
            capability=EXPIRE_PASSWORD,
        )

    return None


def extra_detail(strategy: str, user: UserState) -> str | None:
    """What this regime did that the outcome does not already say, or ``None``.

    Only ``direct`` has anything to add. ``rollover`` reaches
    :data:`~sopuli.check.ROLLOVER_ACTIVE`, whose own sentence already says the
    previous password still authenticates; ``staged`` is an ordinary password
    change and needs no gloss. ``direct`` is the case where something extra
    happened -- a window opened and was closed again inside one run -- and that is
    the difference between "the old password stops working in an hour" and "the
    old password stopped working just now", which is what an application team
    needs to hear.
    """
    if closes_window(strategy, user):
        return "the rollover window was closed, so the previous password no longer works"
    return None


def _will_open(user: UserState) -> str:
    """The refusal's own sentence for a profile that opens a window anyway."""
    where = "this account's profile" if user.profile is None else f"profile {user.profile}"
    return (
        f"{where} grants a rollover window "
        f"(PASSWORD_ROLLOVER_TIME is {user.rollover_time}), so one opens whatever "
        f"this run asks for"
    )
