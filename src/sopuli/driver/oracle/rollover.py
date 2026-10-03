"""Gradual password rollover: the profile check, the window, the finish (#181).

What makes zero-downtime rotation real, and the default strategy where the
capability exists (UC-1 §6.3). During a window **both the old and the new
password authenticate**, which is why a partial apply across several PDBs causes
no outage at all under this strategy.

Measured on 26ai Free 23.26.2.0.0, because three of these would have been got
wrong by reasoning.

**Both passwords really do work, and the finish really does end it.** With
`PASSWORD_ROLLOVER_TIME 1/24` on the profile, an account rotated from
``Old-Pa55-word1`` to ``New-Pa55-word2`` accepted *both* logins; after
``ALTER USER … EXPIRE PASSWORD ROLLOVER PERIOD`` the old one answered
``ORA-01017`` and the new one still worked, and ``ACCOUNT_STATUS`` went from
``OPEN & IN ROLLOVER`` back to ``OPEN``.

**The limit is a fraction of a day, not a count.** ``PASSWORD_ROLLOVER_TIME
1/24`` reads back as the string ``.0416``. Anything parsing it as an integer --
which is the obvious thing to do beside ``FAILED_LOGIN_ATTEMPTS`` -- refuses a
correctly configured profile. **And it is not always days**: 19.32.0.0.0 reads
the same profile back as ``3600``, in seconds (#583), which :func:`days` tells
apart by range.

**Finishing a window that is not open is accepted silently.** The server returns
no error, so invariant 9's ``changed: false`` on a second run is *the tool's*
job: issuing the statement blindly would report a change that did not happen.
:func:`~sopuli.driver.oracle.session.OracleSession.finish_rollover` reads the
state first for that reason and no other.

**Nothing in the dictionary says when a window ends.** ``DBA_*`` and the ``V$``
views were searched for a column named for rollover and there is none;
``SYS.USER$`` has ``PTIME`` and sixteen ``SPARE`` columns and nothing that
admits to it. So :func:`window_end` **derives** the value from two that were
read -- the password change date and the profile's rollover time -- and it is
the one field in :class:`~sopuli.driver.protocol.UserState` that is computed
rather than reported. That is a deliberate reversal of the placeholder #178
left, taken because #181 asks for when the window ends and ``null`` is a worse
answer than Oracle's own documented arithmetic over two measured inputs. It is
populated **only while a window is actually open**, since ending one early
leaves the change date untouched and the derivation pointing into a future that
no longer applies.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

#: What ``PASSWORD_ROLLOVER_TIME`` means when rollover is switched off. The
#: resource exists on every release that has the feature, so its *presence* is
#: the capability (#177) and its *value* is whether this profile uses it. 26ai
#: reads "off" back as ``0`` and 19.32.0.0.0 as ``-1`` (#583); :func:`days`
#: returns this for both.
DISABLED = 0.0

#: Oracle bounds the resource at one hour to 60 days, and renders it in days on
#: 26ai (``1/24`` reads ``.0416``) but in **seconds** on 19.32.0.0.0 (``1/24``
#: reads ``3600``, ``7`` reads ``604800``; #583). The two renderings of that
#: range do not overlap -- days ``(0, 60]``, seconds ``[3600, 5184000]`` -- so
#: the value says which unit it is in, and nothing here asks which release
#: produced it (invariant 3).
MAX_DAYS = 60.0
SECONDS_PER_DAY = 86400.0
MIN_SECONDS = 3600.0
MAX_SECONDS = MAX_DAYS * SECONDS_PER_DAY


def days(limit: str | None) -> float | None:
    """``PASSWORD_ROLLOVER_TIME`` as a number of days, or ``None`` if unreadable.

    A string because that is how a profile limit arrives, and a float because
    ``1/24`` reads back as ``.0416``. ``UNLIMITED`` is not a value this resource
    takes, and anything else unparseable is ``None`` rather than a guess -- a
    window length nobody can read is not a window length of zero.

    **The unit is read off the value** (#583, decided there): zero or below is
    off and returns :data:`DISABLED`; ``(0, 60]`` is days; ``[3600, 5184000]``
    is seconds and is converted. Anything else -- between the two ranges, or past
    the larger -- is a value no profile can hold, so it is ``None`` rather than
    a guess at which unit somebody meant.

    **Non-finite values are unreadable too**, which is not obvious because
    ``float()`` accepts them: ``float("inf")`` and ``float("1e400")`` both give
    infinity, and ``float("nan")`` gives NaN. Left alone, ``inf`` would satisfy
    :func:`is_enabled` -- claiming a window -- and then raise ``OverflowError``
    the moment :func:`window_end` tried to describe it. A value this function
    cannot use is ``None``, and that is the whole rule.
    """
    if limit is None:
        return None
    try:
        value = float(limit)
    except ValueError:
        return None
    if not math.isfinite(value):
        return None
    if value <= DISABLED:
        return DISABLED
    if value <= MAX_DAYS:
        return value
    if MIN_SECONDS <= value <= MAX_SECONDS:
        return value / SECONDS_PER_DAY
    return None


def is_enabled(limit: str | None) -> bool:
    """Whether this profile actually grants a rollover window.

    The capability says the *release* has the feature; this says the *profile*
    uses it. `--strategy rollover` needs both, and they fail differently: an
    absent capability is exit 5 naming the capability and the target, while a
    profile set to zero is a configuration the operator can change -- and the
    tool reports the ``ALTER PROFILE`` for it rather than issuing one (Q4/#88,
    and `02-oracle-privileges.md` §3's must-not-grant list).
    """
    value = days(limit)
    return value is not None and value > DISABLED


def window_end(changed_at: datetime | None, limit: str | None) -> datetime | None:
    """When an open window closes -- **derived**, never read.

    ``password_change_date + PASSWORD_ROLLOVER_TIME``, which is Oracle's
    documented definition of the period and the only way to have the value at
    all: no dictionary column exposes it. Both inputs are read, so this is
    arithmetic over measurements rather than a guess about behaviour -- but it is
    still the one computed field in a type whose every other value came from the
    server, which is why it says so here.

    ``None`` when either input is missing, which includes 11.2, where
    ``PASSWORD_CHANGE_DATE`` does not exist (#87) -- and where rollover does not
    exist either, so the pair are never both wanted.

    **Fails closed rather than raising.** :func:`days` already caps the value at
    60, so an overflow cannot reach here today; the guard stays because this is
    a field derived for a *report*, and a cap is easier to loosen than to
    notice. Crashing ``describe_user`` because a profile holds an absurd limit
    would take out the command that was going to tell somebody about it.
    """
    value = days(limit)
    if changed_at is None or value is None or value <= DISABLED:
        return None
    try:
        return changed_at + timedelta(days=value)
    except (OverflowError, ValueError):
        return None


def alter_profile_ddl(profile: str, rollover_days: str = "1") -> str:
    """The statement an operator would run to enable rollover on ``profile``.

    **Reported, never issued.** Profiles are shared, so changing one affects
    accounts nobody selected, and `02-oracle-privileges.md` §3 keeps
    ``ALTER PROFILE`` off the service account deliberately. Q4 (#88) decided
    that the tool never alters a profile, and this function is that answer: it
    reports the statement for an operator to run.
    """
    return f"ALTER PROFILE {profile} LIMIT PASSWORD_ROLLOVER_TIME {rollover_days};"


__all__ = [
    "DISABLED",
    "alter_profile_ddl",
    "days",
    "is_enabled",
    "window_end",
]
