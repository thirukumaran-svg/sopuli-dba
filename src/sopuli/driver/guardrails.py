"""Which accounts the tool refuses to touch (`02-oracle-privileges.md` §4).

Dropping the definer-rights package moved these checks out of the database and
into the tool, and §4 is unusually direct about what that costs: they **stop
being a security boundary**. A compromised service credential bypasses them
entirely. What they are instead is protection against a typo, and against a
config change with a wider blast radius than intended — which is what they
realistically were anyway for an operator who already holds SYSDBA.

Worth keeping, worth being honest about, and worth writing here rather than
inside the Oracle driver:

**The rule is product-neutral; the facts are the driver's.** "Refuse an account
the driver reports as vendor-maintained, or as holding administrative
privileges" is a sentence about credentials, not about Oracle. So this module
reads :class:`~sopuli.driver.protocol.UserState` and PostgreSQL later fills the
same fields from `pg_roles` rather than reimplementing the reasoning. The one
Oracle-shaped thing left is :data:`ORACLE_SUPPLIED`, and it is there for a
version that cannot answer the neutral question at all.

**It reviews; it does not decide.** Like :mod:`sopuli.driver.oracle.errors`,
this returns a value. Whether a refusal stops the whole run or skips one unit
depends on something this layer cannot see — see :class:`Review` for the rule
the command layer applies.

### The checks, in §4's own numbering

1. **not declared in the config.** Invariant 5: the config is the whitelist, and
   selectors filter it rather than extend it.
2. **vendor-maintained** — Oracle's ``DBA_USERS.ORACLE_MAINTAINED = 'Y'``, which
   covers SYS, SYSTEM, DBSNMP, GSMADMIN_INTERNAL and the rest without a
   hand-maintained list going stale.
3. **in the password file** — ``V$PWFILE_USERS``. The one check that routinely
   has no input: §2 does not grant that view, so on a correctly installed estate
   this answers neither yes nor no — see below.
4. **holds an administrative role** — ``DBA``, ``PDB_DBA``, ``CDB_DBA``,
   ``AUDIT_ADMIN``.
5. **on a literal deny list**, for the version that has no answer to check 2.

### Refused, permitted, or *could not establish*

The third answer arrived with #296, and it arrived because it was missing:
``UserState.password_file_member`` was ``None`` for every account on every path,
nothing populated it, and ``if state.password_file_member:`` therefore read
"nobody looked" as "not a member". Check 3 had never fired and could not.

Reading it (:func:`sopuli.driver.oracle.accounts.password_file_member`) does not
by itself fix that, because the view is deliberately outside §2's grant set: the
answer for most estates is still *unknown*. What fixes it is that unknown is now
a :class:`Caveat` — reported at warning level, refusing nothing, and pointing at
the optional grant that would settle it. "I looked and found nothing" and "I
could not look" are answers a safety report must never merge, which is what
:mod:`sopuli.driver.oracle.privileges` already says one layer up about the same
view.

### `--force` overrides 2 to 5, and never 1

Decided in #89. `DBSNMP` is the case it exists for: rotating its password is
ordinary DBA work and it is `ORACLE_MAINTAINED`, so a tool with no override does
not prevent that rotation — it moves it to SQL\\*Plus, where nothing records that
it happened. An audited override is the better failure.

**It takes two deliberate acts, not one.** `--force` alone will not rotate
`DBSNMP`: check 1 still applies, so the account has to be declared in
`accounts:` as well. That is what keeps "unusual account, deliberately managed"
distinguishable from "typo that happened to be forced past", and it is why
:class:`Review` reports what was overridden rather than merely allowing it — the
override is an audit record, not a silence.

**`--force` is not a setting**, and that is structural rather than careful. It
never enters :mod:`sopuli.settings.registry`, so it has no merge policy and no
layer to win on, which is why it cannot relax `readonly`, `max_targets`,
`confirm_environments` or `dry_run` (invariant 10). Here it is an argument to a
function and nothing else.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from sopuli.driver.protocol import UserState

#: §4 check 1. The only one `--force` cannot reach.
DECLARED = "declared"

#: §4 check 2 — the driver said this account belongs to the product.
VENDOR_MAINTAINED = "vendor_maintained"

#: §4 check 3.
PASSWORD_FILE = "password_file"

#: §4 check 4.
PRIVILEGED_ROLE = "privileged_role"

#: §4 check 5.
DENY_LIST = "deny_list"

#: The roles check 4 refuses. Upper-cased, because that is how a database spells
#: a role and how :attr:`UserState.roles` carries one.
ADMIN_ROLES = frozenset({"DBA", "PDB_DBA", "CDB_DBA", "AUDIT_ADMIN"})

#: Check 5's list, consulted **only where check 2 could not answer** — that is,
#: where :attr:`UserState.vendor_maintained` is ``None`` because the column does
#: not exist, which on Oracle means 11.2.
#:
#: Three things about it, because a list like this invites the wrong
#: expectations:
#:
#: * **It is necessarily incomplete.** An Oracle install has dozens of supplied
#:   accounts and they vary by installed option. This is the set that is
#:   common to essentially every 11.2, not an inventory.
#: * **Incompleteness is survivable and over-inclusion is cheap**, which is why
#:   it errs long. A missing entry means a maintained account is not caught by
#:   *this* check on one old version; a spurious entry means a refusal an
#:   operator clears with `--force`, audited. Those costs are not symmetrical.
#: * **It is a constant rather than a data file.** It is Oracle's list, not the
#:   site's, so nothing about it is configurable — and a file would need a
#:   schema, a loader and an error path for a fixed set of strings.
#:
#: Verifying it against the 11g XE image is a tier-2 test nobody has written
#: (`04-testing.md` §2); until then it is reasoning, and it is labelled as such.
ORACLE_SUPPLIED = frozenset(
    {
        "ANONYMOUS",
        "APPQOSSYS",
        "BI",
        "CTXSYS",
        "DBSNMP",
        "DIP",
        "EXFSYS",
        "FLOWS_FILES",
        "HR",
        "IX",
        "LBACSYS",
        "MDDATA",
        "MDSYS",
        "OE",
        "OLAPSYS",
        "ORACLE_OCM",
        "ORDDATA",
        "ORDPLUGINS",
        "ORDSYS",
        "OUTLN",
        "OWBSYS",
        "PM",
        "SCOTT",
        "SH",
        "SI_INFORMTN_SCHEMA",
        "SPATIAL_CSW_ADMIN_USR",
        "SPATIAL_WFS_ADMIN_USR",
        "SYS",
        "SYSMAN",
        "SYSTEM",
        "TSMSYS",
        "WMSYS",
        "XDB",
        "XS$NULL",
    }
)


@dataclass(frozen=True)
class Refusal:
    """One reason not to touch this account.

    ``reason`` is written for the operator who has to decide what to do about
    it, so it says which check and what was observed. Nothing here is a secret:
    an account name, a role name, a flag.
    """

    check: str
    account: str
    reason: str

    @property
    def overridable(self) -> bool:
        """Whether `--force` can waive this one.

        Everything except check 1. Acting on an account absent from the config
        would make the tool's own audit trail meaningless, so no flag reaches it
        (invariant 5).
        """
        return self.check != DECLARED


@dataclass(frozen=True)
class Caveat:
    """One check that could not be run, on an account nothing refused.

    The third answer :class:`Review` grew in #296, and the reason it is a type
    rather than a ``None`` somewhere is that "I looked and found nothing" and "I
    could not look" are answers a safety report must never merge --
    :mod:`sopuli.driver.oracle.privileges` says so about ``SYSDBA`` in the
    privilege audit, and guardrail 3 was making exactly that merge one layer
    down. A check with no input reads as a pass, and a pass is what a guardrail
    is there not to give away by accident.

    **A caveat does not refuse**, and that is the decision rather than a
    consequence of where the field sits. Check 3's input is ``V$PWFILE_USERS``,
    which ``02-oracle-privileges.md`` §2 deliberately does not grant, so the
    correctly installed estate is the one that cannot answer -- refusing on it
    would mean the tool refusing every mutation everywhere. So it reports, at
    warning level, and the run goes on: the same shape `--preflight` already has
    for a privilege audit the service account may not read.

    Same three fields as :class:`Refusal`, and deliberately not the same type. A
    caller that wanted to know whether it may proceed must not be able to reach
    for a sequence that mixes the two and get the answer wrong by iterating the
    wrong one.
    """

    check: str
    account: str
    reason: str


@dataclass(frozen=True)
class Review:
    """What the guardrails found, and what `--force` did about it.

    ``overridden`` is the reason this is a pair rather than a boolean. §4
    requires the override to be recorded in the audit event and in the JSON
    output, so a waived refusal has to survive the waiving — a `--force` that
    merely returned "allowed" would leave the run document unable to say that
    somebody rotated `DBSNMP` on purpose.

    **The rule for what a caller does with ``refusals``**, decided here so that
    every mutating verb applies the same one:

    * an account the operator **named** — `--account DBSNMP` — refuses the run.
      They asked for something the tool will not do, and quietly skipping it
      would report success for work nobody did.
    * an account that merely **fell inside** a broad selection is `SKIPPED` with
      its reason, and the run does the rest of its job. Refusing 200 rotations
      because the 47th selected account turned out to be `ORACLE_MAINTAINED`
      would make a guardrail more disruptive than the mistake it caught.

    Which of the two happened is a fact about *selection*, which this layer
    cannot see — so the rule lives here and the command applies it.
    """

    account: str
    refusals: tuple[Refusal, ...] = ()
    overridden: tuple[Refusal, ...] = ()
    #: Checks that could not be run at all (#296). Reported, never refusing --
    #: see :class:`Caveat`. Unaffected by ``force``, because there is nothing to
    #: waive: a check that produced no answer produced no refusal either, and a
    #: run that would have overridden the answer had it come still did not get
    #: one. Suppressing these under ``--force`` would hide the missing grant from
    #: the one operator most likely to be looking at what the guardrails did.
    caveats: tuple[Caveat, ...] = ()

    @property
    def permitted(self) -> bool:
        """Whether the tool may proceed against this account.

        Caveats are **not** consulted. A check that could not be run has refused
        nothing, and #296 decided that an unestablished guardrail reports rather
        than blocks -- the alternative refuses every account on every estate
        installed exactly as §2 documents.
        """
        return not self.refusals


def is_declared(account: str, declared: Collection[str]) -> bool:
    """Whether ``account`` is in the config's declared set (§4 check 1).

    **Case-folded**, because the two sides spell accounts differently and
    neither is wrong: `01-configuration.md` writes `acme_web_user` and Oracle
    stores `ACME_WEB_USER`, since an unquoted identifier is upper-cased on the
    way in. Comparing exactly would refuse every correctly-declared account on
    Oracle, which is a guardrail that fires only on its own users.

    The residual risk is an estate holding both `ACME_WEB_USER` and a quoted
    `"acme_web_user"` as genuinely different accounts, where this would accept
    one on the strength of the other's declaration. That is worth naming and not
    worth solving: a binding addresses one account, and an estate spelling two
    accounts the same way has a problem this check would not be the first to hit.
    """
    folded = {name.casefold() for name in declared}
    return account.casefold() in folded


def review(state: UserState, *, declared: Collection[str], force: bool = False) -> Review:
    """Every §4 check, against one account.

    ``state.name`` is the spelling the **database** gave back, which is what the
    checks run on: config says which accounts may be touched, and the database
    says what they are.

    ``force`` waives checks 2 to 5 and never check 1, and what it waives is
    reported in :attr:`Review.overridden` rather than dropped.

    **A check with no input is neither**, and that is the third answer #296 added:
    it lands in :attr:`Review.caveats`, refuses nothing, and survives ``force``
    untouched. Check 3 is the only one that can produce one today.
    """
    found: list[Refusal] = []
    caveats: list[Caveat] = []
    name = state.name

    if not is_declared(name, declared):
        found.append(
            Refusal(
                DECLARED,
                name,
                "the config does not declare this account, and no flag extends the whitelist",
            )
        )

    if state.vendor_maintained:
        found.append(
            Refusal(VENDOR_MAINTAINED, name, "the database reports this account as its own")
        )
    elif state.vendor_maintained is None and name.upper() in ORACLE_SUPPLIED:
        # Check 5 runs only where check 2 had nothing to say. On a version that
        # answers, the answer wins -- a list maintained by us must not overrule
        # the database describing itself.
        found.append(
            Refusal(
                DENY_LIST,
                name,
                "this version cannot say whether the account is vendor-maintained, "
                "and the name is one the product supplies",
            )
        )

    if state.password_file_member:
        found.append(Refusal(PASSWORD_FILE, name, "the account is in the password file"))
    elif state.password_file_member is None:
        # The third answer, and the ordinary one (#296). `V$PWFILE_USERS` is not
        # in §2's grant set, so a correctly installed service account gets here
        # -- which is why this is a caveat and not a refusal. What it must not
        # be is silence: an unread check reads as a pass, and check 3 read as one
        # for every account of every run from the day it was written until this.
        caveats.append(
            Caveat(
                PASSWORD_FILE,
                name,
                "could not establish whether the account is in the password file",
            )
        )

    held = sorted(ADMIN_ROLES & {role.upper() for role in state.roles})
    if held:
        found.append(Refusal(PRIVILEGED_ROLE, name, f"the account holds {', '.join(held)}"))

    if not force:
        return Review(account=name, refusals=tuple(found), caveats=tuple(caveats))

    return Review(
        account=name,
        refusals=tuple(refusal for refusal in found if not refusal.overridable),
        overridden=tuple(refusal for refusal in found if refusal.overridable),
        # Carried through the waiver unchanged. `--force` waives an answer, and a
        # caveat is the absence of one -- see :attr:`Review.caveats`.
        caveats=tuple(caveats),
    )
