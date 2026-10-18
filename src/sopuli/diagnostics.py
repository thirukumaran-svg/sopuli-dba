"""Warnings that carry a code, and the registry of what each code means.

Consumers branch on a code, not on a message, so warnings carry stable
machine-readable codes with a documented registry. This is that registry.

**Every warning that reaches a run document has a code** (J3,
``03-json-output.md`` §3). The codes are one flat series, ``SOPULI-W001``
upwards. The next code is the next free number, and a number is never reused.
``tests/test_warning_codes.py`` fails on two codes with one number, on a gap,
and on a registry that disagrees with the document's table.

For `doctor`, it is settled **when a finding gets a diagnostic at all**: one
for what the exit code cannot tell you. An unreachable store fails the run, so
anything watching the exit code already knows and the entry in ``vaults[]``
names it -- exactly as an unreachable *target* is an entry and never a
diagnostic. A store that answered and cannot serve, or a clock outside the
lock's tolerance, leaves the run exiting 0 with something still wrong, and that
is what a diagnostic is for.

A code, once emitted, is part of the contract in the same way an enum value is
(``03-json-output.md`` §8): adding one is a minor bump, changing what one means
is not a bump at all but a lie. So the registry maps each to a sentence, and
``tests/test_lock_view.py`` asserts that nothing emits a code the registry
does not describe.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from types import MappingProxyType

from sopuli.admin import Resolved
from sopuli.clock import Skew, to_rfc3339
from sopuli.config.codes import (
    DELIVERY_UNSERVICEABLE,
    NOTIFY_UNSERVICEABLE,
    PROFILE_NAMED_AFTER_ENVIRONMENT,
    RELAXATION_DEFEATED,
    THIRD_PARTY_VARIABLE_UNAPPLIED,
    UNREAD_POLICY_KEYS,
    UNVERIFIED_TRANSPORT,
)
from sopuli.constraints import NAMED, POLICY, UNKNOWN, AccountConstraints, Constraints
from sopuli.driver.guardrails import PASSWORD_FILE, Caveat
from sopuli.driver.oracle.wallet import AUTO_LOGIN, WalletReport
from sopuli.driver.protocol import ENCRYPTION_NONE, Encryption, UserState
from sopuli.driver.protocol import UNKNOWN as ENCRYPTION_UNKNOWN_METHOD
from sopuli.install_shape import INSTALLED, InstallShape
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, LockManager, Unguarded
from sopuli.lock.record import LockRecord
from sopuli.output.document import Diagnostic, DiagnosticLevel
from sopuli.store.protocol import OK
from sopuli.store.survey import VaultReport

#: A store is holding locks it cannot guard (``locking: advisory-only``).
ADVISORY_LOCKING = "SOPULI-W001"

#: A lock was taken from whoever held it -- automatically, because it was past
#: its expiry and ``locking.break_expired`` permits that, or deliberately by
#: ``sopuli lock break``. One code, because it is one event: what differs
#: is whether a config key or a person decided it, and a consumer alerting on
#: "somebody's lock was taken" wants both.
LOCK_TAKEN_OVER = "SOPULI-W002"

#: A ``vaults:`` entry names a backend **this machine cannot serve** -- its
#: client is not installed, or this build has no module for it.
#: One code for both, because they are one outage and differ only in the
#: remedy, which the message carries; splitting them would make a consumer
#: alerting on an unusable store subscribe to two.
MISSING_BACKEND = "SOPULI-W003"

#: A store in the survey has no ``list`` capability, so the report covers only
#: the paths the configuration declares.
UNLISTABLE_STORE = "SOPULI-W005"

#: A ``targets:`` entry names a driver this machine cannot serve, read
#: as widely as :data:`MISSING_BACKEND` is.
#: Its own code rather than a widening of :data:`MISSING_BACKEND`, whose
#: registered description names a ``vaults:`` entry: one code meaning "some
#: backend or other is missing" would leave a consumer unable to tell a store it
#: cannot reach from a database it cannot reach, which are different outages.
MISSING_DRIVER = "SOPULI-W006"

#: An account's password is in its grace period: past ``PASSWORD_LIFE_TIME`` and
#: inside the window ``PASSWORD_GRACE_TIME`` grants (UC-1 §6.4).
#:
#: **A warning beside a state, never a state.** The account may be `IN_SYNC` or
#: it may have drifted, and ``state`` is one field -- a value of its own here
#: would have to displace one of those answers, and either choice hides the thing
#: the reader came for. Riding alongside is what lets a run say *drifted, and
#: expiring on Friday*, which is the report worth paging on.
PASSWORD_GRACE_PERIOD = "SOPULI-W013"

#: A login **succeeded** and the server attached a diagnostic to it.
#:
#: Its own code rather than a widening of :data:`PASSWORD_GRACE_PERIOD`, and the
#: two do co-occur: a grace-period account produces both, because they are
#: different sources saying the same thing -- one is what ``ACCOUNT_STATUS`` says
#: about the account, the other is what the server said on this login, in its own
#: words. Reported side by side rather than deduplicated, because the tool cannot
#: know they are the same fact without matching on a vendor code list, and that
#: list is version- and profile-dependent (``ORA-28098`` and ``ORA-28011`` are one
#: condition). Corroboration reads better than a guess.
LOGIN_WARNING = "SOPULI-W014"

#: `creds generate` could not read a target's password constraints, so the
#: policy's declared length governed the draw (UC-1 §4 step 2).
#:
#: A **warning** rather than an error because §4 makes the fallback legitimate:
#: staging a password for an estate that is down is a thing operators do, and the
#: run staged one. What it cannot do is stay quiet -- a password drawn against a
#: policy alone and one drawn against a database that answered are different
#: claims about the same run, and nothing in the password distinguishes them.
#:
#: One code for both shapes it reports, none-answered and some-answered, because
#: the remedy is identical -- reach the targets and run it again -- and the
#: message names which targets in either case. A consumer alerting on this is
#: watching "the draw was not checked against the estate", and a partial read is
#: that with fewer databases missing rather than a different condition.
#:
#: ``--offline`` emits nothing. It is the operator saying they know, and a
#: warning that fires because a flag was passed teaches its reader to filter it.
CONSTRAINTS_UNREAD = "SOPULI-W015"

#: An account's profile names a password verify function, or whether it names one
#: could not be established (UC-1 §4 step 2).
#:
#: **Reported, never acted on.** A verify function is arbitrary PL/SQL and cannot
#: be consulted before the ``ALTER USER`` is issued (invariants 13 and 14), so
#: this does not gate a draw and is not a prediction that one will be refused --
#: the run answers a refusal by redrawing. It says that something other than the
#: policy will judge this password, which is a thing an operator who has just
#: staged one should not have to learn from `apply`.
#:
#: The not-knowing shares the code rather than getting its own, because the
#: consequence is the same: this run cannot tell you that the password will be
#: accepted. §5's `--preflight` rule is that not knowing is not a finding, and
#: the message says which of the two it is -- what it must never do is report the
#: unreadable case as *no verify function*, which reads as a guarantee.
#:
#: One per (target, profile) rather than per account. A verify function is a
#: property of the profile, and an estate that puts forty accounts on one profile
#: would otherwise get forty copies of one fact.
VERIFY_FUNCTION_UNCHECKABLE = "SOPULI-W016"

#: An account's profile restricts password reuse, and this run was given a
#: password rather than drawing one (UC-1 §4 step 2).
#:
#: **Only under ``--from-stdin``**, which is the whole reason it is a separate
#: code from :data:`VERIFY_FUNCTION_UNCHECKABLE`. A drawn password is fresh
#: randomness and cannot collide with a hashed history in any practical sense, so
#: warning about reuse on an ordinary `creds generate` would be a warning that
#: fires on every run and means nothing on any of them. A *supplied* password is
#: whatever an external system dictated, and "the one it had last year" is an
#: ordinary thing for one to dictate.
#:
#: The reuse history is hashed, so this is no more a prediction than
#: :data:`VERIFY_FUNCTION_UNCHECKABLE` is: the values are reported and the reader
#: applies the rule, because ``PASSWORD_REUSE_MAX`` and ``PASSWORD_REUSE_TIME``
#: interact -- one of them ``UNLIMITED`` beside a number is not the same regime as
#: both being numbers -- and this run measured neither interaction nor the
#: history.
PASSWORD_REUSE_ENFORCED = "SOPULI-W017"

#: A §4 account guardrail could not be run, because the fact it checks could not
#: be read. The run went ahead; the check did not.
#:
#: Its own code, because a code exists for what the exit code cannot tell you.
#: This run exits 0 with every account applied, and the thing that is not in the
#: exit code, the states, or ``results[].overridden`` is that one of
#: the five checks contributed nothing to the answer. An operator who reads
#: ``changed: true`` and no refusal is entitled to believe five checks passed.
#:
#: **Not a refusal**, and the reason is the estate rather than the severity.
#: Check 3 reads ``V$PWFILE_USERS``, which ``02-oracle-privileges.md`` §2
#: deliberately does not grant -- so refusing on an unread check would refuse
#: every mutation on every correctly installed target. The optional grant is what
#: silences it, which is what makes it a warning worth leaving on rather than one
#: a reader learns to filter: it has a remedy, and taking the remedy is a site's
#: decision about how much of the guardrail set it wants.
#:
#: One per (target, check) rather than per account, on
#: :data:`VERIFY_FUNCTION_UNCHECKABLE`'s reasoning: the missing grant is a
#: property of the target, and an estate with forty accounts on one database
#: would otherwise be told the same fact forty times.
GUARDRAIL_UNCHECKED = "SOPULI-W018"

#: An estate uses ``auth: external`` and this machine has no wallet it can read.
#: Its own code rather than a widening of anything above: the remedy is a
#: file on this machine, and a consumer that alerts on "sopuli cannot reach a
#: store" is watching a different outage from one that alerts on "the wallet the
#: service account authenticates with has gone".
WALLET_UNUSABLE = "SOPULI-W007"

#: A wallet file somebody other than its owner can reach (P4). Separate
#: from :data:`WALLET_UNUSABLE` because the two are opposite conditions -- one
#: says the credential is not there, the other says it is there and everyone can
#: have it -- and because only the second is something to alert on rather than to
#: fix while you are already looking.
WALLET_NOT_PRIVATE = "SOPULI-W008"

#: This host's clock is further from a configured store's than the advisory lock
#: allows. Its own code because it is the only finding in the vault
#: survey that is neither visible in the exit code nor a property of the store:
#: it is a property of the pair, and the machine to fix is usually this one.
CLOCK_SKEW_BEYOND_TOLERANCE = "SOPULI-W009"

#: A configured store answered and cannot serve this run: sealed, standing by,
#: not initialised, or refusing the credential it was opened with.
#:
#: Separate from an *unreachable* store, which gets no code at all -- that one
#: fails the run, so a consumer watching the exit code already knows, and the
#: entry in ``vaults[]`` says which store and why. This is the opposite case: the
#: run exits 0 and something is still wrong, which is precisely what a
#: diagnostic is for.
STORE_DEGRADED = "SOPULI-W010"

#: This run's lock was taken over while it was running, found at a fence check
#: (UC-1 §8). The run stopped before its next mutation and promoted
#: nothing; what it had already applied stands.
#:
#: Its own code because it is the one thing the exit code cannot say. A fenced-out
#: run exits 4, and so does a run that simply failed on some targets -- and the
#: two want opposite responses. The second is repaired by running `apply` again;
#: the second run of the first would be denied at exit 7 if it is lucky, and the
#: person reading the output needs to know that somebody else is mid-rotation on
#: this estate before they decide anything. The rule is the same: a code exists
#: for what the exit code cannot tell you.
#:
#: Distinct from :data:`LOCK_TAKEN_OVER`, which is the *other* side of the same
#: event -- there, this run did the taking and says so; here, it was taken from.
#: One code for both would leave a consumer unable to tell the run that broke a
#: lock from the run that lost one, which are opposite things to be paged about.
LOCK_LOST = "SOPULI-W011"

#: A rotation promoted a document and then read a different password back out of
#: it (UC-1 §8 step 8).
#:
#: Its own code, because the exit code cannot say this. The run exits 4,
#: which it would also do with half its targets failed -- and those two are
#: opposite situations. Here *every* database took the new password and the
#: promotion was acknowledged; the estate is converged and it is the vault that
#: is not serving what it accepted. Replication lag on a store with read
#: replicas is the ordinary cause, and the next action is to look at the vault
#: rather than at any database.
#:
#: Not to be read as "the rotation failed". Nothing needs undoing, `creds apply`
#: converges what is left, and an application that fetched `current` in the
#: window may have got the old password -- which is the fact worth paging about
#: and the one nothing else in the document says.
ROTATION_UNCONFIRMED = "SOPULI-W012"

#: A lock path was created without the store being made to require a
#: compare-and-set on it, because this run's credential may not set metadata.
#:
#: Emitted once per path, on the run that creates it and never again -- a path
#: whose metadata *is* set never reaches this, and one somebody else created
#: without it is refused outright rather than warned about.
#:
#: Its own code, because the exit code cannot say this.
#: The run succeeds, the lock it took was itself written under a compare-and-set,
#: and the fence held for every mutation -- so nothing in the result is wrong.
#: What is missing is the store enforcing the same rule on *other* writers, which
#: is a property of the path that outlives this run and will be just as missing on
#: the next one. That is a thing to go and fix in the vault, and nothing else in
#: the document says it.
#:
#: Deliberately not a widening of :data:`ADVISORY_LOCKING`, which is the run
#: having no fence at all by configuration. Here the run has one; it is everybody
#: else who is unconstrained. A consumer alerting on "this estate is locking
#: without a fence" wants the first and would be paged wrongly by the second.
LOCK_PATH_UNGUARDED = "SOPULI-W019"

#: The document ``creds apply --repair`` was handed is old enough to be worth
#: saying so (UC-1 §``--repair``).
#:
#: A warning and never a refusal, which is the decision this code exists to
#: carry: a threshold that stopped the run would have to be wrong for somebody,
#: and the run it refused would have been safe. Two properties make it safe --
#: the set can only narrow (invariant 5), and a pair since repaired costs one
#: login and reports ``changed: false`` -- so a stale document is wasteful
#: rather than dangerous.
#:
#: It names the age rather than quoting the threshold, because what the reader
#: does with "eleven days" is decide whether that is still the estate they are
#: looking at, and no constant here can decide it for them. It is a condition the
#: exit code cannot report: the run exits 0 having done less than
#: the operator may have expected, and nothing else in the document says the
#: narrowing came from something written last week.
REPAIR_DOCUMENT_STALE = "SOPULI-W020"

#: The database would not say when an account's password was last set, and the
#: message says why.
#:
#: **It exists to make an omission legible.** `results[].password_age_days` is a
#: documented field that is simply absent when the date is unknown, and `creds
#: status` prints ``-`` -- the same answer on a release that has no such column
#: as on one where something could not be read. A consumer cannot see a dash,
#: and an operator cannot tell the two apart without reading the source.
#:
#: **On `results[].warnings[]`, one per account**, beside the field it explains
#: -- unlike :data:`GUARDRAIL_UNCHECKED`, which is grouped per target. The field
#: that is missing is per result, and a consumer reading one result should not
#: have to join it to a run-level array to learn why that result has a hole. The
#: text output groups it per target instead, because a person reading forty
#: identical lines under a table learns to stop reading notes.
#:
#: Reported and never acted on, like the date itself: nothing gates on it (Q9).
PASSWORD_CHANGE_DATE_UNKNOWN = "SOPULI-W021"

#: A target's admin credential came from the environment. P2 says the
#: ``env`` source is "supported, and flagged low-assurance in output", and
#: ``01-configuration.md`` §3a says twice that it "stays flagged wherever it is
#: reported". This code is what reports :attr:`sopuli.admin.Resolved.low_assurance`.
#:
#: **A code exists for what the exit code cannot tell you.** The run connects,
#: succeeds and exits 0 -- the credential worked -- and nothing else in the
#: document says *how* the tool got hold of it. A reader cannot distinguish a
#: run that authenticated from a wallet from one that
#: authenticated from a variable some CI job exported, and those are different
#: claims about how well guarded the estate is.
#:
#: **Keyed on assurance, not on the method.** :data:`sopuli.admin.LOW_ASSURANCE`
#: is the set, so a second low-assurance source starts emitting this without
#: finding every reporting site again -- which is the mistake the comment on
#: :data:`sopuli.admin.LOW_ASSURANCE` warns against.
#:
#: **One per target per run**, and the message names the variable rather than
#: the method: ``Resolved.source`` is the half an operator can act on, because
#: what they do next is go and look at where that variable is set.
#:
#: A warning and never a refusal. P2 *supports* this source -- bootstrapping an
#: estate that has no other way in is the case it exists for -- so a run that
#: refused it would refuse the situation the source was added for. What is owed
#: is that the run says so.
LOW_ASSURANCE_ADMIN = "SOPULI-W022"

#: `account list` had no reset journal to read, so its ``RESET_AT`` column is
#: empty (UC-2 §3.4).
#:
#: **Raised by the listing verb**, not by the reset. §3.4's absence is stated for
#: a reset, and it is `account list` that has a documented column to leave empty
#: because of it.
#:
#: **It is `SOPULI-W021`'s rule applied to the other date column.** §2 says so
#: outright: a documented column that vanishes with nothing saying why is a hole
#: in the contract. So the dash is accompanied by this, and the message says
#: which of the absences it is -- no journal configured, as against a journal
#: with no record for this account yet, which is not this code and is not a
#: finding at all.
#:
#: A warning and never a refusal, for §3.4's reason: an estate that keeps no
#: journal is a documented mode, not a broken one. A person who cannot log in is
#: still locked out whether or not the estate keeps history.
NO_RESET_JOURNAL = "SOPULI-W023"

#: A reset wrote no record, because the configuration declares no
#: `reset_records:` block (UC-2 §3.4's first absence).
#:
#: **Its own code rather than** :data:`NO_RESET_JOURNAL`, which says the same
#: thing about a different verb: that one explains an empty column in a listing,
#: and this one says a mutation went unrecorded. A consumer that had to tell them
#: apart by reading the message would be parsing prose to find out whether
#: anything happened.
#:
#: **Raised at plan time**, before the password changes, which is §3.4's own
#: requirement and the whole reason it is worth saying: an operator who did not
#: mean to run without a journal should find out while it can still be fixed
#: rather than afterwards.
#:
#: It says *and no lock was taken*, because where there is no store there is no
#: lock either (§3.3) -- two facts with one cause, and an operator told only the
#: first would not learn that two concurrent resets of one account are not
#: serialised.
NO_RESET_RECORD = "SOPULI-W024"

#: The reset succeeded and its record could not be written (UC-2 §3.4's second
#: absence).
#:
#: **A warning on a successful run**, never a rollback and never a non-zero exit.
#: The password has already changed and the person still needs it, so failing the
#: run would report a false negative about the part that mattered.
#:
#: Distinct from :data:`NO_RESET_RECORD` because the operator's next move differs:
#: an absent journal is a configuration somebody chose, and a failed write is
#: something to go and look at -- a revoked token, a policy that grants read and
#: not write, or a store that is not there.
RESET_RECORD_UNWRITTEN = "SOPULI-W025"

#: The reset succeeded and nobody could be told it was waiting.
#:
#: **A warning on a successful run**, for :data:`RESET_RECORD_UNWRITTEN`'s reason
#: and more easily: by the time anything is posted the password has changed and the
#: person can fetch it, so a run that failed over an unsent notification would
#: report a false negative about the part that mattered. A notification carries
#: nothing anybody needs -- §6.1 keeps it to "a password is ready" -- so the cost of
#: losing it is that somebody has to be told another way.
#:
#: Distinct from the two above it because the object differs rather than the
#: severity: those are about a *record*, which is read later and by other people,
#: and this is about a *message*, which is read now and by one person. The next
#: move differs too -- a failed notification is usually a revoked webhook, and the
#: remedy is to tell the person directly today and fix the URL afterwards.
NOTIFICATION_UNSENT = "SOPULI-W026"

#: A document was not promoted because this run was narrower than the promotion.
#: Invariant 7 asks that every target confirm before `current` moves, and
#: a run cannot confirm a pair it was told to leave out.
#:
#: **Its own code for `SOPULI-W011`'s reason**: the run exits 4, and so does one
#: whose targets failed, and the two want different next moves. A failed target
#: is repaired by the same narrowed run again; this is finished only by a run
#: wide enough to include the pairs the message names, and repeating the narrow
#: one withholds the promotion again, for ever.
PROMOTION_WITHHELD = "SOPULI-W027"

#: A rollback applied `previous` to an account whose profile restricts password
#: reuse. `previous` is, by construction, a password the account held one
#: change ago whenever this tool made that change, so it is the value most likely
#: of any to be in the reuse history -- which is `ORA-28007`, measured on ADB's
#: own `DEFAULT` (`4` / `1`) and on tier 1's `SOPULI_REUSE` (`5` / `UNLIMITED`).
#:
#: **Its own code rather than** :data:`PASSWORD_REUSE_ENFORCED` **widened**,
#: because that code's registry sentence says only `--from-stdin` produces it, and
#: this module's docstring is plain that changing what an emitted code means is a
#: lie rather than a bump. A consumer that branched on W017 as "a supplied
#: password" would be told something false about a rollback.
#:
#: Reported rather than refused, and the values reported rather than interpreted,
#: which is UC-1 §4's rule (decision #568): when both limits are
#: numbers, whether the reuse is allowed depends on changes made outside the tool,
#: which it cannot see. Raised on every rollback that reaches the statement on
#: such a profile, whichever way the statement went.
ROLLBACK_REUSE_RESTRICTED = "SOPULI-W028"

#: The server refused a password and the run drew another (UC-1 §6.4).
PASSWORD_REDRAWN = "SOPULI-W029"

#: The server refused a password and the run was not allowed to draw another.
PASSWORD_NOT_REDRAWN = "SOPULI-W030"

#: This run sent a password over a connection that is not encrypted (#697).
#: Not a refusal: the maintainer's decision is to warn. One per target.
CONNECTION_UNENCRYPTED = "SOPULI-W031"

#: This run sent a password over a connection whose encryption could not be
#: established (#697). Its own code, apart from :data:`CONNECTION_UNENCRYPTED`,
#: for :data:`GUARDRAIL_UNCHECKED`'s reason: a check that did not run is not a
#: pass, and a consumer must be able to tell "in clear" from "did not look"
#: without parsing a message. One per target.
CONNECTION_ENCRYPTION_UNKNOWN = "SOPULI-W032"

#: Every target confirmed and the promotion write failed (UC-1 §8 row 7, #805).
#: The run exits 4, and without this nothing else in the document says why: every
#: row is confirmed. Its own code for `SOPULI-W011`'s reason. A failed target is
#: repaired by the same run again, and so is this, but the reader looks first at
#: the vault, because a refused compare-and-set means another writer.
PROMOTION_FAILED = "SOPULI-W033"

#: `creds status --max-age-days`: the vault last rotated this credential longer
#: ago than the threshold. The vault's age, not the database's, which is why it
#: is a warning and not ``password_age_days`` (Q9).
ROTATION_OVERDUE = "SOPULI-W040"

#: `account list` admitted an account the database reports as its own, so a
#: mutating verb refuses it at plan time (guardrail 2).
ADMITTED_VENDOR_ACCOUNT = "SOPULI-W041"

#: `account list` admitted an account that an application also declares, which
#: only a predicate can reach (H1).
ADMITTED_CROSS_DECLARED = "SOPULI-W042"

#: `creds rotate --finish-rollover` left a rollover window open, because the
#: vault may not serve the new password.
ROLLOVER_LEFT_OPEN = "SOPULI-W043"

#: The pre-flight could not read the privilege audit, so it established nothing
#: about the target's grants. A finding of the ``privileges`` check that does
#: not block. Each pre-flight check that can warn has its own code.
PRIVILEGE_AUDIT_UNREAD = "SOPULI-W044"

#: The pre-flight could not establish whether the profile an account would move
#: to exists. A finding of the ``profile`` check that does not block.
PROFILE_UNREAD = "SOPULI-W045"

#: `creds generate --overwrite-pending` replaced a ``pending`` that was already
#: staged.
PENDING_REPLACED = "SOPULI-W046"

#: `creds generate --promote --overwrite-current` replaced ``current``.
CURRENT_REPLACED = "SOPULI-W047"

#: `creds generate --no-policy-check` accepted a password that violates the
#: policy. One per rule the password violates.
POLICY_VIOLATION_ACCEPTED = "SOPULI-W048"

#: On one `creds apply` result: ``current`` may not hold the password this
#: database has, because the database changed and did not confirm, or because
#: the promotion write failed (:data:`PROMOTION_FAILED` says why, once per
#: document).
CHANGED_NOT_PROMOTED = "SOPULI-W049"

#: A document was not promoted because a guardrail skipped one of its accounts on
#: one target and the run applied it on another (#852). The skipped target still
#: holds the old password, so promoting would break invariant 7. Its own code for
#: `SOPULI-W011`'s reason: nothing failed, and the same run again skips the same
#: pair, so the remedy is to clear what the guardrail reported, or `--force`
#: with the document's accounts named.
PROMOTION_SKIPPED = "SOPULI-W050"

#: ``SOPULI-W004`` and ``SOPULI-W034`` to ``SOPULI-W039`` -- imported above
#: rather than defined here. They are raised in the config layer, which cannot
#: import this module, so they are defined in :mod:`sopuli.config.codes` and
#: the registry below stays the one place that says what each means.
#: Importing them here is also what puts them in this module's namespace, so
#: ``from sopuli.diagnostics import UNVERIFIED_TRANSPORT`` reads the same as
#: every other code.

#: Every code this build can emit, and what each one means. The description is
#: the contract; the message wording around it is not, and may improve.
WARNINGS: MappingProxyType[str, str] = MappingProxyType(
    {
        ADVISORY_LOCKING: (
            "A store in this run is configured `locking: advisory-only`, so its lock "
            "record was written without compare-and-set. The run has no fence: two "
            "runs starting in the same second can both believe they hold the lock."
        ),
        LOCK_TAKEN_OVER: (
            "A lock was taken from its holder: automatically, because it was past its "
            "expiry and `locking.break_expired` permits that, or deliberately by `sopuli "
            "lock break`. The previous holder is fenced -- its next check will fail -- but "
            "it may have applied changes before that."
        ),
        MISSING_BACKEND: (
            "A `vaults:` entry names a backend this machine cannot serve. The config is "
            "valid and the install is incomplete, and what that is worth depends on the "
            "question asked: `config validate` warns and exits 0, `doctor` fails, and any "
            "command that resolves that store to a client fails, with SOPULI-20001 where "
            "the client is not installed and SOPULI-20005 where this build has no module "
            "for the type."
        ),
        MISSING_DRIVER: (
            "A `targets:` entry names a driver this machine cannot serve. As with a store, "
            "the config is valid and the install is incomplete, and what that is worth "
            "depends on the question asked: `config validate` warns and exits 0, `doctor` "
            "fails, and any command that connects to that target fails, with SOPULI-20002 "
            "where the client is not installed and SOPULI-20006 where this build has no "
            "module for the type."
        ),
        PASSWORD_GRACE_PERIOD: (
            "An account's password is in its grace period: it still authenticates, and it "
            "stops on the date in the message. Informational rather than a failure -- the "
            "credential works and the vault may well hold it -- but the window closes, and "
            "`creds apply` clears the expiry by setting a password, so this is the notice "
            "that there is time to do it in."
        ),
        LOGIN_WARNING: (
            "A login succeeded and the server attached a diagnostic to the connection "
            "rather than raising -- a password in its grace period is the ordinary cause. "
            "The verification passed and the message is carried verbatim with its vendor "
            "code, because a server that had something to say about a credential is worth "
            "hearing whether or not it refused one."
        ),
        UNVERIFIED_TRANSPORT: (
            "A store in this run is configured `tls.verify: false`, so its certificate is "
            "not checked. Anything on the path can present its own and read every secret "
            "that crosses. The key is under the safety ratchet, so no layer can weaken "
            "this further -- but nothing in the run undoes it either."
        ),
        WALLET_UNUSABLE: (
            "An estate uses `auth: external`, and this machine has no auto-login wallet "
            "that this process can read -- so the connection will fail as an Oracle "
            "*login* error, which is the most misleading way for a file-permission "
            "problem to appear. A warning and not a verdict: the target's own "
            "reachability decides the run, and this says why in advance."
        ),
        WALLET_NOT_PRIVATE: (
            "A wallet file in this run's `TNS_ADMIN` is reachable by somebody other than "
            "its owner. An auto-login wallet is a credential -- whoever can read it can "
            "authenticate as the account it holds. `doctor` warns and never fails: it is "
            "somebody else's file, and refusing to run would block the person who ran it "
            "over a condition they did not create."
        ),
        CLOCK_SKEW_BEYOND_TOLERANCE: (
            "This machine's clock is further from a configured store's than the advisory "
            "lock tolerates. A lease's expiry is compared against the local clock, so a run "
            "on this host will take over locks that are still live, or refuse ones that are "
            "long dead -- and the failure looks like a locking bug rather than an NTP "
            "problem. `doctor` warns and never fails: the condition is real, this run did "
            "not create it, and refusing to survey an estate over it would block the person "
            "who ran it."
        ),
        LOCK_LOST: (
            "This run's lock was taken over by another while it was running, found at a "
            "fence check. It stopped before its next mutation and promoted nothing, so "
            "the vault still advertises the password it did before -- but whatever it "
            "had already applied to a database stands. Do not simply re-run it: another "
            "run holds this estate's lock, and `creds check` is what establishes what is "
            "true."
        ),
        ROTATION_UNCONFIRMED: (
            "A rotation promoted a secret document and then read a different password "
            "back out of it. Every database took the new password and the promotion was "
            "acknowledged, so nothing needs undoing and `creds apply` converges what is "
            "left -- but until the vault serves what it accepted, an application fetching "
            "`current` may get the old password. Look at the vault, not at the databases; "
            "replication lag on a store with read replicas is the ordinary cause."
        ),
        LOCK_PATH_UNGUARDED: (
            "A lock path was created without `cas_required`, because this run's store "
            "credential may not write path metadata. The run's own lock was still taken "
            "under a compare-and-set and its fence held -- what is missing is the store "
            "refusing an un-CAS'd write from anybody else, an operator with a vault CLI "
            "included. Grant `update` on the mount's metadata path, or set it once by "
            "hand; the message names the path."
        ),
        REPAIR_DOCUMENT_STALE: (
            "The document `creds apply --repair` was given is old enough that the run it "
            "describes may not be the estate's current state. The run proceeds: the set "
            "can only narrow, and a pair since repaired costs one login and reports "
            "changed: false. The message names the age, because whether that is still "
            "the estate you are looking at is not something a threshold can decide."
        ),
        PASSWORD_CHANGE_DATE_UNKNOWN: (
            "The database would not say when this account's password was last set, so "
            "`password_age_days` is absent from the result and `creds status` shows `-` "
            "under DB_PW_CHANGED. The message says why -- a release with no such column "
            "and no grant to read it elsewhere, or a value that could not be read -- "
            "because those want different responses. Informational: nothing gates on the "
            "database's date, and `--max-age-days` reads the vault's."
        ),
        STORE_DEGRADED: (
            "A configured store answered and cannot serve this run: sealed, standing by, "
            "not yet initialised, or refusing the credential it was opened with. Distinct "
            "from a store that could not be reached, which fails the run instead -- here "
            "something answered, and what the reader does next is go and look at the vault "
            "rather than at the network."
        ),
        UNLISTABLE_STORE: (
            "A store in this survey has no `list` capability, so `lock status` reported "
            "only the paths this configuration declares. A lock record left at a path the "
            "file no longer names would not appear -- in that store. Everything reported "
            "is accurate; the survey is narrower than it looks."
        ),
        CONSTRAINTS_UNREAD: (
            "`creds generate` could not read a target's password constraints, so the "
            "policy's declared length governed the draw. The fallback is legitimate -- "
            "staging a password for an estate that is down is a thing operators do -- and "
            "the run staged one; what the code says is that the draw was never checked "
            "against a database. `--offline` emits nothing, because there the operator "
            "said so."
        ),
        VERIFY_FUNCTION_UNCHECKABLE: (
            "An account's profile names a password verify function, or whether it names "
            "one could not be established -- a common profile read from inside a PDB "
            "answers `FROM ROOT`. Reported and never acted on: the function is arbitrary "
            "PL/SQL that cannot be consulted before the statement is issued, so this is "
            "not a prediction that the password will be refused, and `creds apply` "
            "redraws if it is. It says that something other than the policy will judge "
            "this password."
        ),
        PASSWORD_REUSE_ENFORCED: (
            "An account's profile restricts password reuse, and this run was given a "
            "password rather than drawing one. Only `--from-stdin` produces it: fresh "
            "randomness cannot collide with a hashed history, and a supplied password is "
            "whatever an external system dictated. The two resource values are reported "
            "rather than interpreted -- they interact, and this run measured neither the "
            "interaction nor the history."
        ),
        LOW_ASSURANCE_ADMIN: (
            "A target's admin credential was read from an environment variable. P2 "
            "supports this source and requires it be flagged: a variable is readable by "
            "anything in the process's environment, survives in shell history and CI job "
            "definitions, and is not rotated by anything here. The run authenticated and "
            "the message names the variable, because what to do about it is to look at "
            "where that variable is set."
        ),
        NO_RESET_JOURNAL: (
            "`account list` reported an empty RESET_AT column because this configuration "
            "declares no `reset_records:` block, so there is no journal to read. The "
            "database's own password-change date is unaffected and is reported beside it. "
            "An estate that keeps no journal is a documented mode rather than a fault "
            "(UC-2 §3.4): what is owed is that the empty column says why, which is this."
        ),
        NO_RESET_RECORD: (
            "`account reset-password` wrote no record of the reset, because this "
            "configuration declares no `reset_records:` block -- so the run document and "
            "the database are the whole record of it, and no advisory lock was taken on "
            "the account either. Raised at plan time, before the password changes. An "
            "estate with no store is a documented mode rather than a fault (UC-2 §3.4): "
            "the seen path may have no store at all, and that is the site it exists for."
        ),
        RESET_RECORD_UNWRITTEN: (
            "The reset succeeded and its record could not be written. The password has "
            "changed and the person still needs it, so this is a warning on a successful "
            "run rather than a failure (UC-2 §3.4) -- but unlike an absent journal it is "
            "something to go and look at: a revoked token, a policy granting read and not "
            "write, or a store that is not reachable."
        ),
        NOTIFICATION_UNSENT: (
            "The password was delivered and the notification saying so could not be sent. "
            "The account and the target are both named, because a reset can notify once per "
            "target and two failures would otherwise be indistinguishable. "
            "A warning on a successful run for the same reason `SOPULI-W025` is, and more "
            "easily: the notification carries nothing anybody needs (UC-2 §6.1 keeps it to "
            '"a password is ready"), so what is lost is that somebody has to be told '
            "another way. A revoked webhook is the usual cause; the URL is not repeated in "
            "the message, because it is itself a credential."
        ),
        PROMOTION_WITHHELD: (
            "A secret document was not promoted because this run was narrowed past pairs "
            "the promotion needs: the same credential on a target outside the run, or a "
            "sibling account in the document with a `pending` of its own. The databases in "
            "scope were still changed. The run exits 4 like one whose targets failed, and "
            "the remedy differs: a wider run that covers the named pairs, not the same "
            "narrowed one again."
        ),
        ROLLBACK_REUSE_RESTRICTED: (
            "A rollback (`creds apply --source previous`) applied `previous` to an "
            "account whose profile restricts password reuse. `previous` is normally a "
            "password the account held one change ago, so the server is likely to refuse "
            "it with ORA-28007; where one limit is UNLIMITED and the other a number, a "
            "password the account has held is never accepted again. The two values are "
            "reported rather than interpreted, because the rule also counts changes made "
            "outside this tool. Raised whichever way the statement went. On such a "
            "profile the way back from a rotation is a rollover window "
            "(`PASSWORD_ROLLOVER_TIME`, UC-1 §6.3), not a rollback."
        ),
        PASSWORD_REDRAWN: (
            "The server refused a password the run applied -- `ORA-28003` or `ORA-28007` "
            "-- so the run drew another and staged it, to be applied again to every "
            "target of that account (UC-1 §6.4). One entry per draw, naming the account, "
            "the version staged and the server's message. It says a draw happened, not "
            "that the new password was accepted: the result rows say whether the "
            "re-apply succeeded, and `results[].redraws` counts the draws."
        ),
        PASSWORD_NOT_REDRAWN: (
            "The server refused a password the run applied, and the run was not allowed "
            "to draw another (UC-1 §6.4): nothing shows this tool drew the password, "
            "the redraw limit was reached, the account has no policy to draw from, or "
            "the run is a rollback. The message names which. The target that refused "
            "keeps the password it had; another target of the same account may already "
            "hold the refused value, and the result rows say which."
        ),
        CONNECTION_UNENCRYPTED: (
            "The run sent a new password over a connection that is not encrypted, so the "
            "password crossed the network in clear. One entry per target, naming what to "
            "do in the product's own words: for Oracle, require NNE or TLS on the server. "
            "The password was still set; this code warns and never refuses."
        ),
        CONNECTION_ENCRYPTION_UNKNOWN: (
            "The run sent a new password over a connection whose encryption could not be "
            "established, so the password may have crossed the network in clear. One "
            "entry per target, with the reason: for Oracle, usually that "
            "`V$SESSION_CONNECT_INFO` is not readable, and the message names the grant. "
            "It is not the same finding as `SOPULI-W031`."
        ),
        PROMOTION_FAILED: (
            "Every target of a secret document confirmed a password, and the write that "
            "promotes it to `current` failed. The databases have that password and "
            "`current` may still hold the one before it, which is UC-1 §8's most severe case. "
            "Only a refused compare-and-set says it does; a write that failed any other way "
            "may have landed. One "
            "entry per document, naming its path, its accounts and the store's message. A "
            "refused compare-and-set means another writer changed the document after this "
            "run read it, so the stage this run applied may have changed too. The remedy is "
            "the same run again, narrowed the same way: `creds apply` applies `pending` to "
            "every target and promotes it, and a failed rollback is repeated with "
            "`--source previous --confirm`. Where the run then lost its lock, the message "
            "names no re-run: the run holding the lock finishes it."
        ),
        UNREAD_POLICY_KEYS: (
            "Retired. Not emitted from 0.74.0, and no release emitted it: it was added "
            "after 0.73.0, and removed with a policy's `rotation:` and `verify:` blocks (#787). "
            "It said that a policy's `rotation:` or `verify:` block set keys that no run "
            "read."
        ),
        DELIVERY_UNSERVICEABLE: (
            "`delivery.method` names a method this build does not implement, so nothing "
            "can hand a password over that way. The file is valid: `config validate` warns "
            "and exits 0, and the verb that tries to deliver fails."
        ),
        NOTIFY_UNSERVICEABLE: (
            "`delivery.notify.method` names a channel this build cannot send through: it "
            "has no code for it, or its client is not installed. The message says which. "
            "`account reset-password` refuses before the password changes, rather than "
            "resetting without notifying."
        ),
        PROFILE_NAMED_AFTER_ENVIRONMENT: (
            "A profile has the name of an environment that a target declares. "
            "`--profile <name>` selects no targets: a profile changes how a run behaves, "
            "not what it acts on."
        ),
        THIRD_PARTY_VARIABLE_UNAPPLIED: (
            "A third-party store variable, such as `VAULT_ADDR`, is set and was not "
            "applied, because this run has no default store to apply it to: no layer "
            "names one, or the one named is not declared. The message says which. A "
            "warning and not a refusal, because the variable may belong to something else "
            "on this machine."
        ),
        RELAXATION_DEFEATED: (
            "A layer asked to relax a safety setting, and the ratchet held (invariant 10). "
            "The message names both ends: the layer that asked, and where the value that "
            "held is set. Nothing failed, and the run uses the safer value."
        ),
        ROTATION_OVERDUE: (
            "`creds status --max-age-days`: the vault last rotated this credential longer "
            "ago than the threshold. The age is the vault's, not the database's, which is "
            "`password_age_days`. One entry per result over the threshold."
        ),
        ADMITTED_VENDOR_ACCOUNT: (
            "`account list` admitted an account the database reports as its own, so a "
            "mutating verb refuses it at plan time (guardrail 2). A `role:` predicate can "
            "reach one, because creating a role grants it to the creator."
        ),
        ADMITTED_CROSS_DECLARED: (
            "`account list` admitted an account that an application also declares, so the "
            "whitelist is ambiguous about which guarantee applies (H1). Only a predicate can "
            "reach this: an enumerated name in both is refused when the file loads."
        ),
        ROLLOVER_LEFT_OPEN: (
            "`creds rotate --finish-rollover` left a rollover window open, because the vault "
            "may not serve the new password. Run `creds finish-rollover` once `current` holds "
            "it. The message names the accounts and targets."
        ),
        PRIVILEGE_AUDIT_UNREAD: (
            "The pre-flight could not read the privilege audit for a target, so it "
            "established nothing about the target's grants either way. The run was not "
            "refused over it. A finding of the `privileges` check."
        ),
        PROFILE_UNREAD: (
            "The pre-flight could not establish whether the profile an account would move to "
            "exists. The run was not refused over it, and the driver asks again before its "
            "own statement. A finding of the `profile` check."
        ),
        PENDING_REPLACED: (
            "`creds generate --overwrite-pending` replaced a `pending` password that was "
            "already staged. Anything holding the old one is now stale. The message names the "
            "document version replaced."
        ),
        CURRENT_REPLACED: (
            "`creds generate --promote --overwrite-current` replaced `current`. The vault now "
            "advertises a password no database has been given, until `creds apply` converges "
            "them."
        ),
        POLICY_VIOLATION_ACCEPTED: (
            "`creds generate --no-policy-check` accepted a password that violates the "
            "policy. One entry per rule violated, naming the rule and the counts, never the "
            "characters."
        ),
        CHANGED_NOT_PROMOTED: (
            "On one `creds apply` result: `current` may not hold the password this database "
            "has, so an application that fetches it may fail to log in. Either the database "
            "changed and did not confirm, and `creds apply` again once the target is well "
            "fixes it, or the promotion write failed, and SOPULI-W033 on the run says what "
            "to do. The message says which."
        ),
        PROMOTION_SKIPPED: (
            "A secret document was not promoted because a guardrail skipped one of its "
            "accounts on one target, and the run applied it on another. The guardrails "
            "read each database, so one account can hold `DBA` on one target only. The "
            "skipped target still holds the old password, so promoting would advertise a "
            "password it does not have. `pending` stays and the run exits 4. The same run "
            "again skips the same pair, so the run prints no `repair with:` line when this "
            "is all that held it back. The remedy is to clear what the guardrail reported "
            "on that target, or to run `creds apply --force` with `--account` naming every "
            "account in the document. The message spells that command out: a bare "
            "`--force` would waive the guardrails for every account in the estate, and "
            "naming fewer accounts narrows the run past a sibling's `pending`, which "
            "SOPULI-W027 then holds back."
        ),
        GUARDRAIL_UNCHECKED: (
            "One of `02-oracle-privileges.md` §4's account guardrails could not be run "
            "against a target, because the fact it checks could not be read. The run "
            "proceeded and the other checks were applied. Today this is always check 3, "
            "the password file: `V$PWFILE_USERS` is outside §2's grant set on purpose, so "
            "the code appears on a correctly installed estate and the optional grant is "
            "what removes it. It is reported rather than passed over silently because a "
            "check with no input reads exactly like a check that found nothing wrong."
        ),
    }
)


def constraint_diagnostics(found: Constraints, *, supplied: bool = False) -> list[Diagnostic]:
    """What `creds generate` says about what it read from the estate.

    Two kinds of thing, and they differ in a way the reader can act on:

    * the byte limit either governed the draw or did not, which is
      :data:`CONSTRAINTS_UNREAD` and is about *this run's password*;
    * a verify function and a reuse policy govern nothing here, and are reported
      because something other than the policy will judge the password later.

    ``supplied`` is whether the run was given a password rather than drawing one
    (``--from-stdin``), and it gates :data:`PASSWORD_REUSE_ENFORCED` alone. See
    that code: reuse cannot bite a fresh random draw, and a warning that fires on
    every run is one a reader learns to filter.

    Lives here rather than in :mod:`sopuli.cli` because this is where a domain
    object becomes a :class:`~sopuli.output.document.Diagnostic` -- the
    arrangement :func:`install_diagnostics` already has -- and because the
    grouping below is worth testing without a command-line runner.
    """
    return [*_unread(found), *_profile_notices(found, supplied=supplied)]


def _unread(found: Constraints) -> list[Diagnostic]:
    """Say which of §4's two answers governed the draw.

    Silence is the one thing not on offer. A password drawn against the policy
    alone and one drawn against a database that answered are different claims
    about the same run, and a reader cannot tell them apart from the password.

    Nothing is emitted where every target answered, because that is the case the
    feature exists to produce and a diagnostic on the happy path is noise a
    consumer learns to filter.
    """
    if found.source == POLICY:
        return [
            Diagnostic(
                level="warning",
                code=CONSTRAINTS_UNREAD,
                message=(
                    "no target could be reached to read password constraints, so the "
                    "policy's declared length governs: " + ", ".join(found.unreachable)
                ),
            )
        ]
    if found.partial:
        return [
            Diagnostic(
                level="warning",
                code=CONSTRAINTS_UNREAD,
                message=(
                    "password constraints were read from "
                    + ", ".join(found.read)
                    + " and could not be read from "
                    + ", ".join(found.unreachable)
                    + "; the limit used may not be the estate's strictest"
                ),
            )
        ]
    return []


def _profile_notices(found: Constraints, *, supplied: bool) -> list[Diagnostic]:
    """One entry per (target, profile), for the constraints nothing can check.

    **Grouped rather than per account**, because a verify function and a reuse
    policy are properties of the profile: an estate that puts forty accounts on
    one profile would otherwise be told the same fact forty times, and the
    per-account detail is in the document's ``constraints`` section for a
    consumer that wants it.

    An account whose profile could not be read at all contributes nothing here.
    That is the rule the accounts missing from
    :attr:`~sopuli.constraints.Constraints.accounts` are already covered by: this
    is a reporting path, and a sentence built out of a profile nobody read would
    be inventing the subject of its own warning.
    """
    groups: dict[tuple[str, str], list[AccountConstraints]] = {}
    for target, one in found.accounts:
        if one.profile is not None:
            groups.setdefault((target, one.profile), []).append(one)

    notices: list[Diagnostic] = []
    for (target, profile), group in groups.items():
        # Every account in a group shares a profile, so it shares the profile's
        # answers; only `versions` differs between them, and nothing here reads
        # it. The first is a representative rather than a sample.
        first = group[0]
        if first.verify_state == NAMED:
            notices.append(
                _notice(
                    VERIFY_FUNCTION_UNCHECKABLE,
                    target,
                    group,
                    f'profile "{profile}" names the verify function '
                    f"{first.verify_function}, which this run cannot evaluate: a "
                    f"password it accepts here may still be refused with ORA-28003 "
                    f"when it is applied",
                )
            )
        elif first.verify_state == UNKNOWN:
            notices.append(
                _notice(
                    VERIFY_FUNCTION_UNCHECKABLE,
                    target,
                    group,
                    f'profile "{profile}" answered FROM ROOT, which is what a common '
                    f"profile says from inside a PDB, so whether it names a verify "
                    f"function could not be established from this connection",
                )
            )
        if supplied and first.reuse_enforced:
            notices.append(
                _notice(
                    PASSWORD_REUSE_ENFORCED,
                    target,
                    group,
                    f'profile "{profile}" restricts password reuse '
                    f"(PASSWORD_REUSE_MAX {first.reuse_max}, PASSWORD_REUSE_TIME "
                    f"{first.reuse_time}); a supplied password the account has held "
                    f"before is refused with ORA-28007 when it is applied",
                )
            )
    return notices


def _notice(
    code: str, target: str, group: Sequence[AccountConstraints], message: str
) -> Diagnostic:
    """One grouped notice, carrying the account only where there is exactly one.

    ``account`` is a single value in the document, so a group of three cannot go
    in it -- and naming one of the three there would be worse than naming none.
    The message carries the list either way.
    """
    names = [one.account for one in group]
    return Diagnostic(
        level="warning",
        code=code,
        target=target,
        account=names[0] if len(names) == 1 else None,
        message=f"{target}: {message} ({_accounts(names)})",
    )


def _accounts(names: Sequence[str]) -> str:
    """The accounts a grouped notice covers, named while naming them is useful.

    Past three the list stops being something a reader scans and starts being
    something they scroll, and the ``constraints`` section has all of them.
    """
    if len(names) > 3:
        return f"{len(names)} accounts"
    return ", ".join(names)


#: What to do about a guardrail that could not be run, by check.
#:
#: Here rather than on :class:`~sopuli.driver.guardrails.Caveat`, because a
#: remedy is a grant on one product and the guardrails are product-neutral by
#: design -- ``guardrails.py`` states the rule and the driver supplies the facts,
#: and a `GRANT` statement is a fact. This module is already the boundary where a
#: domain object becomes something an operator reads, and it is already Oracle-
#: aware; a caveat with no entry here is reported without a remedy rather than
#: not reported.
GUARDRAIL_REMEDIES: Mapping[str, str] = MappingProxyType(
    {
        PASSWORD_FILE: "GRANT SELECT ON SYS.V_$PWFILE_USERS to the service account to enable it",
    }
)


def guardrail_diagnostics(caveats: Sequence[tuple[str, Caveat]]) -> list[Diagnostic]:
    """§4's checks that could not be run, as the warnings a consumer reads.

    ``caveats`` is (target, caveat) pairs, in the order the run produced them --
    the target is the command's to know and the caveat is the guardrail's, which
    is why neither type carries both.

    **One entry per (target, check)**, on
    :data:`VERIFY_FUNCTION_UNCHECKABLE`'s reasoning: what could not be read is a
    grant on a database, so an estate with forty accounts on one target would
    otherwise be told the same fact forty times. The accounts are named in the
    message while naming them is useful, by :func:`_accounts`' rule.

    The caller passes only the accounts the run **acted on** -- an account the
    guardrails already turned away was not touched, so what an unread check might
    have said about it changed nothing. This function does not enforce that and
    could not: which accounts a run acted on is the command's knowledge, and the
    rule is written where the pairs are built.
    """
    grouped: dict[tuple[str, str], list[Caveat]] = {}
    for target, caveat in caveats:
        grouped.setdefault((target, caveat.check), []).append(caveat)

    notices: list[Diagnostic] = []
    for (target, check), group in grouped.items():
        names = [one.account for one in group]
        remedy = GUARDRAIL_REMEDIES.get(check)
        reason = group[0].reason
        notices.append(
            Diagnostic(
                level="warning",
                code=GUARDRAIL_UNCHECKED,
                target=target,
                account=names[0] if len(names) == 1 else None,
                message=(
                    f"{target}: guardrail check `{check}` did not run: {reason}"
                    + (f" -- {remedy}" if remedy else "")
                    + f" ({_accounts(names)})"
                ),
            )
        )
    return notices


def worse_encryption(kept: Encryption | None, found: Encryption | None) -> Encryption | None:
    """The less safe of two answers about the connections one password went over.

    ``none``, then ``unknown``, then anything encrypted. A password known to have
    crossed in clear is the finding, whatever another session could not tell.
    ``None`` means no password was sent, and loses to any answer.
    """
    rank = {ENCRYPTION_NONE: 2, ENCRYPTION_UNKNOWN_METHOD: 1}
    if kept is None:
        return found
    if found is None:
        return kept
    return found if rank.get(found.method, 0) > rank.get(kept.method, 0) else kept


def encryption_diagnostics(sent: Sequence[tuple[str, Encryption]]) -> list[Diagnostic]:
    """A password sent over an unencrypted or unknown connection, once per target.

    ``sent`` is (target, encryption) pairs for the connections a password was
    actually sent over. A target the run read and changed nothing on is not
    passed: a warning about a statement nobody sent is noise (decision #568's
    reasoning). The driver's ``hint`` says what to do.

    A target can appear with more than one answer, because each pass of
    `creds apply`'s redraw opens its own connection, which reads its own. The
    worst answer is kept (:func:`worse_encryption`).
    """
    worst: dict[str, Encryption | None] = {}
    for target, answer in sent:
        worst[target] = worse_encryption(worst.get(target), answer)
    notices: list[Diagnostic] = []
    for target, found in worst.items():
        if found is None:
            continue
        if found.method == ENCRYPTION_NONE:
            code = CONNECTION_UNENCRYPTED
            headline = "a password was sent over a connection that is not encrypted"
        elif found.method == ENCRYPTION_UNKNOWN_METHOD:
            code = CONNECTION_ENCRYPTION_UNKNOWN
            headline = "a password was sent over a connection whose encryption is not known"
        else:
            continue
        notices.append(
            Diagnostic(
                level="warning",
                code=code,
                target=target,
                message=f"{target}: {headline}" + (f": {found.hint}" if found.hint else ""),
            )
        )
    return notices


def rollback_reuse(readings: Sequence[tuple[str, UserState]]) -> list[Diagnostic]:
    """A rollback against a profile that restricts reuse, as a warning.

    ``readings`` is (target, account state) pairs for the rollbacks that reached
    the statement, in the order the run produced them. The caller passes only
    those whose profile restricts reuse -- :func:`~sopuli.constraints.reuse_restricted`
    is the test -- because which pairs were rollbacks is the command's knowledge.

    **One entry per (target, profile)**, on :func:`_profile_notices`' reasoning:
    the limits belong to the profile, so forty accounts on ADB's ``DEFAULT``
    would otherwise be told the same thing forty times.
    """
    grouped: dict[tuple[str, str], list[UserState]] = {}
    for target, state in readings:
        grouped.setdefault((target, state.profile or ""), []).append(state)

    notices: list[Diagnostic] = []
    for (target, profile), group in grouped.items():
        names = [one.name for one in group]
        first = group[0]
        notices.append(
            Diagnostic(
                level="warning",
                code=ROLLBACK_REUSE_RESTRICTED,
                target=target,
                account=names[0] if len(names) == 1 else None,
                message=(
                    f'{target}: profile "{profile}" restricts password reuse '
                    f"(PASSWORD_REUSE_MAX {first.password_reuse_max}, PASSWORD_REUSE_TIME "
                    f"{first.password_reuse_time}), and a rollback applies a password the "
                    f"account has normally held before, so ORA-28007 is likely; on this "
                    f"profile the way back from a rotation is the rollover window a "
                    f"PASSWORD_ROLLOVER_TIME opens, not a rollback ({_accounts(names)})"
                ),
            )
        )
    return notices


def admin_diagnostics(target: str, credential: Resolved) -> list[Diagnostic]:
    """What a run says about where a target's admin credential came from.

    Empty for every source but the low-assurance one, which is the whole design
    of a warning somebody is meant to keep reading. `external`, `vault` and
    `prompt` are the sources P2 prefers, and a diagnostic on each of them would
    put a line on every run of every command -- at which point the one that
    matters is indistinguishable from the three that do not.

    **The decision is** :attr:`~sopuli.admin.Resolved.low_assurance`**'s, not
    this function's.** That property asks whether the method is in
    :data:`~sopuli.admin.LOW_ASSURANCE` rather than whether it is ``env``, so a
    second such source is flagged by adding it to that set -- and this stays the
    site that says what a flagged source *looks like* in a document, which is
    the split :class:`~sopuli.admin.Resolved`'s docstring asks for: it
    classifies and does not decide, and the command that connects is the one
    that reports.

    Here rather than in :mod:`sopuli.cli` for :func:`constraint_diagnostics`'
    reason -- this is where a domain object becomes a
    :class:`~sopuli.output.document.Diagnostic` -- and because a rule about what
    a run must say is worth testing without a command-line runner.
    """
    if not credential.low_assurance:
        return []
    return [
        Diagnostic(
            level="warning",
            code=LOW_ASSURANCE_ADMIN,
            target=target,
            message=(
                f"{target}: the admin credential came from {credential.source}, "
                f"which P2 supports and flags as low assurance"
            ),
        )
    ]


def unlistable_stores(names: Sequence[str]) -> list[Diagnostic]:
    """Say that part of the survey could not be looked at.

    A **warning and not a refusal**, which is P2's third answer to a missing
    capability and the reason `list` needed one: refusing would make `lock
    status` a command that works on some backends and not others, and an operator
    with one such store would lose the report for every other store as well.

    But it cannot be silent either, and that is the whole point of emitting it.
    An empty `found[]` is something a consumer acts on -- it concludes there are
    no leftover locks -- and that conclusion has to be earned by having looked.
    A survey that could not look at one store and said nothing would be handing
    back the same document as a clean estate.

    One entry naming every such store rather than one each: the operator's
    question is "how much of this did you actually see", which is one question
    however many stores answer it.
    """
    if not names:
        return []
    return [
        Diagnostic(
            level="warning",
            code=UNLISTABLE_STORE,
            message=(
                f"could not list {_names(sorted(names))}: this survey covers the lock "
                f"paths this configuration declares, and a record left at a path it no "
                f"longer names would not appear"
            ),
        )
    ]


def no_reset_journal() -> list[Diagnostic]:
    """Say why `account list`'s ``RESET_AT`` column is empty (UC-2 §3.4).

    One entry for the run rather than one per account, because the cause is the
    *configuration* and is identical on every row -- the same reasoning
    :data:`LOW_ASSURANCE_ADMIN` follows, and the opposite of
    :data:`PASSWORD_CHANGE_DATE_UNKNOWN`, which is per result because *that*
    absence is per account: one release, one grant, but a date that may be
    readable for one person and not another.

    A warning and never a refusal. An estate that keeps no journal is a
    documented mode (§3.1), and a listing verb that refused to describe an estate
    because it keeps no history would have its priorities backwards.
    """
    return [
        Diagnostic(
            level="warning",
            code=NO_RESET_JOURNAL,
            message=(
                "no `reset_records:` block is declared, so there is no reset journal to "
                "read and RESET_AT is empty for every account; the database's own "
                "password-change date is unaffected and is reported beside it"
            ),
        )
    ]


def no_reset_record() -> Diagnostic:
    """Say that this reset is going unrecorded, before it happens.

    §3.4's first absence, raised at **plan time** rather than with the result:
    an operator who did not mean to run without a journal should find out while
    the password is still the one the person has.

    One entry for the run, like :func:`no_reset_journal`, because the cause is
    the configuration rather than the account -- and this verb resets one account
    anyway, which is §2's rule for a mutating verb.

    It names the lock as well as the record. Where there is no store there is no
    lock (§3.3), and an operator told only that history is missing would not
    learn that two concurrent resets of the same account are not serialised.
    """
    return Diagnostic(
        level="warning",
        code=NO_RESET_RECORD,
        message=(
            "no `reset_records:` block is declared, so no record of this reset will be "
            "written and no advisory lock is taken on the account: the run document and "
            "the database are the whole record of it"
        ),
    )


def notification_unsent(account: str, target: str, reason: str) -> Diagnostic:
    """The password is waiting and the channel did not say so.

    The reason last, and verbatim, for :func:`reset_record_unwritten`'s reason: a
    refused POST and an unreachable host send somebody to different places, and
    only the channel's own words distinguish them.

    **The account and the target are named, and the URL is not.** A chat
    incoming-webhook URL is a credential (C9), so repeating it in a warning would
    put one wherever warnings go -- which on this verb includes a run document.

    **The target is named because one reset can notify more than once.** A personal
    account is reset on one account and possibly several targets, so a
    notification is attempted per target. A warning that carried only the account
    would repeat itself when two of three targets fail, and no operator could act
    on it.

    The remedy is in the message rather than in a ``hint``, because
    :class:`~sopuli.output.document.Diagnostic` has no hint field: a diagnostic is
    one sentence in ``diagnostics[]`` and the registry in ``03-json-output.md`` §3
    is where the longer explanation lives.
    """
    return Diagnostic(
        level="warning",
        code=NOTIFICATION_UNSENT,
        message=(
            f"the password for {account} on {target} was delivered and the notification "
            f"could not be sent, so nobody has been told it is waiting -- tell them another "
            f"way today and look at `delivery.notify.webhook.url` afterwards: {reason}"
        ),
    )


def promotion_withheld(document: str, pairs: Sequence[tuple[str, str]]) -> Diagnostic:
    """One document this run may not promote, and the pairs that would let it.

    ``pairs`` is (account, target), and every one is named rather than counted:
    what the reader does next is widen the run until it covers them, and "3
    pairs" does not say which way to widen it.
    """
    named = ", ".join(f"{account} on {target}" for account, target in pairs)
    return Diagnostic(
        level="warning",
        code=PROMOTION_WITHHELD,
        message=(
            f"{document} cannot be promoted by this run: the promotion also needs {named}, "
            "which this run's selection left out -- run `creds apply` without the narrowing "
            "to finish"
        ),
    )


def promotion_skipped(
    document: str, pairs: Sequence[tuple[str, str]], accounts: Sequence[str]
) -> Diagnostic:
    """One document a guardrail skip held back (#852), and the pairs it skipped.

    ``pairs`` is (account, target), named for :func:`promotion_withheld`'s reason:
    the reader goes to each of those targets next.

    ``accounts`` is every account in the document, and the `--force` remedy names
    them all. A bare `--force` would waive the guardrails for every account in the
    estate, and naming fewer would narrow the run past a sibling's `pending`,
    which `SOPULI-W027` then holds back.
    """
    named = "; ".join(f"{account} on {target}" for account, target in pairs)
    targets = "that target still holds" if len(pairs) == 1 else "those targets still hold"
    force = " ".join(f"--account {account}" for account in accounts)
    return Diagnostic(
        level="warning",
        code=PROMOTION_SKIPPED,
        message=(
            f"{document} was not promoted: a guardrail skipped {named}, and {targets} the "
            "old password -- clear what the guardrail reported and run `creds apply` again, "
            f"or, if changing it is intended, run `creds apply --force {force}`"
        ),
    )


def promotion_failed(
    document: str,
    accounts: Sequence[str],
    reason: str,
    *,
    conflict: bool,
    rollback: bool,
    rerun: str | None,
) -> Diagnostic:
    """One document whose promotion write failed after every target confirmed.

    ``conflict`` is whether the store refused the compare-and-set. That case
    says another writer changed the document, and the stage this run applied
    may no longer hold what it applied. So the message says to look at the
    document before running `apply` again.

    ``rollback`` is whether the write promoted `previous` (`--source previous`).
    It changes which stage the message names.

    ``rerun`` is the invocation that finishes the job, from
    :func:`sopuli.output.apply_view.repair_invocation`, so it is narrowed and
    resolved the way this run was, and a rollback is repeated as a rollback.
    ``None`` where the run lost its lock afterwards (``SOPULI-W011``): running
    again is then the one thing not to do, and the run holding the lock is the
    one to finish it.

    The store's message comes last, for :func:`reset_record_unwritten`'s reason.
    """
    stage = "previous" if rollback else "pending"
    # Only a refused compare-and-set says what the vault holds. Any other failure,
    # such as a timeout or a lost reply, may follow a write the vault committed.
    if conflict:
        cause = (
            "another writer changed the document after this run read it, so the vault "
            "refused the compare-and-set"
        )
        state = "still holds the password they had before"
    else:
        cause = "the write failed, so this run cannot say whether the vault kept it"
        state = "may still hold the password they had before"
    if rerun is None:
        remedy = "another run then took over this run's lock, and that run is the one to finish it"
    else:
        check = f"find out who wrote to it and what `{stage}` now holds, then " if conflict else ""
        remedy = (
            f"{check}run `{rerun}`, which applies `{stage}` to every target again and promotes it"
        )
    return Diagnostic(
        level="error",
        code=PROMOTION_FAILED,
        message=(
            f"{document} was not promoted: {cause}. The databases have `{stage}` for "
            f"{', '.join(accounts)} and `current` {state} -- {remedy}. "
            f"The store said: {reason}"
        ),
    )


def reset_record_unwritten(path: str, reason: str) -> Diagnostic:
    """The reset happened and the journal did not hear about it.

    §3.4's second absence. **A warning on a successful run** -- the password has
    changed and the person still needs it, so failing here would report a false
    negative about the part that mattered.

    The reason is carried verbatim, and **last**, because it is the whole value
    of the warning: "could not be written" sends somebody to look at a store, and
    "403 at sopuli/personal-resets/..." sends them to a policy. Last because a
    store's own message ends in its own punctuation, and anything appended after
    it reads as a fragment of it.
    """
    return Diagnostic(
        level="warning",
        code=RESET_RECORD_UNWRITTEN,
        message=(
            f"the password was reset and its record at {path} could not be written, so "
            f"the run document and the database are the whole record of it: {reason}"
        ),
    )


def lock_diagnostics(manager: LockManager) -> list[Diagnostic]:
    """What a run should say about the locks it took.

    All three warnings describe something that *worked*, which is why they are
    warnings and not errors: the run holds its locks, and it holds them on terms
    the operator should be able to see afterwards without going and reading the
    config file or the vault.
    """
    return [
        *_advisory(manager.stores),
        *(_unguarded(one) for one in manager.unguarded),
        *(_taken_over(one.key, one.broke) for one in manager.held if one.broke is not None),
    ]


def _unguarded(one: Unguarded) -> Diagnostic:
    """A lock path created without ``cas_required``, because the store said no.

    One per path rather than one per store, which is the opposite of
    :func:`_advisory` and for the opposite reason: advisory locking is a property
    of the store and is the same fact however many locks are held on it, while
    this is a property of one path and the remedy names that path. A run that
    creates three new paths under a token with no metadata write has three
    things to go and fix.

    It is only ever emitted by the run that *creates* the path, so it does not
    repeat: the next run finds metadata, finds ``cas_required`` unset, and is
    refused by pre-flight instead. That asymmetry is deliberate -- the first run
    could not have known, and every one after it is looking at a condition
    somebody has now been told about.
    """
    return Diagnostic(
        level="warning",
        code=LOCK_PATH_UNGUARDED,
        message=(
            f"the lock path for {one.key} is not guarded against a write carrying no "
            f"compare-and-set: {one.reason}"
        ),
    )


def _advisory(stores: Mapping[str, LockableStore]) -> list[Diagnostic]:
    """One warning naming every store that cannot fence.

    One entry rather than one per lock: the weakening is a property of the store,
    and a run holding eleven locks in one advisory store would otherwise say the
    same thing eleven times.
    """
    unfenced = sorted(name for name, entry in stores.items() if not entry.can_fence)
    if not unfenced:
        return []
    return [
        Diagnostic(
            level="warning",
            code=ADVISORY_LOCKING,
            message=(
                f"locking is advisory-only on {_names(unfenced)}: the lock record was "
                f"written without compare-and-set, so two runs in the same second can "
                f"both hold it"
            ),
        )
    ]


def _taken_over(key: LockKey, broke: LockRecord) -> Diagnostic:
    """Somebody's lock was taken by a run that wanted it. Said out loud.

    The evidence is gone from the path the moment the takeover write lands, so if
    this run does not report it, nothing ever does.
    """
    holder = broke.holder
    who = "an unknown holder" if holder is None else f"{holder.os_user}@{holder.host}"
    return Diagnostic(
        level="warning",
        code=LOCK_TAKEN_OVER,
        message=(
            f"took over the expired lock on {key}, held by {who} "
            f"since {to_rfc3339(broke.acquired_at)}"
        ),
    )


def lock_broken(key: LockKey, broke: LockRecord, *, expired: bool) -> list[Diagnostic]:
    """Somebody's lock was taken by a person who asked for it.

    The same code as :func:`_taken_over` and a different sentence, which is the
    arrangement §3 already describes: the code is the contract and the wording
    around it is not. Saying "took over the expired lock" here would be wrong
    half the time -- ``lock break --force`` takes a lock that is still live, and
    that is the case somebody reading the audit trail most needs to see named.

    A **warning** rather than an error, for the reason both of this module's lock
    warnings are: nothing failed. The run did exactly what it was asked, and what
    the operator should be able to see afterwards -- without going and reading
    the vault -- is whose claim it ended.

    A list, so that a caller with nothing to report drops it in the same way it
    drops :func:`unlistable_stores`.
    """
    holder = broke.holder
    who = "an unknown holder" if holder is None else f"{holder.os_user}@{holder.host}"
    claim = "expired" if expired else "live"
    return [
        Diagnostic(
            level="warning",
            code=LOCK_TAKEN_OVER,
            message=(
                f"broke the {claim} lock on {key}, held by {who} "
                f"since {to_rfc3339(broke.acquired_at)}; they are fenced and stop at "
                f"their next check"
            ),
        )
    ]


def _names(names: Sequence[str]) -> str:
    quoted = [f"{name!r}" for name in names]
    if len(quoted) == 1:
        return f"store {quoted[0]}"
    return "stores " + ", ".join(quoted)


def install_diagnostics(
    shape: InstallShape, *, level: DiagnosticLevel = "error"
) -> list[Diagnostic]:
    """What a command says about a configured component this machine cannot serve.

    **The only definition of that fact in the tool.** `doctor` reports it as an
    error and exits 9 (E6); `config validate` reports the same finding as a
    warning and exits 0 (E4). Those are the two commands' own judgements of what
    it is worth, and it is deliberate that they differ -- but *what happened* is
    one thing, and one function computes it.

    A check that asked only whether the *client* was installed would leave
    `config validate` silent about a backend this build has no module for, and
    which backends it reported would depend on the machine rather than on the
    file.

    ``level`` is the caller's, and it is the *only* thing the caller decides.
    With one function answering "is this component missing" there is nothing
    left to disagree about. It is a :data:`~sopuli.output.document.DiagnosticLevel` and
    not a ``str``, so a typo here is a type error rather than a document that
    fails the schema at the end of a run; there is deliberately no runtime check.

    **Derived from the survey rather than computed a second time.** "Missing" has
    to mean the same thing in `doctor`'s ``install`` section and in the
    ``diagnostics`` array of the same document, and it did not when the two were
    worked out separately: the section asks whether this build has a module *and*
    whether the client is there, and a check of the client alone would disagree.
    On a machine with the `oci` SDK installed and no `oci` backend written, it
    would give an exit 9 with no diagnostic at all -- and with the SDK absent it
    would contradict the section and point at a `pip` line that fixes nothing.

    **The install line comes from the component**, so it appears only where one
    exists. That is structural rather than remembered: a
    :class:`~sopuli.install_shape.Component` carries an ``install_command`` only
    when its status is ``not_installed``, so there is no path here that can tell
    somebody to `pip install` a backend nobody has written.
    """
    found = []
    for component in shape.backends:
        if component.status == INSTALLED:
            continue
        for name in component.configured:
            found.append(
                Diagnostic(
                    level=level,
                    code=MISSING_BACKEND,
                    message=(
                        f'vault "{name}" declares type "{component.name}", '
                        f"{_cannot_serve(component.name, 'backend', component.install_command)}"
                    ),
                )
            )
    for component in shape.drivers:
        if component.status == INSTALLED or not component.configured:
            continue
        # One per driver *type*, counted, exactly as `driver_diagnostics` does
        # and for the same reason: twenty-one PDBs from one `target_sets:` entry
        # would otherwise be twenty-one identical lines about one command.
        names = component.configured
        if len(names) > 1:
            subject = f'{len(names)} targets, including "{names[0]}", declare'
        else:
            subject = f'target "{names[0]}" declares'
        found.append(
            Diagnostic(
                level=level,
                code=MISSING_DRIVER,
                message=(
                    f'{subject} type "{component.name}", '
                    f"{_cannot_serve(component.name, 'driver', component.install_command)}"
                ),
            )
        )
    return found


def _cannot_serve(name: str, kind: str, install_command: str | None) -> str:
    """Why this machine cannot serve it, and what -- if anything -- to do.

    The two halves are different sentences because they are different problems,
    which is the distinction :class:`~sopuli.store.registry.BackendNotInstalledError`
    and :class:`~sopuli.store.registry.BackendNotImplementedError` already draw.
    Only one of them ends in something the reader can run, and offering an
    install command for the other is the expensive mistake: it sends somebody to
    `pip` forever for something `pip` cannot supply.

    Takes the three pieces rather than a
    :class:`~sopuli.install_shape.Component` because the subject of the sentence
    differs -- a store is named by its ``vaults:`` key and a driver type is
    counted across the targets that declare it -- while this half is the same
    fact for both. ``install_command`` being ``None`` is what selects the second
    reading, and it comes from one place: a
    :class:`~sopuli.install_shape.Component` carries one only when its status is
    :data:`~sopuli.install_shape.NOT_INSTALLED`.
    """
    if install_command is not None:
        return f"but that {kind} is not installed; install it with: {install_command}"
    return f"but this build has no {name} {kind} yet -- this is not something to install"


def wallet_diagnostics(report: WalletReport) -> list[Diagnostic]:
    """What a run should say about the wallet it will authenticate with.

    **Warnings, never a verdict.** `01-configuration.md` §3a makes the config
    rules around ``external`` load-time errors; this is a runtime report and must
    not re-litigate them. What happens to the run is decided a moment later by
    each target's own connection attempt, and if the wallet is the reason, this
    is the entry that says so before the Oracle error that will not.

    Two codes and not one, because they are opposite conditions with opposite
    remedies: :data:`WALLET_UNUSABLE` says the credential is not there, and
    :data:`WALLET_NOT_PRIVATE` says it is there and other people can have it. A
    consumer alerting on the second is doing security monitoring; one alerting on
    the first is watching an outage.

    The unusable case is **one entry naming every target that needs it**, not one
    per target: there is one wallet per run, and an estate with twenty external
    targets would otherwise say the same sentence twenty times about the same
    directory.
    """
    found = []
    if not report.usable:
        found.append(
            Diagnostic(
                level="warning",
                code=WALLET_UNUSABLE,
                message=(
                    f"{_needs_wallet(report.required_by)} external authentication, "
                    f"and {_why_unusable(report)}"
                ),
            )
        )
    for name, reason in report.insecure:
        found.append(
            Diagnostic(
                level="warning",
                code=WALLET_NOT_PRIVATE,
                message=(
                    f"{name} in {report.directory} {reason}; an auto-login wallet is a "
                    f"credential, and whoever can read it can authenticate as the account "
                    f"it holds"
                ),
            )
        )
    return found


def _needs_wallet(names: Sequence[str]) -> str:
    """The subject of the sentence, carrying its own verb.

    The verb has to travel with the subject rather than sit in the f-string that
    joins them, because the subject is singular or plural depending on the estate
    -- and "20 targets ... uses external authentication" is the kind of seam that
    makes a reader doubt the rest of the report.
    """
    if len(names) == 1:
        return f"target {names[0]!r} uses"
    return f"{len(names)} targets, including {names[0]!r}, use"


def _why_unusable(report: WalletReport) -> str:
    """The half of the message that names the remedy.

    Three different problems, and telling somebody to check permissions on a
    directory that does not exist -- or to set a variable that is already set --
    is the failure this exists to avoid.
    """
    if report.directory is None:
        return "$TNS_ADMIN is unset, so there is nowhere to read a wallet from"
    if not report.readable:
        return f"{report.directory} is missing or not readable by this user"
    if AUTO_LOGIN in report.unreadable:
        return (
            f"{report.directory} holds {AUTO_LOGIN} and this process cannot read it -- "
            f"check who owns it, and which account this is running as"
        )
    if report.files or report.unreadable:
        present = ", ".join(sorted({*report.files, *report.unreadable}))
        return (
            f"{report.directory} holds {present} but no readable {AUTO_LOGIN}, "
            f"and an encrypted wallet needs a passphrase this tool cannot supply"
        )
    return f"{report.directory} holds no wallet"


def vault_diagnostics(reports: Sequence[VaultReport]) -> list[Diagnostic]:
    """What a run should say about the stores it surveyed (P4).

    **Only what the exit code cannot say.** An *unreachable* store deliberately
    gets no diagnostic: it fails the run at exit 1, so anything watching the exit
    code already knows, and the ``vaults[]`` entry names which store and carries
    the error -- exactly the arrangement ``targets[]`` has, where
    an unreachable database is an entry and never a diagnostic. Adding one here
    would report a single condition twice and make the two able to disagree.

    What is left is the pair of findings that leave a run exiting 0 with
    something still wrong, and those are what :func:`Diagnostic` exists for:

    * a store that answered and cannot serve -- sealed, standing by, or refusing
      this run's credential;
    * a clock further from a store's than the lock tolerates.

    One entry per store rather than one naming all of them, unlike
    :func:`unlistable_stores`: the operator's unit of action is a vault -- one to
    unseal, one host's NTP to fix -- and two stores in one sentence is a line
    somebody has to take apart before they can act on either half.
    """
    found = []
    for report in reports:
        if report.reachable and report.health.status != OK:
            found.append(
                Diagnostic(
                    level="warning",
                    code=STORE_DEGRADED,
                    message=(
                        f'vault "{report.name}" answered and cannot serve this run: '
                        f"{report.health.detail or 'it did not say why'}"
                    ),
                )
            )
    for report in reports:
        if report.skew is not None and report.skew.beyond_tolerance:
            found.append(
                Diagnostic(
                    level="warning",
                    code=CLOCK_SKEW_BEYOND_TOLERANCE,
                    message=(
                        f"this host's clock is {_gap(report.skew)} the clock of vault "
                        f'"{report.name}", further than the '
                        f"{_seconds(report.skew.tolerance)} the lock allows: a lease's "
                        f"expiry is judged against the local clock, so leases here will be "
                        f"taken over early or held past their end"
                    ),
                )
            )
    return found


def _gap(skew: Skew) -> str:
    """How far out and which way, in words rather than a sign.

    A reader who has to remember whether positive means the store is ahead will
    remember it wrongly half the time, and the two directions are different
    failures: a host behind the store refuses leases that have really expired,
    and one ahead takes over leases that are still live.
    """
    behind = skew.delta > timedelta(0)
    return f"{_seconds(abs(skew.delta))} {'behind' if behind else 'ahead of'}"


def _seconds(value: timedelta) -> str:
    """A duration as an operator would say it, not as `timedelta` prints it.

    `str(timedelta(seconds=90))` is ``0:01:30``, which in the middle of a
    sentence about clocks reads as a time of day.
    """
    total = value.total_seconds()
    if total < 1:
        return f"{round(total * 1000)}ms"
    return f"{total:.0f}s" if total == int(total) else f"{total:.1f}s"
