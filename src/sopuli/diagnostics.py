"""Warnings that carry a code, and the registry of what each code means.

J3 asks for stable machine-readable codes so that consumers branch on a code
rather than grepping a message, and says they get a documented registry. This is
that registry, opened by the first warning that needed one: #83 requires the
``advisory-only`` weakening to appear in **every run's** output rather than only
in the config file, which is only useful if a consumer can recognise it.

**J3 itself stays open**, and the way this registry has grown is the evidence.
What is decided is the spelling ``SOPULI-Wnnn``, which `03-json-output.md`
already used as its example, and that these ten warnings have codes: the two the
advisory lock needed (#83), a configured-but-uninstalled backend (#130), a store
that does not verify its certificate (#135), a store that could not be listed
(#150), an uninstalled driver (#170), the wallet pair (#215), and the vault
survey's pair (#216). Every one was allocated by hand, at the moment something
needed it.

Whether *every* warning gets one -- the config layer's §10 findings still do not
-- and how numbers are allocated across categories is the part of J3 nobody has
answered, and ten hand-picked numbers answer it no better than two did.

What #216 did settle, narrowly and only for `doctor`, is **when a finding gets a
diagnostic at all**: one for what the exit code cannot tell you. An unreachable
store fails the run, so anything watching the exit code already knows and the
entry in ``vaults[]`` names it -- exactly as an unreachable *target* has been an
entry and never a diagnostic since #212. A store that answered and cannot serve,
or a clock outside the lock's tolerance, leaves the run exiting 0 with something
still wrong, and that is what a diagnostic is for.

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

from sopuli.clock import Skew, to_rfc3339
from sopuli.config.references import UNVERIFIED_TRANSPORT
from sopuli.driver.oracle.wallet import AUTO_LOGIN, WalletReport
from sopuli.install_shape import INSTALLED, InstallShape
from sopuli.lock.keys import LockKey
from sopuli.lock.manager import LockableStore, LockManager
from sopuli.lock.record import LockRecord
from sopuli.output.document import Diagnostic, DiagnosticLevel
from sopuli.store.protocol import OK
from sopuli.store.survey import VaultReport

#: A store is holding locks it cannot guard (``locking: advisory-only``, #94).
ADVISORY_LOCKING = "SOPULI-W001"

#: A lock was taken from whoever held it -- automatically, because it was past
#: its expiry and ``locking.break_expired`` permits that, or deliberately by
#: ``sopuli lock break`` (#149). One code, because it is one event: what differs
#: is whether a config key or a person decided it, and a consumer alerting on
#: "somebody's lock was taken" wants both.
LOCK_TAKEN_OVER = "SOPULI-W002"

#: A ``vaults:`` entry names a backend **this machine cannot serve** (#130,
#: #238) -- its client is not installed, or this build has no module for it.
#: One code for both, because they are one outage and differ only in the
#: remedy, which the message carries; splitting them would make a consumer
#: alerting on an unusable store subscribe to two.
MISSING_BACKEND = "SOPULI-W003"

#: A store in the survey has no ``list`` capability, so the report covers only
#: the paths the configuration declares (#150).
UNLISTABLE_STORE = "SOPULI-W005"

#: A ``targets:`` entry names a driver this machine cannot serve (#170), read
#: as widely as :data:`MISSING_BACKEND` is.
#: Its own code rather than a widening of :data:`MISSING_BACKEND`, whose
#: registered description names a ``vaults:`` entry: one code meaning "some
#: backend or other is missing" would leave a consumer unable to tell a store it
#: cannot reach from a database it cannot reach, which are different outages.
#: Hand-allocated, like #130's pair, and J3 is still open.
MISSING_DRIVER = "SOPULI-W006"

#: An account's password is in its grace period: past ``PASSWORD_LIFE_TIME`` and
#: inside the window ``PASSWORD_GRACE_TIME`` grants (#309, UC-1 §6.4).
#:
#: **A warning beside a state, never a state.** The account may be `IN_SYNC` or
#: it may have drifted, and ``state`` is one field -- a value of its own here
#: would have to displace one of those answers, and either choice hides the thing
#: the reader came for. Riding alongside is what lets a run say *drifted, and
#: expiring on Friday*, which is the report worth paging on.
PASSWORD_GRACE_PERIOD = "SOPULI-W013"

#: A login **succeeded** and the server attached a diagnostic to it (#322).
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
#: policy's declared length governed the draw (#317, UC-1 §4 step 2).
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

#: An estate uses ``auth: external`` and this machine has no wallet it can read
#: (#215). Its own code rather than a widening of anything above: the remedy is a
#: file on this machine, and a consumer that alerts on "sopuli cannot reach a
#: store" is watching a different outage from one that alerts on "the wallet the
#: service account authenticates with has gone".
WALLET_UNUSABLE = "SOPULI-W007"

#: A wallet file somebody other than its owner can reach (#215, P4). Separate
#: from :data:`WALLET_UNUSABLE` because the two are opposite conditions -- one
#: says the credential is not there, the other says it is there and everyone can
#: have it -- and because only the second is something to alert on rather than to
#: fix while you are already looking.
WALLET_NOT_PRIVATE = "SOPULI-W008"

#: This host's clock is further from a configured store's than the advisory lock
#: allows (#216, #83). Its own code because it is the only finding in the vault
#: survey that is neither visible in the exit code nor a property of the store:
#: it is a property of the pair, and the machine to fix is usually this one.
CLOCK_SKEW_BEYOND_TOLERANCE = "SOPULI-W009"

#: A configured store answered and cannot serve this run: sealed, standing by,
#: not initialised, or refusing the credential it was opened with (#216).
#:
#: Separate from an *unreachable* store, which gets no code at all -- that one
#: fails the run, so a consumer watching the exit code already knows, and the
#: entry in ``vaults[]`` says which store and why. This is the opposite case: the
#: run exits 0 and something is still wrong, which is precisely what a
#: diagnostic is for.
STORE_DEGRADED = "SOPULI-W010"

#: This run's lock was taken over while it was running, found at a fence check
#: (#282, UC-1 §8). The run stopped before its next mutation and promoted
#: nothing; what it had already applied stands.
#:
#: Its own code because it is the one thing the exit code cannot say. A fenced-out
#: run exits 4, and so does a run that simply failed on some targets -- and the
#: two want opposite responses. The second is repaired by running `apply` again;
#: the second run of the first would be denied at exit 7 if it is lucky, and the
#: person reading the output needs to know that somebody else is mid-rotation on
#: this estate before they decide anything. That is #216's rule exactly: a code
#: exists for what the exit code cannot tell you.
#:
#: Distinct from :data:`LOCK_TAKEN_OVER`, which is the *other* side of the same
#: event -- there, this run did the taking and says so; here, it was taken from.
#: One code for both would leave a consumer unable to tell the run that broke a
#: lock from the run that lost one, which are opposite things to be paged about.
LOCK_LOST = "SOPULI-W011"

#: A rotation promoted a document and then read a different password back out of
#: it (#284, UC-1 §8 step 8).
#:
#: Its own code for #216's reason: the exit code cannot say this. The run exits 4,
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

#: ``SOPULI-W004`` -- imported above rather than defined here. It is raised in
#: the config layer, which cannot import this module (see the constant's own
#: comment in :mod:`sopuli.config.references`), so the definition lives with the
#: code that raises it and the registry below stays the one place that says what
#: it means. Importing it here is also what puts it in this module's namespace,
#: so ``from sopuli.diagnostics import UNVERIFIED_TRANSPORT`` reads the same as
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
            "command that resolves that store to a client fails with SOPULI-20001."
        ),
        MISSING_DRIVER: (
            "A `targets:` entry names a driver this machine cannot serve. As with a store, "
            "the config is valid and the install is incomplete, and what that is worth "
            "depends on the question asked: `config validate` warns and exits 0, `doctor` "
            "fails, and any command that connects to that target fails with SOPULI-20002."
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
    }
)


def unlistable_stores(names: Sequence[str]) -> list[Diagnostic]:
    """Say that part of the survey could not be looked at (#150).

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


def lock_diagnostics(manager: LockManager) -> list[Diagnostic]:
    """What a run should say about the locks it took.

    Both warnings describe something that *worked*, which is why they are
    warnings and not errors: the run holds its locks, and it holds them on terms
    the operator should be able to see afterwards without going and reading the
    config file or the vault.
    """
    return [
        *_advisory(manager.stores),
        *(_taken_over(one.key, one.broke) for one in manager.held if one.broke is not None),
    ]


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
    """Somebody's lock was taken by a person who asked for it (#149).

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

    **The only definition of that fact in the tool** (#238). `doctor` reports it
    as an error and exits 9 (E6); `config validate` reports the same finding as a
    warning and exits 0 (E4). Those are the two commands' own judgements of what
    it is worth, and it is deliberate that they differ -- but *what happened* is
    one thing, and until #238 it was computed twice.

    The pair that computed it the other way, ``backend_diagnostics`` and
    ``driver_diagnostics``, are gone. They asked only whether the *client* was
    installed, which left `config validate` silent about `file` and `keyring` --
    unusable in this build for every user, unconditionally -- and silent about
    `oci` on any machine that happened to have the SDK. Three of the four backend
    types in ``01-configuration.md`` §3a have no module, so a config declaring
    all four reported one warning, and which one depended on the machine rather
    than on the file.

    ``level`` is the caller's, and it is the *only* thing the caller decides.
    Giving :func:`backend_diagnostics` a level was tried before #238 and was
    worse, because there were still two functions answering "is this component
    missing" from two definitions; with one function there is nothing left to
    disagree about. It is a :data:`~sopuli.output.document.DiagnosticLevel` and
    not a ``str``, so a typo here is a type error rather than a document that
    fails the schema at the end of a run; there is deliberately no runtime check.

    **Derived from the survey rather than computed a second time.** "Missing" has
    to mean the same thing in `doctor`'s ``install`` section and in the
    ``diagnostics`` array of the same document, and it did not when the two were
    worked out separately: the section asks whether this build has a module *and*
    whether the client is there, and the older pair asked only about the client.
    On a machine with the `oci` SDK installed and no `oci` backend written, that
    disagreement produced an exit 9 with no diagnostic at all -- and with the SDK
    absent it produced one that contradicted the section and pointed at a `pip`
    line that fixes nothing.

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
    """What a run should say about the wallet it will authenticate with (#215).

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
    """What a run should say about the stores it surveyed (#216, P4).

    **Only what the exit code cannot say.** An *unreachable* store deliberately
    gets no diagnostic: it fails the run at exit 1, so anything watching the exit
    code already knows, and the ``vaults[]`` entry names which store and carries
    the error -- exactly the arrangement ``targets[]`` has had since #212, where
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
