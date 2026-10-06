"""Reading a credential out of a stored document (#183, P2, ``01-configuration.md`` §7).

:mod:`sopuli.config.secret_refs` parses a ref when the file is read and
:mod:`sopuli.payload` computes where each stage lives inside a document. Neither
has ever *read* one. This is the join: a ref, a store, and the value the ref
addresses. The ``creds`` verbs and the admin credential's ``method: vault`` read
through it.

**What this module does not do is decide a sequence.** It supplies primitives;
the ``pending`` → ``current`` ordering that makes rotation safe is UC-1 §3's and
belongs to ``creds rotate``. Invariant 7 is not enforceable here and this layer
does not pretend it is: a promotion is one merge patch like any other, and what
makes it correct is *when* it is issued and under which lock.

Four things this module decides, each of which a caller would otherwise decide
differently:

**A ref with no field is a whole-secret read, and it is legal here.** §7 refuses
a field-less ref for an *application* binding, because rotation needs somewhere
to put ``pending`` beside the value -- and says in the same breath that "none of
this constrains a ref that is only ever read". An ``admin.auth.secret`` is
exactly that: a credential the tool authenticates with and never rotates. So the
whole-secret form resolves here and is refused in
:func:`sopuli.payload.stage_layout`, and the two are consistent rather than in
tension.

**The value has to be a string.** A ref that lands on a map or a number has
addressed the wrong depth -- typically the container rather than the account
inside it -- and that is a mistake worth naming while it is still a read. The
alternative is a :class:`~sopuli.secrets.Secret` wrapping ``{'acme_web_user':
...}`` on its way to ``ALTER USER``.

**A document is edited, never regenerated** (§7). The write is a merge patch:
keys this run did not come for are not sent, so a sibling account's password is
neither read into this process nor written back. Where the store cannot apply one
-- KV v1, or a Vault policy granting ``update`` and not ``patch`` -- the fallback
is a read-modify-write under the same compare-and-set, and the run reports which
of the two happened, because they are not equally narrow.

**The one reveal is** :func:`_plaintext`, immediately before the store call. It
is invariant 2's permitted reveal for the vault write, and it is one recursive
function rather than an unwrapping per call site for the mirror of invariant 2's
own reason: if redaction must not depend on anybody remembering, neither may
revealing. Every message this module raises is built from keys and never from
values, including the ones about a document being the wrong shape -- which is
where a leak would be easiest, since the obvious way to say "that is not a
password" is to show what it was instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sopuli.config.secret_refs import SecretRef
from sopuli.exit_codes import ExitCode
from sopuli.payload import CURRENT, StageLayout, stage_layout
from sopuli.payload import apply_patch as payload_apply
from sopuli.secrets import Secret
from sopuli.store.protocol import (
    MERGE_PATCH,
    VERSIONING,
    CasConflictError,
    PatchNotPermittedError,
    SecretStore,
    StoreError,
)

__all__ = [
    "READ_MODIFY_WRITE",
    "CannotPinVersionError",
    "SecretShapeError",
    "StoredSecret",
    "Written",
    "apply_patch",
    "read_secret",
    "resolve",
    "staged_patch",
]


class SecretShapeError(StoreError):
    """The document is not shaped the way the ref addresses it.

    Its own class because the fix is not the store's: the file and the vault
    disagree about where a password lives, and whoever reads the message has to
    know which of the two to change. The exit code stays
    :attr:`~sopuli.exit_codes.ExitCode.FAILURE` rather than borrowing
    ``CONFIG_INVALID`` -- the config parsed, and a run that called it invalid
    would send somebody to edit a file that is very possibly the right one.
    """


class CannotPinVersionError(StoreError):
    """A ref pinned a version and the store it resolves against keeps none.

    :attr:`~sopuli.exit_codes.ExitCode.UNSUPPORTED_CAPABILITY` for the reason
    invariant 4 gives about databases and P2 gives about stores: a command that
    needs a capability the backend lacks fails with a distinct code and a message
    naming the capability, rather than with a generic failure further in.
    """

    exit_code = ExitCode.UNSUPPORTED_CAPABILITY


@dataclass(frozen=True)
class StoredSecret:
    """One value read out of a store, and enough about it to be audited.

    P2's sketch calls this ``SecretValue + metadata``. The version and the stage
    are here rather than left to the caller because the run document's
    ``secret_ref`` carries both (``03-json-output.md``), and a caller that
    re-derived them would be re-deriving them from the ref it started with --
    which says what was *asked for*, not what was found. "No ``@version=``" and
    "version 7 came back" are different facts and only one of them is in the ref.
    """

    #: The value itself, wrapped. There is no plaintext accessor on this class: a
    #: caller that needs the string calls ``reveal()`` on the value, which is what
    #: keeps the permitted reveals greppable (invariant 2).
    value: Secret
    #: The store's version for the document this came out of. Zero on a store
    #: with no versioning, which is
    #: :data:`sopuli.store.hashicorp.kv1.NO_VERSION` and not a version -- the same
    #: honest zero, carried rather than reinvented.
    version: int
    #: Which of C14's three stages was read: ``current`` unless the ref asked for
    #: another. Always populated, because "no qualifier" *means* current and a
    #: ``None`` here would make every consumer restate that.
    stage: str


def resolve(document: Any, ref: SecretRef) -> Secret | None:
    """The value ``ref`` addresses inside ``document``, or ``None``.

    Pure: no store, no I/O, and the whole of the addressing. ``04-testing.md`` §4
    wants the layers that decide things testable without a container, and where a
    password lives inside a document is a decision.

    ``None`` covers every way of finding nothing -- no such field, no such key in
    the container, no ``pending`` staged for this account, no document at all.
    They are one answer deliberately, the reading
    :meth:`sopuli.payload.StageLayout.read` gives at greater length: UC-1 §3's
    state model treats "there is nothing staged here" as one state, and a caller
    that separated them would be separating states it has no separate action for.

    What is *not* ``None`` is a document shaped wrongly, which raises. The
    difference is between a value that is absent and a value that is present and
    is not a password, and only the first of those is ordinary.
    """
    if document is None:
        # Before anything else, including the staged read below: **no document**
        # is not a document of the wrong shape. Reachable through the store as
        # well as directly -- KV v1 answers a body with no `data` key as
        # `Stored(data=None)`, so a staged read there would otherwise be refused
        # for a path that is merely empty.
        return None
    if ref.field is None:
        return _whole(document, ref)

    # Built directly rather than through `stage_layout`, which refuses a field
    # named `pending` and a ref with no field at all. Those refusals guard
    # *rotation* and belong to the binding validation that runs when the file is
    # read (`config/bindings.py`); re-imposing them on a read would refuse an
    # `admin.auth.secret` that §7 explicitly permits.
    layout = StageLayout(container=ref.field, within=ref.pointer_segments)
    stage = ref.stage or CURRENT

    if stage != CURRENT and not isinstance(document, Mapping):
        # The mirror rule needs a root to hang `pending` off, and a scalar
        # document has none. Not `None`: on a store that emulates the stages in
        # payload fields -- every backend in P2's table but OCI -- there is
        # nowhere else for a stage to be, so this is a ref that can never resolve
        # rather than one that found nothing today. An *absent* document took the
        # early return above and never reaches this.
        raise SecretShapeError(
            f"the secret ref {ref} asks for the `{stage}` stage of a document that is not a map",
            hint=(
                f"{ref.path!r} holds a single value, so there is no `{stage}` beside it "
                "-- the stages are emulated in payload fields on this store (P2)"
            ),
        )

    return _wrap(layout.read(document, stage), ref, at=layout.location(stage))


def read_secret(store: SecretStore, ref: SecretRef) -> StoredSecret | None:
    """Read ``ref`` through ``store``, or ``None`` if there is nothing there.

    The two qualifiers can never both apply -- §7 refuses a ref carrying
    ``@version=`` and ``@stage=`` together, on the grounds that nothing says which
    would win -- so this reads a version *or* a stage and never has to order them.
    A pinned version selects the document; a stage selects a key inside whichever
    document was selected.

    The capability check is here as well as in the store, and the duplication is
    the point: this one can name the ref, which is the thing somebody has to go
    and edit. A store's own refusal names a path, because a store has never heard
    of a ref.
    """
    if ref.version is not None and VERSIONING not in store.supports():
        raise CannotPinVersionError(
            f"the secret ref {ref} pins a version, and its store keeps none",
            hint=(
                "drop `@version=` from the ref, or point it at a store that versions "
                "-- P2's capability table has which do, and KV v1 does not"
            ),
        )

    stored = store.read(ref.path, version=ref.version)
    if stored is None:
        return None
    value = resolve(stored.data, ref)
    if value is None:
        return None
    return StoredSecret(value=value, version=stored.version, stage=ref.stage or CURRENT)


# ------------------------------------------------------------------- write ---


def staged_patch(ref: SecretRef, value: Any, *, stage: str = CURRENT) -> dict[str, Any]:
    """A merge patch putting ``value`` at ``ref``'s ``stage``, and nothing else.

    The write-side counterpart of :func:`resolve`, and the same layout by the
    same rule: a patch built here names one account in one stage, and every
    sibling account is **absent** rather than rewritten with what was last read.
    ``04-testing.md`` §4 makes that the interesting assertion, and it is asserted
    on what the patch does not contain.

    ``value`` stays a :class:`~sopuli.secrets.Secret` all the way through -- there
    is no ``reveal()`` in this function, and the patch it returns is safe to log.
    Pass :data:`sopuli.payload.REMOVE` to clear a stage, which is how ``pending``
    is cleared at promotion.

    Refuses a field-less ref, because that is the one case with nowhere to stage
    into: §7 permits the whole-secret form for a ref that is only ever *read*, and
    this is the other half of that sentence.
    """
    return stage_layout(ref).patch(stage, value)


@dataclass(frozen=True)
class Written:
    """What a write did, and how.

    ``mechanism`` is reported rather than inferred because UC-1 §3 requires it --
    "the tool abstracts over that but reports which mechanism it used" -- and
    because the two are not equally safe. Under :data:`MERGE_PATCH` a sibling
    account's password is never read into this process; under the fallback the
    whole document goes out, and the run should say which of those happened
    rather than leave a reader to work it out from the backend.
    """

    #: The store's version after the write. This run's fence.
    version: int
    #: :data:`MERGE_PATCH` or :data:`READ_MODIFY_WRITE`.
    mechanism: str


#: The fallback ``01-configuration.md`` §7 names: read the document, apply the
#: patch locally, write it back under the same compare-and-set. Safe against a
#: concurrent writer -- the CAS is what makes it so -- and wider than a merge
#: patch, because every key in the document is sent whether it changed or not.
READ_MODIFY_WRITE = "read_modify_write"


def apply_patch(
    store: SecretStore, path: str, patch: Mapping[str, Any], *, cas: int | None
) -> Written:
    """Apply ``patch`` to the document at ``path``, and say how it was applied.

    **This is where the plaintext appears**, and it is one of invariant 2's three
    permitted reveals. Values travel as :class:`~sopuli.secrets.Secret` from
    generation through :func:`staged_patch` to here; :func:`_plaintext` unwraps
    them at the last possible moment, immediately before the call that sends
    them. There is exactly one such unwrapping on this path, and it is the reason
    everything above can be logged without care.

    Mechanism, in order:

    * a merge patch where the store has :data:`MERGE_PATCH` and its policy allows
      one, so the keys this run did not come for are never sent;
    * a **read-modify-write** under the same ``cas`` otherwise -- a store without
      the capability, or a Vault policy granting ``update`` and not ``patch``.

    ``cas=0`` skips the patch entirely and writes: it asserts there is nothing at
    the path, and Vault will not create a document by merge patch. That is the
    right refusal rather than an inconvenience — a patch describes a change to
    something — and the caller already knows which case it is in, because ``0``
    is what it passed.

    A :class:`~sopuli.store.protocol.CasConflictError` propagates and is **never**
    retried. §7 is explicit: this run holds the advisory lock on the path, so a
    conflict means a *foreign* writer, and re-reading to merge over them is the
    read-modify-write that rewrites fields belonging to accounts nobody selected.
    The write is abandoned and reported.
    """
    if cas != 0 and MERGE_PATCH in store.supports():
        try:
            return Written(
                version=store.patch(path, _plaintext(patch), cas=cas), mechanism=MERGE_PATCH
            )
        except PatchNotPermittedError:
            # A policy granting `update` and not `patch`, which is ordinary. Fall
            # through rather than fail -- and if the token was in fact bad, the
            # read below fails with the 403 it deserves.
            pass

    stored = store.read(path)
    if stored is not None and cas is not None and stored.version != cas:
        # The conflict the store would have raised, raised here instead: the
        # fallback's read and write are two calls, and without this the run would
        # compute a whole document from a version it has already been told it is
        # not writing against. The store's own CAS still guards the write; this
        # only stops the wrong document being built first.
        raise CasConflictError(
            f"compare-and-set failed at {path!r}: expected version {cas}, found {stored.version}"
        )
    document = None if stored is None else stored.data
    merged = payload_apply(document, _plaintext(patch))
    return Written(version=store.write(path, merged, cas=cas), mechanism=READ_MODIFY_WRITE)


# ----------------------------------------------------------------- helpers ---


def _plaintext(value: Any) -> Any:
    """``value`` with every :class:`~sopuli.secrets.Secret` in it revealed.

    **Invariant 2's permitted reveal for the vault write, and the only one in
    this module.** Deliberately one recursive function rather than an unwrapping
    at each call site: invariant 2's whole argument is that redaction must not
    depend on anybody remembering, and the mirror image of that is that revealing
    must happen in one findable place. Grep for ``reveal()`` and this is what
    turns up on the store side.

    Recursive because a promotion patch is nested -- ``{"pending":
    {"acme_web_user": Secret(…)}}`` -- and because the same call has to serve the
    merge patch and the whole document the fallback builds.
    """
    if isinstance(value, Secret):
        return value.reveal()
    if isinstance(value, Mapping):
        return {key: _plaintext(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        # `targets` is a list of strings in UC-1 §3's payload. Nothing puts a
        # secret in one today; walking it anyway costs nothing and means a future
        # stamp that does cannot be the thing that breaks the guarantee.
        return [_plaintext(item) for item in value]
    return value


def _whole(document: Any, ref: SecretRef) -> Secret | None:
    """A ref with no field: §7's "whole secret (scalar or single-field)".

    The single-field reading is what makes the form usable against KV at all,
    since a KV secret is always a map -- ``vault kv put path password=…`` stores a
    document of one key, and a ref naming no field means that key. More than one
    and there is nothing for it to mean. Listing the field names in the message is
    safe: they are keys, and the values are what this module never shows.

    ``document`` is never ``None`` here: :func:`resolve` returns for that before
    it dispatches, so an absent document is one answer at one place rather than
    the same check repeated down each branch.
    """
    if not isinstance(document, Mapping):
        return _wrap(document, ref, at=())
    if len(document) == 1:
        (only,) = document.values()
        return _wrap(only, ref, at=tuple(str(key) for key in document))
    if not document:
        return None
    fields = ", ".join(sorted(str(key) for key in document))
    raise SecretShapeError(
        f"the secret ref {ref} names no field, and {ref.path!r} holds {len(document)} of them",
        hint=f"add `#field` to the ref -- the document has: {fields}",
    )


def _wrap(value: Any, ref: SecretRef, *, at: tuple[str, ...]) -> Secret | None:
    """Wrap what was found, or say what it was instead -- never what it held.

    ``at`` is the document keys walked to reach it, which is what makes the
    message actionable without quoting the value: "``DB_CREDENTIALS`` holds dict
    rather than a password" tells the reader the ref stopped a level short, using
    key names that were already in the config file.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        where = "/".join(at) if at else ref.path
        raise SecretShapeError(
            f"the secret ref {ref} addresses {where!r}, which holds "
            f"{type(value).__name__} rather than a password",
            hint=(
                "a ref has to reach the value itself -- a pointer one level short lands "
                "on the container, e.g. `#DB_CREDENTIALS` where "
                "`#DB_CREDENTIALS/acme_web_user` was meant"
            ),
        )
    return Secret(value)
