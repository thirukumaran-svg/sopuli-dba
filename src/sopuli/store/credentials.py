"""Reading a credential out of a stored document (#183, P2, ``01-configuration.md`` §7).

:mod:`sopuli.config.secret_refs` parses a ref when the file is read and
:mod:`sopuli.payload` computes where each stage lives inside a document. Neither
has ever *read* one. This is the join: a ref, a store, and the value the ref
addresses -- which is what ``creds check`` is blocked on and what
:data:`sopuli.admin.RefReader` has been declared as a callable waiting for since
#175.

The read side only. Writing a credential is the other half of #183, and the seam
is not arbitrary: a read resolves an address, while a write has to preserve every
key it did not come for (§7's "a document is edited, not regenerated"), hold the
lock while it does, and never promote before every target has confirmed
(invariant 7). Those are different problems and the second is the dangerous one.

Three things this module decides, each of which a caller would otherwise decide
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

**Nothing here reveals.** Values are wrapped on the way out and the plaintext is
never formatted into a message, including the messages about a document being the
wrong shape -- which is where it would be easiest to leak one, since the obvious
way to say "that is not a password" is to show what it was instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sopuli.config.secret_refs import SecretRef
from sopuli.exit_codes import ExitCode
from sopuli.payload import CURRENT, StageLayout
from sopuli.secrets import Secret
from sopuli.store.protocol import VERSIONING, SecretStore, StoreError

__all__ = [
    "CannotPinVersionError",
    "SecretShapeError",
    "StoredSecret",
    "read_secret",
    "resolve",
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


# ----------------------------------------------------------------- helpers ---


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
