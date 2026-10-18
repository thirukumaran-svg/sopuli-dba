"""One string that addresses a value in any backend (§7).

::

    [<vault>:]<path>[#<field>[/<json-pointer>]][@<qualifier>=<value>]

P2 makes this the whole of the addressing model: a ref is uniform across
backends and only its *resolution* is backend-specific. So this module decides
structure and nothing else. It never opens a store, never reads a value, and has
no opinion about whether the path exists.

**Templates parse too, and that is the point.** ``tenants/{tenant}#DB_CREDENTIALS/{account}``
has the same structure as the ref it expands into, because the punctuation that
gives a ref its shape is literal and the ``{tokens}`` sit inside the parts. A
template can therefore be checked when the file is read rather than at the first
rotation. The one thing that cannot be checked early is a token whose *value*
turns out to contain ``#``, ``:`` or ``/`` -- that changes the structure, and the
labels are not known until expansion.

Three ambiguities in the grammar have to be settled to parse it at all, and each
is settled the way that keeps a realistic ref working:

* ``:`` means a vault prefix only before the first ``/`` or ``#``. Otherwise
  ``tenants/beta#DB:extra`` would name a vault called ``tenants/beta#DB``.
* ``@`` starts a qualifier only when what follows contains ``=``. Paths like
  ``apps/user@example.com/db`` are ordinary; ``@version=7`` is not.
* ``/`` inside the ``#`` part starts the JSON pointer, because a field name is
  one segment and everything after it addresses into that field's document.

**The qualifier vocabularies are the tool's** (C14). ``version``
and ``stage`` are the two §7 names, an unknown qualifier is refused, and so is an
unknown *value*: a stage outside ``current`` / ``pending`` / ``previous``, or a
version that is not a whole number from 1 upwards. Both stores in scope have a
fixed vocabulary of their own -- OCI's rotation states are Oracle's five, not
user-definable labels, and both number versions with integers -- so carrying the
value through to the backend would buy nothing and move a typo to rotation time,
which invariant 4 says is the wrong time to find out.

Stages are matched case-insensitively and normalised to lower case, because OCI
writes ``PENDING`` and that is the spelling a DBA copies out of the console. The
cost is the one place a ref no longer renders back byte-for-byte; see
:meth:`SecretRef.__str__`.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.errors import ROOT, ConfigError, KeyPath

#: Path segments that address something other than a document. Refused rather
#: than dropped, everywhere a path is read (decision #344).
#:
#: The ref grammar owns this rule: it is a statement about what a path may say,
#: and the lock layer is one of its consumers rather than its author.
#: :func:`normalise_path` below -- the other place that enforces it -- lives
#: here for that same reason.
TRAVERSAL = frozenset({".", ".."})

#: Characters a store path or mount may not hold (#858). The HashiCorp backends
#: put the path into the URL as written. A ``?`` starts a query, so the rest of
#: the path is dropped. A ``%`` lets ``%2e%2e`` reach the server as a ``..`` that
#: the traversal check never saw. A backslash or a control character has no
#: use in a vault path. They are refused rather than percent-encoded, as
#: ``TRAVERSAL`` is: the operator learns at load time, with a location, that
#: the path does not say what they meant, and no real estate needs them.
UNSAFE_PATH_CHARACTERS = frozenset("?%\\")

UNSAFE_PATH_HINT = (
    "a store path or mount may not hold `?`, `%`, a backslash or a control "
    "character: the path goes into the store's URL as written, and these change "
    "which document it addresses"
)

CONFIG_PATH_HINT = (
    "a store path, prefix or mount may not hold `?`, `#`, `%`, a backslash or a "
    "control character: it goes into the store's URL as written, and these change "
    "which document it addresses"
)


def unsafe_path_characters(text: str, *, also: str = "") -> list[str]:
    """The characters in ``text`` that a store path or mount may not hold.

    Control characters are C0, DEL and C1. ``also`` adds characters for one
    caller. Each one is listed once, in the order it first appears.
    """
    found: list[str] = []
    for character in text:
        code = ord(character)
        control = code < 0x20 or 0x7F <= code <= 0x9F
        refused = control or character in UNSAFE_PATH_CHARACTERS or character in also
        if refused and character not in found:
            found.append(character)
    return found


def reject_unaddressable_path(text: str, *, what: str, at: KeyPath, traversal_hint: str) -> None:
    """Raise :class:`ConfigError` unless ``text`` addresses what it says.

    Two rules, for every store path or mount a file names: no ``.`` or ``..``
    segment (decision #344), and none of the characters
    :func:`unsafe_path_characters` finds, nor ``#``. httpx drops everything
    after a ``#`` as a URL fragment. A ref's path cannot hold one, because the
    ref grammar splits on it, but a prefix or a mount could. ``#`` is checked
    here and not in :func:`normalise_path`, because that function also builds
    reset-record paths, and an Oracle ``C##`` account name holds two.

    ``what`` names the value in the message, such as ``secret ref 'apps/x'``.
    ``traversal_hint`` says what a relative segment would do at this site, which
    differs between a ref, a prefix and a mount.
    """
    traversal = sorted({segment for segment in text.split("/") if segment in TRAVERSAL})
    if traversal:
        raise ConfigError(
            f"{what} contains {', '.join(repr(one) for one in traversal)} as a path segment",
            at=at,
            hint=traversal_hint,
        )
    unsafe = unsafe_path_characters(text, also=FIELD_SEPARATOR)
    if unsafe:
        raise ConfigError(
            f"{what} contains {', '.join(repr(one) for one in unsafe)}",
            at=at,
            hint=CONFIG_PATH_HINT,
        )


#: The qualifiers §7 names. Closed, because a misspelt one would otherwise
#: become part of the field name and read a secret that does not exist -- or,
#: worse, one that does.
VERSION = "version"
STAGE = "stage"
QUALIFIERS = (VERSION, STAGE)

#: The stages a ref may name (C14). UC-1 §2's three states, which are also
#: three of OCI's five rotation states. ``LATEST`` and ``DEPRECATED`` are left
#: out on purpose: ``LATEST`` is an upload-ordering artefact with no counterpart
#: in a payload of JSON fields, and ``DEPRECATED`` names a *set* of versions
#: rather than selecting one, so it is not a selector at all.
STAGES = ("current", "pending", "previous")

#: The lowest version a ref may pin. Not 0: KV v2 reads version 0 as "the latest
#: version" while OCI numbers from 1, and a ref that meant two different things
#: depending on where it resolved would be a rotation reading the wrong password.
#: "The current one" is ``@stage=current``, or no qualifier at all.
FIRST_VERSION = 1

#: What a token looks like in a template, so a qualifier can refuse to hold one.
TOKEN_START = "{"

VAULT_SEPARATOR = ":"
FIELD_SEPARATOR = "#"
POINTER_SEPARATOR = "/"
QUALIFIER_SEPARATOR = "@"

#: RFC 6901's escapes. ``~1`` must be decoded before ``~0``, as the RFC says:
#: the other order turns ``~01`` into ``/`` rather than the ``~1`` it means.
_POINTER_ESCAPES = (("~1", POINTER_SEPARATOR), ("~0", "~"))


@dataclass(frozen=True)
class SecretRef:
    """A parsed §7 reference. Frozen, like everything else the config produces.

    ``pointer`` keeps its leading ``/`` so that it round-trips, and so that the
    difference between "no pointer" and "the pointer to the empty key" is
    representable even though the latter is refused on the way in.
    """

    path: str
    vault: str | None = None
    field: str | None = None
    pointer: str | None = None
    version: int | None = None
    stage: str | None = None

    @property
    def pointer_segments(self) -> tuple[str, ...]:
        """The pointer as RFC 6901 segments, unescaped.

        ``#DB_CREDENTIALS/a~1b`` addresses the key ``a/b``, not two levels. A
        store that split on ``/`` itself would write into the wrong place, which
        is why the decoding lives here rather than in each backend.
        """
        if self.pointer is None:
            return ()
        return tuple(_unescape(segment) for segment in self.pointer.split(POINTER_SEPARATOR)[1:])

    @property
    def is_templated(self) -> bool:
        """Whether any part still contains a ``{token}`` to expand (§7)."""
        return TOKEN_START in str(self)

    def __str__(self) -> str:
        """Render the canonical form of the ref.

        Round-tripping is not a convenience: a ref is what plan output and the
        audit trail name a secret by, and a form that differed from the one in
        the config file would make the two impossible to line up by eye.

        One difference is allowed, and only one: a stage written in upper case
        renders back in lower case, because C14 normalises it. That is the price
        of a canonical form, and the right side of the trade -- two refs that
        differ only in the case of a stage now compare equal, which is what
        "addresses the same secret" ought to mean.
        """
        rendered = self.path if self.vault is None else f"{self.vault}:{self.path}"
        if self.field is not None:
            rendered += f"{FIELD_SEPARATOR}{self.field}"
        if self.pointer is not None:
            rendered += self.pointer
        if self.version is not None:
            rendered += f"{QUALIFIER_SEPARATOR}{VERSION}={self.version}"
        if self.stage is not None:
            rendered += f"{QUALIFIER_SEPARATOR}{STAGE}={self.stage}"
        return rendered


def parse_secret_ref(text: str, *, at: KeyPath = ROOT) -> SecretRef:
    """Parse a §7 ref, or say exactly which part of it is wrong.

    Every failure names the ref as written. A message about "the secret ref"
    without it is unusable in a file that may declare a dozen.
    """
    if not text or text != text.strip():
        raise ConfigError(
            f"secret ref {text!r} has leading or trailing whitespace"
            if text.strip()
            else "secret ref must not be empty",
            at=at,
            hint="a ref is `[vault:]path[#field[/pointer]][@version=N|@stage=NAME]`",
        )

    remainder, version, stage = _split_qualifier(text, at=at)
    remainder, vault = _split_vault(remainder, text, at=at)
    path, field, pointer = _split_field(remainder, text, at=at)

    # Refused here as well as at the lock key, and this is the one an operator
    # sees: a ref in a file gets a message with a location, rather than the
    # `ValueError` backstop `normalise_path` raises for a path that reached it
    # some other way. A `..` does not address a document -- it walks out
    # of whatever prefix the caller put it under, which for a lock is the
    # `locks/` prefix that keeps lock writes off the secret itself.
    reject_unaddressable_path(
        path,
        what=f"secret ref {text!r}",
        at=at,
        traversal_hint=(
            "write the path the document actually lives at -- a relative segment "
            "resolves somewhere else on the way to the store, so the ref addresses "
            "a document other than the one written here; a lock for it, for "
            "instance, would not land under `locks/`"
        ),
    )

    return SecretRef(
        path=path,
        vault=vault,
        field=field,
        pointer=pointer,
        version=version,
        stage=stage,
    )


def normalise_path(path: str) -> str:
    """Collapse a path to the one spelling a lock is taken on.

    Empty segments are dropped -- ``apps//acme/db`` and ``apps/acme/db`` are one
    document, and two keys for it would be two locks that never contend.

    **`.` and `..` are refused rather than dropped** (decision #344). Dropping
    them would silently rewrite the path the operator typed, so `lock status` and
    `lock break` would disagree about which record they mean; keeping them was
    worse still. `lock_path()` prefixes a key with ``locks/``, and a `..` walks
    straight back out of that prefix: without this refusal,
    ``lock break 'kv:../secrets/acme/db'`` would build
    ``locks/../secrets/acme/db``, which httpx collapses to the *secret's* own
    path, and the run would CAS-write a lock record onto the credential
    document. Decision #344 records the case.

    :func:`sopuli.lock.keys.lock_key` says normalisation can only ever *merge*
    keys, "which over-locks at worst". **This refusal is what makes that true.**
    Merging is safe and redirecting is not, and these two segments are the whole
    difference -- so they cannot be normalised away, only rejected.

    :class:`ValueError` rather than the :class:`ConfigError` everything else in
    this module raises,
    for :func:`sopuli.lock.keys.parse_lock_key`'s reason: this is reached from a command line as
    well as from a file, and the command boundary already turns it into exit 2.
    A ref in a *file* is refused earlier and with a location, by
    :func:`parse_secret_ref` above, so this is the backstop rather than the
    message an operator normally sees. The same holds for the characters in
    :data:`UNSAFE_PATH_CHARACTERS` and the control characters.
    """
    segments = [segment for segment in path.split("/") if segment]
    offending = sorted({segment for segment in segments if segment in TRAVERSAL})
    if offending:
        raise ValueError(
            f"secret path {path!r} contains {', '.join(repr(one) for one in offending)}, "
            f"which cannot address a document"
        )
    unsafe = unsafe_path_characters(path)
    if unsafe:
        raise ValueError(
            f"secret path {path!r} contains {', '.join(repr(one) for one in unsafe)}; "
            f"{UNSAFE_PATH_HINT}"
        )
    return "/".join(segments)


# ------------------------------------------------------------- qualifiers ---


def _split_qualifier(text: str, *, at: KeyPath) -> tuple[str, int | None, str | None]:
    """Peel ``@version=N`` or ``@stage=NAME`` off the end.

    Split on the *last* ``@`` so a path containing one still parses, and only
    when what follows looks like an assignment. A qualifier with a misspelt name
    is an error rather than path text: silently addressing
    ``creds#password@versio=7`` as a field name would read the wrong secret.

    Structure is checked before vocabulary, so ``@version=1@stage=pending`` is
    reported as two qualifiers rather than as whichever value happens to be
    looked at first.
    """
    head, separator, tail = text.rpartition(QUALIFIER_SEPARATOR)
    if not separator or "=" not in tail:
        return text, None, None

    name, _, value = tail.partition("=")
    if name not in QUALIFIERS:
        raise ConfigError(
            f"unknown qualifier {name!r} in secret ref {text!r}",
            at=at,
            hint=f"known: {', '.join(QUALIFIERS)}",
        )
    if not value:
        raise ConfigError(
            f"qualifier {name!r} has no value in secret ref {text!r}",
            at=at,
            hint=f"write `@{name}=...`, or leave the qualifier off entirely",
        )
    if not head:
        raise ConfigError(
            f"secret ref {text!r} is a qualifier with nothing to qualify",
            at=at,
            hint="a ref needs a path before `@`",
        )
    if _ends_with_qualifier(head):
        raise ConfigError(
            f"secret ref {text!r} has more than one qualifier",
            at=at,
            hint=(
                "a pinned version and a stage select the same secret two different ways, "
                "and nothing says which would win"
            ),
        )

    if TOKEN_START in value:
        raise ConfigError(
            f"qualifier {name!r} in secret ref {text!r} contains a token",
            at=at,
            hint=(
                "write it literally: a version or stage that varied per target would have "
                "one rotation reading a different generation on each of them"
            ),
        )

    if name == VERSION:
        return head, _version(value, text, at=at), None
    return head, None, _stage(value, text, at=at)


def _version(value: str, text: str, *, at: KeyPath) -> int:
    """A pinned version, as an integer (C14).

    Both stores in scope number versions with integers, so a ref that does not is
    refused here rather than at the far end of a rotation. ``isascii`` as well as
    ``isdigit`` because ``int()`` accepts other scripts' digits and a version
    written in them is a typo, not a preference.

    ``@version=007`` is refused rather than read as 7, so that the case of a
    stage stays the *only* thing that does not render back as it was written.
    Upper case has a source -- OCI spells its rotation states that way -- and
    padding has none, so accepting it would be canonicalising for nothing.
    """
    if not (value.isascii() and value.isdigit()):
        raise ConfigError(
            f"version {value!r} in secret ref {text!r} is not a whole number",
            at=at,
            hint="both stores number versions with integers, as in `@version=7`",
        )
    number = int(value)
    if number < FIRST_VERSION:
        raise ConfigError(
            f"version {value!r} in secret ref {text!r} is below the first version",
            at=at,
            hint=(
                "versions are numbered from 1; for the current one write `@stage=current` "
                "or leave the qualifier off"
            ),
        )
    if value != str(number):
        raise ConfigError(
            f"version {value!r} in secret ref {text!r} is padded with leading zeros",
            at=at,
            hint=f"write it as `@{VERSION}={number}` -- a ref has one canonical form",
        )
    return number


def _stage(value: str, text: str, *, at: KeyPath) -> str:
    """A stage, normalised to the vocabulary UC-1 §2 and the run schema share.

    Case-insensitive because OCI writes ``PENDING`` and that is the spelling
    somebody copies out of the console -- but the parsed value is lower case, so
    there is one spelling downstream and the backends map from it rather than to
    each other.
    """
    normalised = value.lower()
    if normalised not in STAGES:
        raise ConfigError(
            f"unknown stage {value!r} in secret ref {text!r}",
            at=at,
            hint=f"known: {', '.join(STAGES)} -- any case",
        )
    return normalised


def _ends_with_qualifier(head: str) -> bool:
    """Whether what is left after peeling one qualifier ends in another.

    Asked of the *end* of the remainder, because that is the only place a
    qualifier can be. Scanning the whole string for ``@...=...`` instead would
    contradict the rule above and reject ``apps/user@foo=bar/db#password@version=2``,
    where only the trailing assignment is a qualifier and the rest is path.
    """
    _, separator, tail = head.rpartition(QUALIFIER_SEPARATOR)
    if not separator:
        return False
    name, equals, value = tail.partition("=")
    return bool(equals) and bool(value) and name in QUALIFIERS


# ------------------------------------------------------------------ parts ---


def _split_vault(remainder: str, text: str, *, at: KeyPath) -> tuple[str, str | None]:
    """Peel ``vault:`` off the front, if that is what the colon means."""
    colon = remainder.find(VAULT_SEPARATOR)
    if colon == -1 or _starts_a_part(remainder, before=colon):
        return remainder, None

    vault = remainder[:colon]
    if not vault:
        raise ConfigError(
            f"secret ref {text!r} names an empty vault",
            at=at,
            hint="write `vault-name:path`, or drop the colon to use the default store",
        )
    return remainder[colon + 1 :], vault


def _starts_a_part(remainder: str, *, before: int) -> bool:
    """Whether a path or field separator comes first, making the colon literal."""
    return any(
        0 <= remainder.find(separator) < before
        for separator in (POINTER_SEPARATOR, FIELD_SEPARATOR)
    )


def _split_field(remainder: str, text: str, *, at: KeyPath) -> tuple[str, str | None, str | None]:
    """Split ``path#field/pointer`` into its three parts."""
    path, separator, rest = remainder.partition(FIELD_SEPARATOR)
    if not path:
        raise ConfigError(
            f"secret ref {text!r} has no path",
            at=at,
            hint="the path is the part before `#`, and every ref needs one",
        )
    if not separator:
        return path, None, None

    if FIELD_SEPARATOR in rest:
        raise ConfigError(
            f"secret ref {text!r} has more than one `#`",
            at=at,
            hint="one `#` names the field; anything addressing into it goes after a `/`",
        )

    field, pointer_separator, pointer = rest.partition(POINTER_SEPARATOR)
    if not field:
        raise ConfigError(
            f"secret ref {text!r} has an empty field",
            at=at,
            hint="name the field after `#`, or drop the `#` to address the whole secret",
        )
    if not pointer_separator:
        return path, field, None
    if any(not segment for segment in pointer.split(POINTER_SEPARATOR)):
        raise ConfigError(
            f"secret ref {text!r} has an empty pointer segment",
            at=at,
            hint=(
                "RFC 6901 allows a key named nothing; a credential store has no such key, "
                "so this is a stray `/`"
            ),
        )
    return path, field, f"{POINTER_SEPARATOR}{pointer}"


def _unescape(segment: str) -> str:
    for escape, character in _POINTER_ESCAPES:
        segment = segment.replace(escape, character)
    return segment
