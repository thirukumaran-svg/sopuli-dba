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

What is *not* settled here is what a qualifier value means. ``version`` and
``stage`` are the two §7 names, so an unknown qualifier is refused -- but their
values are kept as written, because P2 puts per-backend validation behind the
store interface. Version numbering and the stage vocabulary are the store's, and
inventing them here would fix a schema the vault layer then has to live with.
The same reasoning as ``auth.method`` in :mod:`sopuli.config.vaults`.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.errors import ROOT, ConfigError, KeyPath

#: The qualifiers §7 names. Closed, because a misspelt one would otherwise
#: become part of the field name and read a secret that does not exist -- or,
#: worse, one that does.
VERSION = "version"
STAGE = "stage"
QUALIFIERS = (VERSION, STAGE)

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
    version: str | None = None
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
        return "{" in str(self)

    def __str__(self) -> str:
        """Render back to the string it was parsed from.

        Round-tripping is not a convenience: a ref is what plan output and the
        audit trail name a secret by, and a form that differed from the one in
        the config file would make the two impossible to line up by eye.
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

    return SecretRef(
        path=path,
        vault=vault,
        field=field,
        pointer=pointer,
        version=version,
        stage=stage,
    )


# ------------------------------------------------------------- qualifiers ---


def _split_qualifier(text: str, *, at: KeyPath) -> tuple[str, str | None, str | None]:
    """Peel ``@version=N`` or ``@stage=NAME`` off the end.

    Split on the *last* ``@`` so a path containing one still parses, and only
    when what follows looks like an assignment. A qualifier with a misspelt name
    is an error rather than path text: silently addressing
    ``creds#password@versio=7`` as a field name would read the wrong secret.
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

    return (head, value, None) if name == VERSION else (head, None, value)


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
