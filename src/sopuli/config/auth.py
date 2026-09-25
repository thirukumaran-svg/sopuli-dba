"""How the file points at authentication material, without ever holding it.

Two places in the config authenticate to something: a vault entry's ``auth:``
(P2) and a target's ``admin:`` (P2's bootstrap sources). They share a *grammar*
and not a vocabulary, and this module is the grammar.

**A MaterialRef is not a SecretRef.** §7's SecretRef addresses a value *in* a
vault. Vault auth material cannot be addressed that way -- it is what you need
before you have a vault at all -- so it is a second, smaller type, named
differently so that the chicken-and-egg stays visible rather than being papered
over by reusing one word for both.

It is a one-key mapping, exactly one of ``env`` or ``file``::

    secret_id: { env: SOPULI_VAULT_SECRET_ID }
    secret_id: { file: /run/secrets/vault_secret_id }

Preferred over an ``_env`` / ``_file`` suffix convention because it makes P2's
constraint *structural*: there is no slot for an inline string, so "auth material
is never written to the config file in plaintext" is enforced by the shape rather
than by a validation rule somebody has to remember to write. A token helper
(``command:``) is deliberately absent -- shelling out from a credential tool
deserves its own decision, and Vault's own helper is the only real use.

**Everything secret-bearing is a MaterialRef, with no exceptions.** An AppRole's
``role_id`` is arguably an identifier rather than a credential, but carving out
one field that may be inline sets a precedent that has to be re-litigated for
every method added later. Non-secret *identity* fields -- ``role``, ``username``,
``profile``, ``mount`` -- stay inline.

**The method block.** Both positions are ``{ method: NAME, ...method-specific
keys }``, with a scalar shorthand where the method requires nothing:
``auth: prompt`` is sugar for ``auth: { method: prompt }``. The shorthand is
legal exactly where the method has no *required* keys, which is what keeps §2's
and §4's existing examples valid unchanged; ``auth: approle`` is refused, naming
the keys it needs, because there is nowhere in a scalar to write them.

What this module checks is shape: the material is one of ``env`` / ``file``, the
method is in the vocabulary for its position, and the keys are the ones that
method takes. Whether the values are *true* -- that the variable is set, that the
role exists -- is checked when something authenticates, which is where P1 and P2
already put vendor validation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.fields import choice, mapping, reject_unknown_keys, string
from sopuli.config.model import MaterialRef

#: The two sources a MaterialRef may name. Closed, and deliberately short: each
#: entry is a promise that the tool can read material from there on every
#: supported platform (P4), which rules out anything shell-shaped.
MATERIAL_KINDS = ("env", "file")


@dataclass(frozen=True)
class Method:
    """One method's key set: what it must be given, and what it may be.

    ``required`` is what decides whether the scalar shorthand is available, so
    the two are one statement rather than a flag that could disagree with the
    keys beside it.
    """

    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()

    @property
    def keys(self) -> tuple[str, ...]:
        return (*self.required, *self.optional)

    @property
    def is_parameterless(self) -> bool:
        """Whether ``auth: NAME`` says everything this method needs."""
        return not self.required


def read_material(
    raw: Any, *, at: KeyPath, noun: str = "auth material", example: str = "SOPULI_VAULT_SECRET_ID"
) -> MaterialRef:
    """Read ``{ env: NAME }`` or ``{ file: PATH }`` -- never a value.

    A bare value is the failure worth a message of its own. It is what somebody
    writes when they mean *the material itself*, and P2's whole constraint is
    that the file does not hold it; "must be a mapping" would read as a type
    complaint about a line that is wrong for a much more specific reason. Numbers
    count: an unquoted ``role_id: 1234`` is the same mistake in YAML's clothing.

    ``noun`` and ``example`` exist because this reader stopped being only auth's
    (#442). A webhook URL is a MaterialRef for C9's reason -- it embeds its own
    credential -- and telling somebody who pasted a chat URL that "auth material is
    named, not written here", with `SOPULI_VAULT_SECRET_ID` as the example, answers
    a question they did not ask. Both default to what every auth caller already
    said, so the defaults are the existing behaviour rather than a new one.
    """
    if isinstance(raw, str | int | float):
        raise ConfigError(
            f"{noun} is named, not written here",
            at=at,
            hint=(
                f"write one of {_kinds()} -- e.g. `{{ env: {example} }}`. "
                "P2: the config points at where the material comes from, never at the "
                "material itself"
            ),
        )

    entry = mapping(raw, at=at)
    if len(entry) != 1:
        named = ", ".join(repr(key) for key in sorted(entry)) or "none"
        raise ConfigError(
            f"must name exactly one source, found {len(entry)} ({named})",
            at=at,
            hint=(
                f"one of {_kinds()} -- two sources leave nothing to say which was meant, "
                "and none says nothing at all"
            ),
        )

    kind, location = next(iter(entry.items()))
    return MaterialRef(
        kind=choice(kind, allowed=MATERIAL_KINDS, at=at, noun="material source"),
        location=string(location, at=at.key(kind)),
    )


def read_method(
    raw: Any,
    *,
    at: KeyPath,
    methods: dict[str, Method],
    noun: str,
    shape: Callable[[str], str],
) -> tuple[str, dict[str, Any]]:
    """Read a method block, or its scalar shorthand, and check its keys.

    Returns the method name and the mapping its keys were written in -- empty for
    the shorthand -- leaving each key's own type to the caller. The two positions
    read the same grammar and build different objects, and one reader that
    returned a union of both would have to know about vaults and databases at
    once.

    ``shape`` says how one key is written, for the error about a missing one. It is
    the caller's to supply because this module knows only that a key is *absent*:
    a vault's material is a MaterialRef, a target's ``admin.auth.secret`` is a
    SecretRef, and an identity field such as ``role`` is written inline. A sentence
    fixed here would be wrong for one of those positions, and "required for this
    method: role_id, secret_id" -- which is what it used to say -- was wrong for
    all of them, because it repeated the message instead of answering it (#70).

    It returns a predicate **without its verb** -- "named, not written -- ``{ env:
    NAME }``" rather than "is named" -- because :func:`_explain` groups the keys
    that share one and has to choose *is* or *are* for the group.
    """
    if isinstance(raw, str):
        return _shorthand(raw, at=at, methods=methods, noun=noun, shape=shape), {}

    entry = mapping(raw, at=at)
    if "method" not in entry:
        raise ConfigError(
            "must name a method",
            at=at.key("method"),
            hint=f"one of: {', '.join(methods)}",
        )

    method = choice(entry["method"], allowed=tuple(methods), at=at.key("method"), noun=noun)
    spec = methods[method]
    reject_unknown_keys(
        entry,
        allowed=("method", *spec.keys),
        at=at,
        hint=(
            f"`method: {method}` takes {_listed(spec.keys)} -- a key belongs to the method "
            "that uses it, so a key from another method is a leftover rather than a typo"
        ),
    )
    missing = [key for key in spec.required if key not in entry]
    if missing:
        # Anchored at the first missing key rather than at the block, the way
        # `required_string` reports a key that is not there: the path is where the
        # line has to be written, and a block-level path leaves a reader to work
        # that out from the message. All of them are named, so nothing is hidden by
        # pointing at one.
        raise ConfigError(
            f"`method: {method}` needs {_listed(tuple(missing))}",
            at=at.key(missing[0]),
            hint=_explain(tuple(missing), shape),
        )
    return method, entry


def read_material_key(entry: dict[str, Any], key: str, *, at: KeyPath) -> MaterialRef | None:
    """One optional MaterialRef inside a method block.

    Absent stays absent. ``method: token`` with no ``token:`` is the fall-through
    P2 describes -- ``--vault-token-file``, then ``$SOPULI_VAULT_TOKEN``, then
    ``$VAULT_TOKEN``, then ``~/.vault-token`` -- and a default written in here
    would turn a documented source chain into a path this layer had guessed at.
    """
    if key not in entry:
        return None
    return read_material(entry[key], at=at.key(key))


def _shorthand(
    text: str, *, at: KeyPath, methods: dict[str, Method], noun: str, shape: Callable[[str], str]
) -> str:
    """``auth: prompt`` -- legal where the method requires nothing else."""
    method = choice(text, allowed=tuple(methods), at=at, noun=noun)
    spec = methods[method]
    if not spec.is_parameterless:
        raise ConfigError(
            f"`{method}` cannot be written as a bare value: it needs {_listed(spec.required)}",
            at=at,
            hint=(
                f"the short form is for methods that need nothing else -- write "
                f"`{{ method: {method}, ... }}`, where {_explain(spec.required, shape)}"
            ),
        )
    return method


def _explain(missing: tuple[str, ...], shape: Callable[[str], str]) -> str:
    """The keys that are missing, and what goes in each of them.

    Keys sharing a shape are grouped, because ``approle`` needs two MaterialRefs
    and saying so twice in one sentence is how a hint stops being read.
    """
    grouped: dict[str, list[str]] = {}
    for key in missing:
        grouped.setdefault(shape(key), []).append(key)
    return "; ".join(f"{_keys(keys)} {text}" for text, keys in grouped.items())


def _keys(keys: list[str]) -> str:
    """```role_id:` and `secret_id:` are`` -- the subject of one clause."""
    written = [f"`{key}:`" for key in keys]
    if len(written) == 1:
        return f"{written[0]} is"
    return f"{', '.join(written[:-1])} and {written[-1]} are"


def _kinds() -> str:
    return ", ".join(f"`{kind}:`" for kind in MATERIAL_KINDS)


def _listed(keys: tuple[str, ...]) -> str:
    """Name a method's keys, or say plainly that it takes none."""
    if not keys:
        return "no other keys"
    return ", ".join(f"`{key}`" for key in keys)
