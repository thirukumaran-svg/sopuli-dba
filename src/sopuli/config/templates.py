"""``{token}`` substitution, in the one form the config file uses.

Two things expand tokens against a flat scope: a target set rendering its
template over dimension values (§4), and a secret ref rendering per account and
target (§7). They differ only in what is in scope, so they share the mechanism
and differ in one sentence of the error message.

That sharing is the point. Two implementations would drift, and the way they
would drift is in what they do with a token that resolves to nothing -- which is
the failure §10 names twice: an unresolved ``{placeholder}`` is an error, never
an empty string. A DSN with `{tenant}` still in it reaches the driver; a secret
ref with it still in it reaches the vault.

Deliberately not a template language (C3, C7): a fixed token list, no
expressions, and no way to escape a literal brace. Neither a DSN nor a secret
path has a reason to contain one, and an escape syntax is one more thing to get
wrong in the file that decides where production passwords are written.
"""

from __future__ import annotations

import re

from sopuli.config.errors import ConfigError, KeyPath

#: One ``{placeholder}``. Non-nesting by construction: the character class
#: excludes both braces, so ``{a{b}}`` cannot match as one token and is reported
#: as the unbalanced brace it is.
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")


def substitute(text: str, variables: dict[str, str], *, at: KeyPath, source: str) -> str:
    """Replace every ``{name}`` from ``variables``, or say why it could not.

    ``source`` completes the hint on an unresolved token -- "a placeholder
    resolves from ..." -- because the useful half of that message is *where the
    values were supposed to come from*, and only the caller knows.

    Balance is checked before substitution rather than after, so a variable whose
    *value* happens to contain a brace is not reported as a malformed template.
    """
    stripped = PLACEHOLDER.sub("", text)
    if "{" in stripped or "}" in stripped:
        raise ConfigError(
            f"unbalanced brace in {text!r}",
            at=at,
            hint="a placeholder is written `{name}`; a literal brace cannot be escaped",
        )

    def resolve(match: re.Match[str]) -> str:
        name = match.group(1)
        if not name:
            raise ConfigError(
                f"empty placeholder in {text!r}",
                at=at,
                hint=f"write `{{name}}`; in scope here: {in_scope(variables)}",
            )
        if name not in variables:
            raise ConfigError(
                f"nothing to substitute for `{{{name}}}` in {text!r}",
                at=at,
                hint=f"in scope here: {in_scope(variables)} -- {source}",
            )
        return variables[name]

    return PLACEHOLDER.sub(resolve, text)


def in_scope(variables: dict[str, str]) -> str:
    """The names a template could have used here, for an error message."""
    return ", ".join(sorted(variables))
