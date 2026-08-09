"""YAML parsing, hardened against the two ways PyYAML loses data quietly.

``safe_load`` is the baseline and is not negotiable: the plain loader constructs
arbitrary Python objects from tags in the document, and a config file is exactly
the kind of thing that arrives from a shared drive or a repository someone else
can write to.

On top of that, two behaviours of stock PyYAML are wrong for this file, and both
are wrong *silently*, which is what makes them worth code rather than a note in
the README. See ``docs/decisions/adr-004-yaml-parser.md``.

**Duplicate mapping keys.** PyYAML keeps the last one and says nothing:

    >>> yaml.safe_load("accounts: [a]\\naccounts: [b]")
    {'accounts': ['b']}

For this tool that is a config declaring six accounts, managing three, and
reporting success. Invariant 5 makes the config the whitelist; a whitelist that
can silently lose half its entries is not one. Duplicates are an error here,
reported at the *second* occurrence, which is the one to delete.

**Booleans, YAML 1.1 style.** PyYAML implements YAML 1.1, where ``yes``, ``no``,
``on`` and ``off`` are booleans:

    >>> yaml.safe_load("tenant: no")
    {'tenant': False}

This config is full of bare words in positions where that matters -- tenant
names, environment names, PDB suffixes, label values. The well-known form of
this is the "Norway problem", where the country code ``NO`` stops being a
string. A tenant called ``no`` becoming ``False`` would flow all the way into a
rendered secret path. Only ``true`` and ``false`` stay boolean.

Left alone deliberately:

* **Anchors and aliases.** Useful in a file a human maintains by hand, and the
  billion-laughs concern is about hostile input -- this file is the operator's
  own, and they can already point it at any database they like.
* **YAML 1.1 octal**, where ``0640`` parses as 416. No field in the schema is
  written with a leading zero, and PR 2 types numeric fields explicitly, so a
  wrong value is caught by the field's own validation rather than accepted. It
  is recorded in the ADR so the next person does not rediscover it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sopuli.config.errors import ConfigError, location_of

#: PyYAML indexes implicit resolvers by the first character of the scalar, so
#: the bool resolver is registered under y, Y, n, N, o, O, t, T, f and F.
#: Keeping only these four is what leaves `true`/`false` boolean while `yes`,
#: `no`, `on` and `off` stay the strings they look like.
BOOLEAN_FIRST_CHARS = "tTfF"


class SopuliSafeLoader(yaml.SafeLoader):
    """``SafeLoader`` that refuses duplicate keys and narrows YAML 1.1 booleans.

    Subclassed rather than configured because PyYAML holds resolvers in class
    attributes: editing them on ``SafeLoader`` itself would change the
    behaviour of every other library in the process that happens to use it.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        # flatten_mapping resolves `<<:` merge keys first, so a merged-in key is
        # not mistaken for a duplicate of one written out longhand.
        self.flatten_mapping(node)

        seen: dict[Any, yaml.Node] = {}
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicated = key in seen
            except TypeError:
                # An unhashable key -- YAML allows a sequence or mapping as one
                # (`? [a, b]`). PyYAML's own construct_mapping reports that as a
                # ConstructorError carrying a mark, which parse_yaml turns into a
                # located ConfigError. Skipping here leaves it to do so; without
                # this, the hardening would replace a good error with a bare
                # TypeError, which is a regression on stock behaviour.
                continue
            if duplicated:
                line, column = location_of(key_node.start_mark)
                first_line, _ = location_of(seen[key].start_mark)
                raise ConfigError(
                    f"duplicate key {key!r}",
                    line=line,
                    column=column,
                    hint=(
                        f"first defined at line {first_line}; YAML would silently keep "
                        "only the last one, so remove one of them"
                    ),
                )
            seen[key] = key_node

        return super().construct_mapping(node, deep=deep)


def _narrow_boolean_resolvers() -> None:
    """Keep ``true``/``false``, drop ``yes``/``no``/``on``/``off``.

    Rebuilding the whole table is the supported way to do this -- PyYAML has no
    "remove one resolver" call. See :data:`BOOLEAN_FIRST_CHARS`.
    """
    original = SopuliSafeLoader.yaml_implicit_resolvers
    rebuilt: dict[str, list[tuple[str, Any]]] = {}
    for first_char, resolvers in original.items():
        rebuilt[first_char] = [
            (tag, regexp)
            for tag, regexp in resolvers
            if tag != "tag:yaml.org,2002:bool" or first_char in BOOLEAN_FIRST_CHARS
        ]
    SopuliSafeLoader.yaml_implicit_resolvers = rebuilt


_narrow_boolean_resolvers()


def parse_yaml(text: str, *, source: Path | None = None) -> Any:
    """Parse one YAML document, turning any parser failure into a ConfigError.

    A ``yaml.YAMLError`` reaching a user is a stack trace with a library name in
    it. The information inside it -- what the parser expected, and where -- is
    good; only the packaging is wrong, so it is repackaged rather than replaced.
    """
    try:
        # Not yaml.load's default loader: SopuliSafeLoader derives from
        # SafeLoader, so no tag can construct an arbitrary Python object.
        return yaml.load(text, Loader=SopuliSafeLoader)
    except ConfigError as error:
        # Raised by construct_mapping above; it already knows its own location.
        error.source = source
        raise
    except yaml.MarkedYAMLError as error:
        line, column = location_of(error.problem_mark)
        # PyYAML splits its message into `problem` ("found character '\t' that
        # cannot start any token") and `context` ("while scanning for the next
        # token"). Together they read as one sentence; separately, the context
        # is not actionable enough to be a hint.
        problem = error.problem or "could not parse YAML"
        if error.context:
            problem = f"{problem}, {error.context}"
        raise ConfigError(problem, source=source, line=line, column=column) from error
    except yaml.YAMLError as error:
        raise ConfigError(f"could not parse YAML: {error}", source=source) from error
