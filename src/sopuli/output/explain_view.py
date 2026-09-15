"""``config show --explain`` -- every effective setting, and where it came from.

P3 calls this "making precedence debuggable" and gives the format:

    vault.addr         = https://vault.example.com:8200   [env SOPULI_VAULT_ADDR]
    verify.method      = hash                             [profile ci]
    safety.max_targets = 1                                [defaults]
                         profile ci asked for 200; safety only ratchets toward safe

The last line is the one worth being able to see. A setting that was *requested*
and did not win is invisible in the result and obvious here, which is the
difference between "the ratchet works" as a claim and as something an operator
can check.

A view over :mod:`sopuli.settings`, and nothing more: it renders
:class:`~sopuli.settings.resolver.Resolved` values that the resolver produced and
decides nothing about precedence itself. That is also what makes it testable
against settings the tool cannot yet supply -- a secret-valued one, or a profile
that tried to relax a ratchet -- which is most of them today.

Three rendering rules are decisions rather than layout:

**The source is named, not just the layer.** ``env SOPULI_DRY_RUN``, never
``env``. The point of the view is to send somebody to the thing they have to
change, in their own environment or their own file, which is the same reason
``source_detail`` exists in the JSON contract. A built-in default has nowhere to
point at, so it says so.

**Values render through the resolver's own** :func:`~sopuli.settings.resolver.render_value`,
so a value in the table and the same value quoted in a ratchet note three lines
below it cannot be spelled differently. It writes booleans the way YAML does, and
a :class:`~sopuli.secrets.Secret` prints ``***`` because that is what the type
does (invariant 2) -- this module handles secrets correctly by not knowing they
exist, which is what keeps it from forgetting one.

**Laid out by hand rather than through :mod:`sopuli.output.table`.** Two reasons,
and the second is the real one: a truncated ``SOPULI_...`` variable name is
useless in exactly the moment this view exists for, and the ratchet note is a
*continuation* of the row above it, which a column layout has no shape for.
"""

from __future__ import annotations

from collections.abc import Mapping

from sopuli.output.document import Diagnostic
from sopuli.output.palette import Role, paint
from sopuli.settings import Layer, Resolved, ratchet_note, render_value

#: What a built-in default calls itself. P3's own wording, and it reads as an
#: answer rather than as a missing source -- which is what it is: nothing else
#: spoke.
BUILT_IN = "built-in default"


def render_settings(resolved: Mapping[str, Resolved]) -> list[str]:
    """The settings table, one row per setting, in name order.

    Empty when nothing was resolved, so a caller can append it unconditionally
    and get no heading over an empty section.
    """
    if not resolved:
        return []

    rows = [
        (name, render_value(resolved[name].value), _source(resolved[name]))
        for name in sorted(resolved)
    ]
    name_width = max(len(name) for name, _, _ in rows)
    value_width = max(len(value) for _, value, _ in rows)

    lines = []
    for name, value, source in rows:
        lines.append(f"  {name:<{name_width}} = {value:<{value_width}}  [{source}]")
        note = ratchet_note(resolved[name])
        if note is not None:
            # Under the value, as P3 draws it: the note is about this row, and a
            # line starting at column zero would read as a new one.
            lines.append(f"  {'':<{name_width}}   {note}")
    return lines


def ratchet_notes(resolved: Mapping[str, Resolved]) -> list[Diagnostic]:
    """Defeated relaxations, as run-level diagnostics.

    ``03-json-output.md`` §``invocation.options`` says a request that lost to the
    ratchet "appears in ``diagnostics[]`` as a warning naming both ends". That is
    true of every run rather than only of ``--explain`` runs, so the caller for
    this is the boundary that opens the document, not this view.

    A warning rather than an error: nothing failed. Something was asked for and
    safely refused, and the run continues -- which is precisely the case that is
    invisible without being said out loud.
    """
    notes = []
    for name in sorted(resolved):
        note = ratchet_note(resolved[name])
        if note is not None:
            notes.append(Diagnostic(level="warning", message=note))
    return notes


def section(resolved: Mapping[str, Resolved]) -> list[str]:
    """The rendered table under its heading, or nothing at all."""
    lines = render_settings(resolved)
    return ["", paint("settings", Role.HEADING), *lines] if lines else []


def _source(answer: Resolved) -> str:
    """Where the value came from, as specifically as the layer allows.

    ``env SOPULI_DRY_RUN`` rather than ``env``: the layer alone answers "which
    rule applied", and the question this view exists for is "what do I edit".
    """
    if answer.layer is Layer.BUILTIN:
        return BUILT_IN
    if answer.detail is None:
        # A layer that supplied no location. Nothing produces this today -- every
        # source names itself -- and the layer is still a better answer than an
        # empty bracket if one ever does.
        return str(answer.layer)
    if answer.layer is Layer.OBJECT:
        # The same rule as below and it cannot be reached by matching, because
        # the section a named object lives in is not named after the layer:
        # `vaults.vault-dev.addr` is a key path into the file and "object" is
        # this chain's word for its rank, which appears in nobody's YAML. P3
        # calls the layer "target/vault-level setting", and the path already says
        # which one and where.
        return answer.detail
    if answer.detail.split(".", 1)[0].startswith(str(answer.layer)):
        # `defaults defaults.safety.readonly` says it twice. A config key path
        # already begins with the section it lives in, so the layer word adds
        # nothing; `env SOPULI_DRY_RUN` is the case where it does.
        #
        # Matched on the *first segment*, and by prefix within it, because the
        # section a profile lives in is the layer word pluralised:
        # `profiles.ci.output` says "profile" as plainly as `defaults.…` says
        # "defaults". Against the whole string this would also fire on any detail
        # that merely began with a layer's name, which is a coincidence rather
        # than a repetition.
        return answer.detail
    return f"{answer.layer} {answer.detail}"
