"""The codes the config layer's warnings carry (``01-configuration.md`` §10, J3).

Declared here rather than in :mod:`sopuli.diagnostics`, which is where the
registry of what each code *means* lives, because the config layer may not
import that module: it reaches into :mod:`sopuli.output` and :mod:`sopuli.lock`,
and ``04-testing.md`` §4 keeps this layer free of both. The registry imports
these names instead, so the dependency points the way the architecture does and
each code still has exactly one definition.

This module imports nothing, so the registry can read the codes without loading
the config builder.
"""

#: A store in this file does not verify the certificate it is offered (§3a).
UNVERIFIED_TRANSPORT = "SOPULI-W004"

#: Retired: a policy's `rotation:` or `verify:` block set keys that no run read.
#: The blocks were removed (#787), so nothing emits it. Kept so that the number
#: is never given to another warning.
UNREAD_POLICY_KEYS = "SOPULI-W034"

#: `delivery.method` names a method this build cannot deliver with.
DELIVERY_UNSERVICEABLE = "SOPULI-W035"

#: `delivery.notify.method` names a channel this build cannot send through: one
#: with no code in this build, or one whose client is not installed. One code
#: for both, as `SOPULI-W003` is one code for a store: they are one outage, and
#: the message carries the remedy.
NOTIFY_UNSERVICEABLE = "SOPULI-W036"

#: A profile is named after an environment that a target declares, so
#: `--profile <name>` reads as selecting targets and selects none.
PROFILE_NAMED_AFTER_ENVIRONMENT = "SOPULI-W037"

#: A third-party store variable, such as ``VAULT_ADDR``, is set and was not
#: applied, because the run has no default store to apply it to. One code
#: whether no layer names a default store or the one named is not declared:
#: either way the variable was ignored, and the message and hint say which case
#: it is and what to change.
THIRD_PARTY_VARIABLE_UNAPPLIED = "SOPULI-W038"

#: A layer asked to relax a safety setting, and the ratchet held (invariant 10).
#: The config layer raises it while it merges a store's ``tls:`` block, and
#: ``config explain`` for every other safety setting. One code for all of them,
#: because :func:`sopuli.settings.ratchet_note` writes each message and names
#: the setting.
RELAXATION_DEFEATED = "SOPULI-W039"

#: ``VAULT_ADDR`` gives a store a different address from the one the file
#: declares for it (#865). P3 lets the variable win, so the run goes to that
#: address. Only the third-party variable warns: ``SOPULI_VAULT_ADDR`` and
#: ``--vault-addr`` were set for this tool.
THIRD_PARTY_ADDR_OVERRIDES = "SOPULI-W051"

#: ``VAULT_NAMESPACE`` gives a store a different namespace from the one the file
#: declares for it (#892). P3 lets the variable win, so the run logs in and
#: writes in that namespace. A code of its own rather than a widening of
#: :data:`THIRD_PARTY_ADDR_OVERRIDES`, whose registered description names the
#: address.
THIRD_PARTY_NAMESPACE_OVERRIDES = "SOPULI-W052"
