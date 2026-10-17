"""What `creds generate` decides before it writes.

Pure: which policy governs an account, what its candidate is, and which accounts
share a write. The write itself is `tests/test_cli_creds_generate.py`.

The property that carries most of this file is that **a document is the unit of
the write**. Q7 makes one secret per application the default, so the shared
case is the ordinary one, and getting it wrong means either three versions where
one was intended or three accounts sharing one password.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from sopuli import generate
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Binding, Config, PasswordPolicy
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.passwords import ByteLimit, PasswordPolicyError
from sopuli.payload import CURRENT, GENERATED, ORIGIN, PENDING, SUPPLIED
from sopuli.secrets import Secret

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp"}}

POLICIES: dict[str, Any] = {
    "app-standard": {"password": {"length": 24, "charset": "alnum", "first_char": "alpha"}},
    "app-short": {"password": {"length": 8, "charset": "alnum"}},
}


def estate(
    *,
    accounts: list[str] | None = None,
    template: str = "apps/acme/db#DB_CREDENTIALS/{account}",
    policy: str | None = None,
    defaults: dict[str, Any] | None = None,
    policies: dict[str, Any] | None = None,
) -> Config:
    application: dict[str, Any] = {
        "name": "acme",
        "targets": ["plain"],
        "accounts": accounts or ["acme_web_user"],
        "secret_template": template,
    }
    if policy is not None:
        application["policy"] = policy
    document: dict[str, Any] = {
        "version": 1,
        "vaults": VAULTS,
        "policies": POLICIES if policies is None else policies,
        "targets": [{"name": "plain", "type": "oracle", "dsn": "h:1521/x", "vault": "vault-dev"}],
        "applications": [application],
        "defaults": defaults if defaults is not None else {"policy": "app-standard"},
    }
    return build_config(document)


def candidates(config: Config) -> list[generate.Candidate]:
    out = []
    for binding in config.bindings:
        name, policy = generate.policy_for(config, binding)
        out.append(generate.candidate_for(binding, policy, name=name))
    return out


# ------------------------------------------------------------- the policy ---


def test_the_binding_s_own_policy_wins_over_the_default() -> None:
    """§3's chain, and the same one `bindings.py` walks."""
    config = estate(policy="app-short")

    name, policy = generate.policy_for(config, config.bindings[0])

    assert name == "app-short"
    assert policy.length == 8


def test_defaults_policy_applies_where_the_entry_names_none() -> None:
    config = estate()

    name, _ = generate.policy_for(config, config.bindings[0])

    assert name == "app-standard"


def test_no_policy_anywhere_is_refused_rather_than_defaulted() -> None:
    """§8: a policy declaring no `length` is refused rather than given one the
    tool chose, and having no policy at all is the same argument one level up --
    there is no safe length to invent."""
    config = estate(defaults={})

    with pytest.raises(ConfigError, match="no password policy"):
        generate.policy_for(config, config.bindings[0])


def test_a_policy_name_that_names_nothing_is_refused() -> None:
    config = estate(defaults={"policy": "app-standard"})
    binding = Binding(account="a", target="plain", secret=None, vault="vault-dev", policy="nosuch")

    with pytest.raises(ConfigError, match="no policy named 'nosuch'"):
        generate.policy_for(config, binding)


# ---------------------------------------------------------- the candidate ---


def test_a_generated_password_satisfies_its_policy() -> None:
    config = estate()
    name, policy = generate.policy_for(config, config.bindings[0])

    candidate = generate.candidate_for(config.bindings[0], policy, name=name)

    assert len(candidate.value.reveal()) == 24
    assert candidate.supplied is False
    assert candidate.accepted_violations == ()


def test_each_account_is_drawn_separately() -> None:
    """Sharing a document is a storage layout, not a shared credential: two
    accounts written together must not end up with one password."""
    drawn = candidates(estate(accounts=["acme_web_user", "acme_batch_user"]))

    assert len({one.value.reveal() for one in drawn}) == 2


def two_targets(template: str) -> Config:
    """`acme_web_user` on two targets in one store, under one policy."""
    return build_config(
        {
            "version": 1,
            "vaults": VAULTS,
            "policies": POLICIES,
            "defaults": {"policy": "app-standard"},
            "targets": [
                {"name": name, "type": "oracle", "dsn": "h:1521/x", "vault": "vault-dev"}
                for name in ("acme-alpha", "acme-beta")
            ],
            "applications": [
                {
                    "name": "acme",
                    "targets": ["acme-alpha", "acme-beta"],
                    "accounts": ["acme_web_user"],
                    "secret_template": template,
                }
            ],
        }
    )


def draw(config: Config) -> generate.DrawFunction:
    def one(binding: Binding) -> generate.Candidate:
        name, policy = generate.policy_for(config, binding)
        return generate.candidate_for(binding, policy, name=name)

    return one


def test_one_password_on_two_targets_is_drawn_once() -> None:
    """The ref names no target, so both bindings are one password. Each keeps
    its own candidate, for its own result, and both hold the one value (#830)."""
    config = two_targets("acme/prod/shared#DB_CREDENTIALS/{account}")
    calls: list[str] = []

    def counted(binding: Binding) -> generate.Candidate:
        calls.append(binding.target)
        return draw(config)(binding)

    drawn = generate.draw_once(config.bindings, counted)

    assert calls == ["acme-alpha"]
    assert [one.binding.target for one in drawn] == ["acme-alpha", "acme-beta"]
    assert drawn[0].value is drawn[1].value


def test_a_password_per_target_is_drawn_per_target() -> None:
    config = two_targets("acme/{target}#DB_CREDENTIALS/{account}")

    drawn = generate.draw_once(config.bindings, draw(config))

    assert drawn[0].value.reveal() != drawn[1].value.reveal()


def test_a_shared_password_is_drawn_once_whatever_its_bindings_policies() -> None:
    """The key is the password alone. The loader refuses two policies on one
    password (#830); were they to get here, one value still beats two values
    for one field."""
    config = two_targets("acme/prod/shared#DB_CREDENTIALS/{account}")
    alpha, beta = config.bindings
    calls: list[str] = []

    def counted(binding: Binding) -> generate.Candidate:
        calls.append(binding.target)
        return draw(config)(binding)

    generate.draw_once([alpha, replace(beta, policy="app-short")], counted)

    assert calls == ["acme-alpha"]


def test_two_values_for_one_password_are_refused_rather_than_merged() -> None:
    """A draw site that skips `draw_once` would put two values in one field,
    and the merge would keep the last. `group` refuses it."""
    config = two_targets("acme/prod/shared#DB_CREDENTIALS/{account}")
    separately = [draw(config)(binding) for binding in config.bindings]

    with pytest.raises(ValueError, match="two different passwords for 'acme_web_user'"):
        generate.group(separately)


def test_a_shared_password_is_one_account_in_its_write_and_one_draw_to_report() -> None:
    config = two_targets("acme/prod/shared#DB_CREDENTIALS/{account}")
    drawn = generate.draw_once(config.bindings, draw(config))

    (write,) = generate.group(drawn)

    assert write.accounts == ("acme_web_user",)
    assert [one.binding.target for one in generate.one_per_password(drawn)] == ["acme-alpha"]


def test_a_supplied_password_goes_through_the_same_predicate() -> None:
    """UC-1 §4, and what stops `--from-stdin` becoming a way to write a password
    the policy would have refused."""
    config = estate()
    name, policy = generate.policy_for(config, config.bindings[0])

    with pytest.raises(PasswordPolicyError, match="violates policy"):
        generate.candidate_for(config.bindings[0], policy, name=name, supplied=Secret("short"))


def test_a_supplied_password_may_be_longer_than_the_policy_length() -> None:
    """`length:` is a minimum for a supplied password: one an external system
    dictated is not weaker for being longer. `generate` produces exactly the
    length because it is choosing, not because the rule differs."""
    config = estate()
    name, policy = generate.policy_for(config, config.bindings[0])

    candidate = generate.candidate_for(
        config.bindings[0], policy, name=name, supplied=Secret("A" * 40)
    )

    assert candidate.supplied is True
    assert candidate.accepted_violations == ()


def test_no_policy_check_accepts_and_records_what_it_accepted() -> None:
    """§4 requires the override in the audit event, and "the flag was passed"
    does not say what it let through."""
    config = estate()
    name, policy = generate.policy_for(config, config.bindings[0])

    candidate = generate.candidate_for(
        config.bindings[0], policy, name=name, supplied=Secret("short"), enforce=False
    )

    assert candidate.supplied is True
    assert [one.rule for one in candidate.accepted_violations]


def test_no_policy_check_does_not_loosen_a_generated_password() -> None:
    """There is nothing to override when the tool drew the value itself, and a
    flag that silently changed the generator would be a different feature."""
    config = estate()
    name, policy = generate.policy_for(config, config.bindings[0])

    candidate = generate.candidate_for(config.bindings[0], policy, name=name, enforce=False)

    assert candidate.accepted_violations == ()
    assert len(candidate.value.reveal()) == 24


# -------------------------------------------------------------- the write ---


def test_accounts_sharing_a_document_are_one_write() -> None:
    """Q7's default layout. Three writes would be three versions, two of which
    describe states nobody intended."""
    writes = generate.group(candidates(estate(accounts=["acme_web_user", "acme_batch_user"])))

    assert len(writes) == 1
    assert writes[0].accounts == ("acme_web_user", "acme_batch_user")


def test_separate_documents_are_separate_writes() -> None:
    writes = generate.group(
        candidates(
            estate(
                accounts=["acme_web_user", "acme_batch_user"],
                template="apps/acme/{account}#password",
            )
        )
    )

    assert len(writes) == 2


def test_the_write_key_is_the_lock_key() -> None:
    """ "Shares a document", "shares a write" and "shares a lock" must not give
    three answers -- the path goes through the same normaliser."""
    writes = generate.group(candidates(estate(template="/apps/acme//db#DB_CREDENTIALS/{account}")))

    assert writes[0].key.path == "apps/acme/db"
    assert writes[0].key.store == "vault-dev"


def test_one_patch_carries_every_account_and_nothing_else() -> None:
    """The merge has to preserve what `staged_patch` guarantees per account:
    every sibling absent rather than rewritten with what was last read.

    There are two root keys, not one: the staged value and the `origin`
    describing it. Both are keyed by account under the same mirror rule, and the
    assertion that matters is unchanged -- nothing here names an account this run
    did not come for.
    """
    writes = generate.group(candidates(estate(accounts=["acme_web_user", "acme_batch_user"])))

    patch = writes[0].patch(stage=PENDING)

    assert set(patch) == {PENDING, ORIGIN}
    assert set(patch[PENDING]) == {"acme_web_user", "acme_batch_user"}
    assert set(patch[ORIGIN]) == {"acme_web_user", "acme_batch_user"}


# ------------------------------------------------------------- the origin ---


def test_a_drawn_password_is_staged_as_generated() -> None:
    """The default case, and the one `apply` is allowed to redraw."""
    writes = generate.group(candidates(estate()))

    assert writes[0].patch(stage=PENDING)[ORIGIN] == {"acme_web_user": GENERATED}


def test_a_supplied_password_is_staged_as_supplied() -> None:
    """`--from-stdin`, and the reason the key exists at all. An external system
    dictated this value, so `apply` redrawing it would make the tool disagree with
    whoever owns it -- and `Candidate.supplied` dies at the process boundary, so
    the document is the only place a later `apply` can learn this."""
    config = estate()
    binding = config.bindings[0]
    name, policy = generate.policy_for(config, binding)
    supplied = generate.candidate_for(
        binding, policy, name=name, supplied=Secret("Dictated1234567890abcdef")
    )

    writes = generate.group([supplied])

    assert writes[0].patch(stage=PENDING)[ORIGIN] == {"acme_web_user": SUPPLIED}


def test_the_origin_is_keyed_the_way_the_value_is() -> None:
    """The mirror rule, applied to a key that is not a stage and not a stamp: in
    the one-account layout it is a scalar at the root, and in the shared layout a
    map keyed by account. If those ever needed separate code the rule would have
    stopped covering it."""
    own = generate.group(candidates(estate(template="apps/acme/{account}#password")))
    shared = generate.group(candidates(estate()))

    assert own[0].patch(stage=PENDING)[ORIGIN] == GENERATED
    assert shared[0].patch(stage=PENDING)[ORIGIN] == {"acme_web_user": GENERATED}


def test_each_account_carries_its_own_origin_in_a_shared_document() -> None:
    """One drawn, one supplied, one document, one write. A single root-level
    `origin` would describe some of the document and not the rest -- the same
    reason UC-1 §3's stamps are per account."""
    config = estate(accounts=["acme_web_user", "acme_batch_user"])
    drawn, dictated = config.bindings
    name, policy = generate.policy_for(config, drawn)

    writes = generate.group(
        [
            generate.candidate_for(drawn, policy, name=name),
            generate.candidate_for(
                dictated, policy, name=name, supplied=Secret("Dictated1234567890abcdef")
            ),
        ]
    )

    assert writes[0].patch(stage=PENDING)[ORIGIN] == {
        "acme_web_user": GENERATED,
        "acme_batch_user": SUPPLIED,
    }


def test_nothing_written_straight_to_current_carries_an_origin() -> None:
    """`origin` describes what `pending` holds. A value going into `current` has
    nothing staged for it to describe, and what applications are already holding
    is not a thing `apply` may redraw -- so the key is absent, and absent already
    reads as *not safe to redraw*."""
    writes = generate.group(candidates(estate()))

    assert ORIGIN not in writes[0].patch(stage=CURRENT)


def test_the_origin_is_not_a_secret_and_is_not_wrapped() -> None:
    """It is a two-word vocabulary, not a value: it must survive
    `_plaintext` unchanged and be readable in a plan without a reveal."""
    patch = generate.group(candidates(estate()))[0].patch(stage=PENDING)

    assert patch[ORIGIN]["acme_web_user"] in (GENERATED, SUPPLIED)
    assert GENERATED in repr(patch)


def test_the_patch_stages_into_pending_not_current() -> None:
    """Invariant 7's ordering starts here: nothing reaches `current` until every
    target has confirmed."""
    writes = generate.group(candidates(estate()))

    assert "current" not in writes[0].patch(stage=PENDING)


def test_the_patch_never_reveals_a_password() -> None:
    """Values stay `Secret` all the way to `apply_patch`, which holds the one
    permitted unwrapping on this path (invariant 2)."""
    writes = generate.group(candidates(estate()))
    patch = writes[0].patch(stage=PENDING)

    assert all(isinstance(value, Secret) for value in patch[PENDING].values())
    assert "***" in repr(patch)


def test_a_binding_with_no_ref_is_refused_rather_than_dropped() -> None:
    """Silently generating a password that lands nowhere is the failure mode
    worth being loud about."""
    config = estate()
    name, policy = generate.policy_for(config, config.bindings[0])
    orphan = generate.candidate_for(
        Binding(account="a", target="plain", secret=None, vault="vault-dev"), policy, name=name
    )

    with pytest.raises(ValueError, match="names no secret ref"):
        generate.group([orphan])


def test_two_accounts_staging_into_one_place_are_refused() -> None:
    """`path#{account}` gives each account a root *field* and no pointer, so
    `stage_layout` puts the stage at the document root -- correct for the
    one-account layout UC-1 §3 describes, and a silent overwrite the moment a
    second account shares the document. The merge would keep whichever came
    last, which would give one account's password to both and lose the other's.

    The load-time check refuses a file spelled this way, so it does not reach
    here -- `tests/config/test_stage_collisions.py` tests that.

    This guard is exercised on bindings built directly, because the load-time
    check can only fire where the store is known: a binding whose `vault` (C15)
    is completed later from a profile or `SOPULI_VAULT` has no backend at load,
    so whether the rule applies is not knowable from the file. Those arrive here
    unchecked.
    """
    config = estate()
    name, policy = generate.policy_for(config, config.bindings[0])
    ref = parse_secret_ref("apps/acme/db#DB_CREDENTIALS")
    drawn = [
        generate.candidate_for(
            Binding(account=account, target="plain", secret=ref, vault="vault-dev"),
            policy,
            name=name,
        )
        for account in ("acme_web_user", "acme_batch_user")
    ]

    with pytest.raises(ValueError, match="would both stage into"):
        generate.group(drawn)


def test_one_account_per_document_at_the_root_is_still_fine() -> None:
    """The layout that is *correct* at the root: one account, so nothing to
    collide with. Refusing this would reject UC-1 §3's own worked payload."""
    writes = generate.group(candidates(estate(template="apps/acme/{account}#password")))

    assert len(writes) == 1
    assert writes[0].patch(stage=PENDING) == {
        PENDING: writes[0].candidates[0].value,
        ORIGIN: GENERATED,
    }


# -------------------------------------------------------------- estate limits ---
#
# `limits` is every answered target's, and the two paths use it differently: a
# drawn password is ASCII by §8 so only the count can bind it, while a supplied
# one has to satisfy every target it will be applied to.

BINDING = Binding(account="acme_web_user", target="appdb-alpha")

#: A policy whose alphabet reaches outside every single-byte character set, so
#: the only thing that can refuse ``ab中z`` is the *target's* encoding.
WIDE = PasswordPolicy(length=4, charset="custom", allow="abz中", first_char="alpha")

WESTERN = ByteLimit(max_bytes=128, encoding="cp1252", charset="WE8MSWIN1252")
UNICODE = ByteLimit(max_bytes=128, encoding="utf-8", charset="AL32UTF8")
LEGACY = ByteLimit(max_bytes=30, encoding="ascii", charset="US7ASCII")


def test_a_supplied_password_must_satisfy_every_target_not_the_smallest() -> None:
    """The failure a single "strictest" limit lets through.

    ``中`` is three bytes in ``AL32UTF8`` and cannot be encoded in
    ``WE8MSWIN1252`` at all. Both targets declare 128 bytes, so no comparison of
    counts distinguishes them, and validating against either one alone accepts a
    password the other deterministically cannot store -- which is the "characters
    the target will not accept" half of what the estate limits are for.
    """
    with pytest.raises(ConfigError):
        generate.candidate_for(
            BINDING,
            WIDE,
            name="p",
            readings=(
                ("unicode", UNICODE),
                ("western", WESTERN),
            ),
            supplied=Secret("ab中z"),
        )


def test_the_same_password_is_accepted_where_every_target_can_hold_it() -> None:
    """The control, so the test above is measuring the character set and not the
    password."""
    found = generate.candidate_for(
        BINDING, WIDE, name="p", readings=(("unicode", UNICODE),), supplied=Secret("ab中z")
    )

    assert found.supplied is True


def test_one_violation_is_reported_once_however_many_targets_report_it() -> None:
    """Checking per limit re-runs the policy half, and a reader should not see
    the same problem three times because three databases agreed about it."""
    policy = PasswordPolicy(length=40, charset="alnum", first_char="alpha")
    found = generate.candidate_for(
        BINDING,
        policy,
        name="p",
        readings=(
            ("legacy", LEGACY),
            ("western", WESTERN),
            ("unicode", UNICODE),
        ),
        supplied=Secret("short"),
        enforce=False,
    )

    rules = [violation.rule for violation in found.accepted_violations]
    assert len(rules) == len(set(rules)), rules


def test_a_drawn_password_is_bound_by_the_count_and_not_the_encoding() -> None:
    """Both targets hold 128 bytes and §8's alphabet is ASCII, so a 40-character
    policy is satisfiable -- and would not be if the encoding were folded into
    the comparison."""
    policy = PasswordPolicy(length=40, charset="alnum", first_char="alpha")

    found = generate.candidate_for(
        BINDING,
        policy,
        name="p",
        readings=(
            ("unicode", UNICODE),
            ("western", WESTERN),
        ),
    )

    assert len(found.value.reveal()) == 40


def test_a_drawn_password_is_refused_where_no_target_can_hold_it() -> None:
    """The refusal belongs here, at the pure layer, and not in `apply`."""
    policy = PasswordPolicy(length=40, charset="alnum", first_char="alpha")

    with pytest.raises(PasswordPolicyError):
        generate.candidate_for(
            BINDING,
            policy,
            name="p",
            readings=(
                ("unicode", UNICODE),
                ("legacy", LEGACY),
            ),
        )


def test_a_drawn_refusal_names_the_target_whose_limit_governed() -> None:
    """Invariant 4 asks for the capability *and the target*. In an estate
    "the target's limit" could be any of them, so the message names the one the
    draw was bound by -- and its hint points there too."""
    policy = PasswordPolicy(length=40, charset="alnum", first_char="alpha")

    with pytest.raises(PasswordPolicyError) as caught:
        generate.candidate_for(
            BINDING,
            policy,
            name="p",
            readings=(("db-unicode", UNICODE), ("db-legacy", LEGACY)),
        )

    assert "the limit on 'db-legacy' is 30" in str(caught.value)
    assert "for 'db-legacy'" in (caught.value.hint or "")


def test_a_drawn_refusal_names_the_first_of_equally_strict_targets() -> None:
    """Ties keep the first reading, as `strictest_target` does, so the refusal and
    the constraint line name the same target."""
    policy = PasswordPolicy(length=40, charset="alnum", first_char="alpha")

    with pytest.raises(PasswordPolicyError) as caught:
        generate.candidate_for(
            BINDING,
            policy,
            name="p",
            readings=(("db-unicode", UNICODE), ("db-one", LEGACY), ("db-two", LEGACY)),
        )

    assert "'db-one'" in str(caught.value)
    assert "'db-two'" not in str(caught.value)


def test_a_supplied_password_names_each_target_that_refuses_it() -> None:
    """`--from-stdin` is checked against every target's limit, so each violation
    says which target it came from -- and two targets refusing it are two
    violations, not one merged into "the target"."""
    policy = PasswordPolicy(length=4, charset="custom", allow="abz中", first_char="alpha")
    narrow = ByteLimit(max_bytes=4, encoding="utf-8", charset="AL32UTF8")

    found = generate.candidate_for(
        BINDING,
        policy,
        name="p",
        readings=(("db-western", WESTERN), ("db-narrow", narrow), ("db-unicode", UNICODE)),
        supplied=Secret("ab中z"),
        enforce=False,
    )

    details = [violation.detail for violation in found.accepted_violations]
    assert details == [
        "cannot be represented in cp1252 on 'db-western'",
        "is 6 bytes in utf-8, the limit on 'db-narrow' is 4",
    ]
