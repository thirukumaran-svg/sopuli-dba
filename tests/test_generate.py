"""What `creds generate` decides before it writes (#254).

Pure: which policy governs an account, what its candidate is, and which accounts
share a write. The write itself is `tests/test_cli_creds_generate.py`.

The property that carries most of this file is that **a document is the unit of
the write**. Q7 (#85) made one secret per application the default, so the shared
case is the ordinary one, and getting it wrong means either three versions where
one was intended or three accounts sharing one password.
"""

from __future__ import annotations

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

    Two root keys since #311, not one: the staged value and the `origin`
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
    """#311's default case, and the one #312 is allowed to redraw."""
    writes = generate.group(candidates(estate()))

    assert writes[0].patch(stage=PENDING)[ORIGIN] == {"acme_web_user": GENERATED}


def test_a_supplied_password_is_staged_as_supplied() -> None:
    """`--from-stdin`, and the reason the key exists at all. An external system
    dictated this value, so #312 redrawing it would make the tool disagree with
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
    is not a thing #312 may redraw -- so the key is absent, and absent already
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
    second account shares the document.

    Found by writing the first real staging run: the merge kept whichever came
    last, which would have given one account's password to both and lost the
    other's. **#255 moved the refusal to load time**, so a file spelled this way
    no longer reaches here -- `tests/config/test_stage_collisions.py` is where
    that is tested now.

    This guard stays, and is exercised on bindings built directly, because the
    load-time check can only fire where the store is known: a binding whose
    `vault` C15 (#118) completes later from a profile or `SOPULI_VAULT` has no
    backend at load, so whether the rule applies is not knowable from the file.
    Those arrive here unchecked.
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


# ------------------------------------------------------- estate limits (#317) ---
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
    the target will not accept" half of what #317 is for.
    """
    with pytest.raises(ConfigError):
        generate.candidate_for(
            BINDING, WIDE, name="p", limits=(UNICODE, WESTERN), supplied=Secret("ab中z")
        )


def test_the_same_password_is_accepted_where_every_target_can_hold_it() -> None:
    """The control, so the test above is measuring the character set and not the
    password."""
    found = generate.candidate_for(
        BINDING, WIDE, name="p", limits=(UNICODE,), supplied=Secret("ab中z")
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
        limits=(LEGACY, WESTERN, UNICODE),
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

    found = generate.candidate_for(BINDING, policy, name="p", limits=(UNICODE, WESTERN))

    assert len(found.value.reveal()) == 40


def test_a_drawn_password_is_refused_where_no_target_can_hold_it() -> None:
    """The refusal #317 moves from `apply` to here, at the pure layer."""
    policy = PasswordPolicy(length=40, charset="alnum", first_char="alpha")

    with pytest.raises(PasswordPolicyError):
        generate.candidate_for(BINDING, policy, name="p", limits=(UNICODE, LEGACY))
