"""The one rule that covers both of Q7's layouts.

The point of the mirror rule is that the per-account and per-application layouts
are the *same* arithmetic with a different container, so most of what follows is
the same assertion made twice -- once against `#password` and once against
`#DB_CREDENTIALS/{account}` -- and would be uninteresting if the two ever needed
separate code.

The other half is about not touching what was not selected. A patch that names a
sibling is indistinguishable from a correct one until two accounts share a
document, at which point it silently rewrites a credential nobody asked about.
So the assertions are on what a patch *omits*.
"""

from __future__ import annotations

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.payload import (
    CURRENT,
    GENERATED,
    ORIGIN,
    PENDING,
    PREVIOUS,
    REMOVE,
    RESERVED,
    StageLayout,
    apply_patch,
    merge,
    stage_layout,
)
from sopuli.secrets import Secret

#: One account per secret -- UC-1 §3's original payload.
OWN = "apps/orders/prod/db/creds#password"
#: One secret per application -- the Q7 default, already in `01-configuration.md` §2.
SHARED = "tenants/beta#DB_CREDENTIALS/acme_web_user"


def layout(text: str) -> StageLayout:
    return stage_layout(parse_secret_ref(text))


def test_a_field_is_the_container_and_a_pointer_is_what_lies_below_it() -> None:
    assert layout(OWN) == StageLayout(container="password")
    assert layout(SHARED) == StageLayout(container="DB_CREDENTIALS", within=("acme_web_user",))


@pytest.mark.parametrize("ref", [OWN, SHARED], ids=["own", "shared"])
@pytest.mark.parametrize("stage", [PENDING, PREVIOUS, "rotated_at", "targets"])
def test_every_root_key_mirrors_the_container(ref: str, stage: str) -> None:
    """The rule itself: swap the root key, keep the pointer."""
    at = layout(ref)
    assert at.location(stage) == (stage, *at.location(CURRENT)[1:])


def test_the_current_stage_has_no_root_key_of_its_own() -> None:
    """`current` is where the ref already points, which is why it is not reserved."""
    assert layout(SHARED).location(CURRENT) == ("DB_CREDENTIALS", "acme_web_user")
    assert layout("tenants/beta#current/acme_web_user").container == "current"


def test_a_pointer_of_several_segments_mirrors_whole() -> None:
    at = layout("tenants/beta#creds/oracle/acme_web_user")
    assert at.location(PENDING) == (PENDING, "oracle", "acme_web_user")


def test_an_escaped_pointer_segment_is_one_key() -> None:
    """RFC 6901: `a~1b` is the single key `a/b`, not two levels of document."""
    assert layout("tenants/beta#creds/acme~1web").location(CURRENT) == ("creds", "acme/web")


class TestReading:
    document = {
        "DB_CREDENTIALS": {"acme_web_user": "w", "acme_api_user": "a"},
        "pending": {"acme_api_user": "staged"},
        "settings": {"pool_size": 8},
    }

    def test_it_reads_through_the_container(self) -> None:
        assert layout(SHARED).read(self.document) == "w"

    @pytest.mark.parametrize(
        "document",
        [None, {}, {"pending": {}}, {"pending": {"acme_api_user": "someone else's"}}],
        ids=["no document", "empty document", "no account staged", "another account staged"],
    )
    def test_nothing_staged_here_is_one_answer(self, document: dict[str, object] | None) -> None:
        """Four states that differ, and mean the same thing to UC-1 §3's model.

        `None` is what the store returns for a path with nothing at it, which is
        the first rotation rather than a failure -- so it arrives here as itself
        rather than as an `or {}` somebody wrote at a call site.
        """
        assert layout(SHARED).read(document, PENDING) is None

    def test_an_emptied_container_reads_as_nothing_staged(self) -> None:
        """What a promotion actually leaves behind, asserted end to end.

        RFC 7396 deletes the *key named in the patch*, and a patch built by the
        mirror rule names an account inside a container -- so promoting the last
        staged account empties `pending` and `origin` rather than removing them,
        and promoting an account whose document has no `origin` creates an empty
        `origin` on the way past. The same is true of `pending`.

        It stays that way. The alternatives are both worse: pruning empty maps
        locally would make this module's RFC 7396 disagree with the one Vault
        runs server-side -- `store/credentials.py` picks between them per store
        and says in its own docstring that two implementations which had to agree
        would be a bug waiting -- and deleting at the root instead would clobber a
        concurrent writer's account, which is the one thing the mirror rule's
        "siblings absent" property exists to prevent.

        So the empty container is pinned here rather than tidied: `read` gives
        UC-1 §3's "there is nothing staged here", which is the answer every caller
        acts on, and no caller distinguishes an absent key from an emptied one.
        """
        promoted = apply_patch(
            {
                "DB_CREDENTIALS": {"acme_web_user": "old"},
                "pending": {"acme_web_user": "new"},
                "origin": {"acme_web_user": GENERATED},
            },
            merge(
                layout(SHARED).patch(CURRENT, "new"),
                layout(SHARED).patch(PENDING, REMOVE),
                layout(SHARED).patch(ORIGIN, REMOVE),
            ),
        )

        assert promoted["pending"] == {}
        assert promoted["origin"] == {}
        assert layout(SHARED).read(promoted, PENDING) is None
        assert layout(SHARED).read(promoted, ORIGIN) is None

    def test_a_scalar_where_a_container_was_expected_reads_as_absent(self) -> None:
        """A malformed document is not a crash: `check` has to be able to report it."""
        assert layout(SHARED).read({"DB_CREDENTIALS": "not a map"}) is None

    def test_the_neighbours_are_who_a_write_would_sit_next_to(self) -> None:
        assert layout(SHARED).accounts(self.document) == ("acme_api_user", "acme_web_user")

    def test_an_unaddressed_layout_has_no_neighbours(self) -> None:
        """One account per secret: there is no container to look inside."""
        assert layout(OWN).accounts({"password": "w"}) == ()
        assert layout(OWN).is_addressed is False

    def test_a_document_that_is_not_there_yet_has_no_neighbours(self) -> None:
        """The first rotation into a path, which is not a failure."""
        assert layout(SHARED).accounts(None) == ()


class TestPatching:
    def test_a_patch_names_only_what_it_changes(self) -> None:
        assert layout(SHARED).patch(PENDING, "new") == {"pending": {"acme_web_user": "new"}}

    def test_the_unaddressed_layout_patches_the_root_key(self) -> None:
        assert layout(OWN).patch(PENDING, "new") == {"pending": "new"}

    def test_a_sibling_account_is_absent_rather_than_rewritten(self) -> None:
        """Invariant 5, as a property of the patch.

        Rewriting a sibling with what was last read looks identical until a
        concurrent writer changed it, and then it is a silent revert of somebody
        else's rotation.
        """
        patch = layout(SHARED).patch(CURRENT, "new")
        assert patch == {"DB_CREDENTIALS": {"acme_web_user": "new"}}
        assert "acme_api_user" not in patch["DB_CREDENTIALS"]

    def test_removing_is_how_pending_is_cleared(self) -> None:
        assert layout(SHARED).patch(PENDING, REMOVE) == {"pending": {"acme_web_user": None}}

    def test_a_secret_travels_wrapped(self) -> None:
        """No `reveal()` in this layer -- the wrapper reaches the store intact."""
        secret = Secret("hunter2")
        assert layout(SHARED).patch(CURRENT, secret)["DB_CREDENTIALS"]["acme_web_user"] is secret


class TestMerging:
    def test_a_promotion_is_one_write(self) -> None:
        at = layout(SHARED)
        assert merge(
            at.patch(CURRENT, "new"),
            at.patch(PREVIOUS, "old"),
            at.patch(PENDING, REMOVE),
            at.patch("rotated_by", "approle:sopuli-ci"),
        ) == {
            "DB_CREDENTIALS": {"acme_web_user": "new"},
            "previous": {"acme_web_user": "old"},
            "pending": {"acme_web_user": None},
            "rotated_by": {"acme_web_user": "approle:sopuli-ci"},
        }

    def test_two_accounts_staged_in_one_run_both_survive(self) -> None:
        """A shallow update would file the second and lose the first."""
        web = layout("tenants/beta#DB_CREDENTIALS/acme_web_user")
        api = layout("tenants/beta#DB_CREDENTIALS/acme_api_user")
        assert merge(web.patch(PENDING, "w"), api.patch(PENDING, "a")) == {
            "pending": {"acme_web_user": "w", "acme_api_user": "a"}
        }

    def test_later_wins_at_the_leaf(self) -> None:
        at = layout(SHARED)
        assert merge(at.patch(PENDING, "first"), at.patch(PENDING, "second")) == {
            "pending": {"acme_web_user": "second"}
        }

    def test_the_inputs_are_left_alone(self) -> None:
        """Patches are built once and may be reported as well as written."""
        first = layout("tenants/beta#DB_CREDENTIALS/acme_web_user").patch(PENDING, "w")
        merge(first, layout("tenants/beta#DB_CREDENTIALS/acme_api_user").patch(PENDING, "a"))
        assert first == {"pending": {"acme_web_user": "w"}}


class TestRefusals:
    def test_a_whole_secret_ref_has_nowhere_to_stage(self) -> None:
        with pytest.raises(ConfigError, match="nowhere to stage"):
            layout("apps/orders/prod/db/ORDERS_APP")

    @pytest.mark.parametrize("reserved", RESERVED)
    def test_a_container_may_not_take_a_key_the_rule_generates(self, reserved: str) -> None:
        """`#pending` would put the current stage and the pending stage in one key."""
        with pytest.raises(ConfigError, match="reserved field name"):
            layout(f"tenants/beta#{reserved}/acme_web_user")

    def test_the_refusal_names_the_ref_and_what_to_do(self) -> None:
        with pytest.raises(ConfigError) as raised:
            layout("apps/orders/prod/db/ORDERS_APP")
        assert "apps/orders/prod/db/ORDERS_APP" in str(raised.value)
        assert "#password" in str(raised.value)
