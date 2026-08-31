"""What a pre-flight prints (#283).

The decision is `tests/test_preflight.py`. This is the half a consumer of the
*text* sees, and the property worth asserting is that it cannot disagree with the
document: the verdict counts what refused, which is what the run-level `error`
counts, and never what merely appeared in the table.
"""

from __future__ import annotations

from sopuli import preflight
from sopuli.output.preflight_view import render_preflight


def blocking(target: str = "appdb-alpha") -> preflight.Finding:
    return preflight.Finding(target, preflight.PRIVILEGES, "missing GRANT ALTER USER")


def caveat(target: str = "appdb-alpha") -> preflight.Finding:
    return preflight.Finding(
        target, preflight.PRIVILEGES, "the audit could not be read", blocking=False
    )


def test_the_verdict_counts_what_refused_and_not_what_was_printed() -> None:
    """A caveat is in the table because it is worth seeing and is not a problem.
    Counting it here would have the text say two where the document said one, and
    one run described two ways is what the JSON contract exists to prevent."""
    rendered = render_preflight([blocking(), caveat()])

    assert "1 problem over 1 target" in rendered
    assert preflight.summarise([blocking(), caveat()]).startswith("pre-flight found 1 problem")


def test_a_caveat_is_named_rather_than_left_unexplained() -> None:
    """A reader who fixes one thing and sees a second row needs to know why it is
    there."""
    assert "1 check could not be established" in render_preflight([blocking(), caveat()])


def test_a_survey_with_no_caveats_says_nothing_about_them() -> None:
    assert "could not be established" not in render_preflight([blocking()])


def test_problems_are_counted_over_the_targets_that_had_them() -> None:
    rendered = render_preflight([blocking(), blocking("appdb-beta"), caveat("appdb-gamma")])

    assert "2 problems over 2 targets" in rendered


def test_each_distinct_hint_is_printed_once() -> None:
    """A missing grant on twenty targets is one install script to run, and twenty
    identical sentences would make the twenty rows above them harder to read."""
    findings = [
        preflight.Finding("appdb-alpha", preflight.PRIVILEGES, "missing", hint="run the script"),
        preflight.Finding("appdb-beta", preflight.PRIVILEGES, "missing", hint="run the script"),
    ]

    assert render_preflight(findings).count("run the script") == 1


def test_the_account_column_is_filled_only_where_the_check_is_about_one() -> None:
    findings = [
        preflight.Finding(
            "appdb-alpha", preflight.ACCOUNT, "no such user", account="acme_web_user"
        ),
        blocking(),
    ]

    rendered = render_preflight(findings)

    assert "acme_web_user" in rendered
