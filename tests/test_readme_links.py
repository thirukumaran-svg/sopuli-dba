"""The README's links resolve outside the repository (#545).

PyPI renders ``README.md`` as the project page, detached from the repository, so
a relative link -- ``docs/getting-started.md`` -- is a 404 there. Every link and
image in it is therefore an absolute URL, and this keeps it that way: the README
is the file most often edited by hand, and a relative link looks correct on
GitHub, which is where anyone adding one would check it.

In-page anchors (``#status``) stay relative, because they resolve wherever the
page is rendered.
"""

from __future__ import annotations

import re
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"

#: Markdown link and image targets, and HTML ``src``/``href`` attributes.
TARGETS = re.compile(r"\]\(([^)\s]+)\)|(?:src|href)=\"([^\"]+)\"")


def _relative_targets(text: str) -> list[str]:
    found = (a or b for a, b in TARGETS.findall(text))
    return [t for t in found if not t.startswith(("https://", "http://", "mailto:", "#"))]


def test_every_readme_link_is_absolute() -> None:
    assert _relative_targets(README.read_text(encoding="utf-8")) == []


def test_the_check_catches_a_relative_link() -> None:
    """The regex is the whole test, so it is checked against what it must catch."""
    sample = '[a](docs/x.md) ![b](img.png) <img src="docs/y.png"> [c](#anchor) [d](https://e)'
    assert _relative_targets(sample) == ["docs/x.md", "img.png", "docs/y.png"]
