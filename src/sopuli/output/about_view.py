"""What ``sopuli about`` prints (#413).

The one view in this package that renders nothing about a run. Every other
``*_view`` module turns a result, a config or a survey into text; this turns
*nothing* into text -- the same bytes on every machine, every invocation, with
no I/O behind them except the installed distribution's version.

That is the whole reason the command exists. ``--version`` has to stay a single
greppable line that a script can parse, so the banner, the tagline and the links
needed somewhere else to live, and bolting them onto ``--version`` or adding a
root-level ``--about`` would have been an exception to D2's grammar for no gain.
A bare top-level verb is not an exception: `doctor` is already one.

**It is deliberately narrower than `doctor`.** No install path, no backend
status, no diagnostics -- `doctor` owns all of that, and a second command
reporting an overlapping subset is how two answers to one question start. If
bug-report output (Python version, OS, config path) is ever wanted, it is a
change to `doctor`, not a ``--full`` flag here.

**Colour is decoration and never meaning**, which is `palette.py`'s first rule
and is trivially true of a banner: `click.unstyle` the output and every word is
still there. The banner asks for :attr:`~sopuli.output.palette.Role.BANNER`
rather than naming a colour, for the reason that module gives -- a call site
that reached for ``click.style`` would be inventing a colour that means nothing
to any other view. Whether the escapes survive is not decided here either; the
emitter strips them when colour is off.
"""

from __future__ import annotations

from sopuli.output.palette import Role, paint
from sopuli.version import get_version

#: Two words, stacked, in a five-row block font. ASCII by the same rule as every
#: other piece of the tool's own prose (``tests/test_cli_smoke.py``): box-drawing
#: characters would render this beautifully on the terminals that have the font
#: and as a row of boxes on the ones that do not.
BANNER = r""" ####  ###  ####  #   # #     #####
#     #   # #   # #   # #       #
 ###  #   # ####  #   # #       #
    # #   # #     #   # #       #
####   ###  #      ###  ##### #####

         ####  ####   ###
         #   # #   # #   #
         #   # ####  #####
         #   # #   # #   #
         ####  ####  #   #"""

TAGLINE = "Database credential rotation, without the ceremony."

REPO_URL = "https://github.com/villebase/sopuli-dba"

MAINTAINER = "Ville (github.com/villebase)"

SUPPORT_URL = "https://ko-fi.com/villeronkko"


def render() -> str:
    """The whole of ``sopuli about``, as one string.

    A string rather than a series of ``click.echo`` calls so that the colour
    gate and the write stay where they are for every other command: one text,
    handed to the emitter, which strips escapes if it must and writes once.
    """
    return "\n".join(
        (
            paint(BANNER, Role.BANNER),
            "",
            TAGLINE,
            f"version {get_version()}",
            REPO_URL,
            "",
            f"Maintained by {MAINTAINER}",
            f"Support the project: {SUPPORT_URL}",
        )
    )
