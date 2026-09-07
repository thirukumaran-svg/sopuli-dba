"""Give the logo a transparent background.

Run once, to produce `sopuli-dba-logo.png` from the original JPEG. It is kept
here as the provenance of that file rather than as part of the package: it is
not imported by anything, it needs `pillow` and `numpy` (neither of which is a
project dependency), and `docs/` is outside ruff's and mypy's scope.

    python -m venv /tmp/imgvenv && /tmp/imgvenv/bin/pip install pillow numpy
    /tmp/imgvenv/bin/python docs/assets/make-transparent.py SRC.jpg DST.png

Both paths are required. **The source JPEG is no longer in the tree** -- this
ran once against it and the PNG replaced it -- so recover it first if you need
to re-run this:

    git show <commit-that-deleted-it>^:docs/assets/sopuli-dba-logo.jpg > /tmp/logo.jpg

`git log --follow -- docs/assets/sopuli-dba-logo.png` finds that commit. There is
deliberately no default source path: defaulting to a file the same commit deleted
would fail with a bare FileNotFoundError and tell nobody why.

The background is a flat light grey (229,232,234), and nothing else in the image
is that colour -- the lab coat is 255 and the database cylinders are bluer. So
the key is on the background's own colour, flood-filled from the border, rather
than on "anything near white": a global colour key would punch holes in the coat.

Four steps, and the last two are what make it survive a dark page:

1. Flood fill from every border pixel over pixels close to the background
   colour. Connectivity is what keeps the interior white intact.
2. Soft alpha. A JPEG edge pixel is a blend of background and subject, so its
   alpha is how far it has travelled from the background colour.
3. Floors. A pixel barely above the fill tolerance gets a tiny alpha, and
   dividing by that in step 4 sends its colour to an extreme -- which reads as
   white speckle around the badge on a dark page. Below FLOOR it becomes fully
   transparent instead, and decontamination is skipped below DECON_MIN.
4. Decontaminate. A half-transparent pixel still carries half the grey. Solving
   C = a*F + (1-a)*B for F removes it. Without this the logo wears a grey halo
   on any dark background, which is the whole thing being fixed here.

Parameters were chosen by sweeping and looking at the result at 5x on both a
white and a near-black ground. Lowering FILL_TOL is worse, not better: below
about 14 the fill stops short of the noisier background pixels and strands them
as a grey smudge.
"""

from __future__ import annotations

import sys
from collections import deque

import numpy as np
from PIL import Image

USAGE = """usage: make-transparent.py SRC.jpg DST.png

Both paths are required, and there is deliberately no default source: the JPEG
this was written for is no longer in the tree, so a default would fail with a
bare FileNotFoundError and tell nobody why. To recover it:

    git log --follow -- docs/assets/sopuli-dba-logo.png   # find the commit
    git show <commit>^:docs/assets/sopuli-dba-logo.jpg > /tmp/logo.jpg
"""

if len(sys.argv) != 3:
    sys.exit(USAGE)

SRC, DST = sys.argv[1], sys.argv[2]

FILL_TOL = 20.0  # within this of the background colour: flooded
SOLID_AT = 52.0  # at this distance: fully opaque. between the two: ramped
BAND_PX = 3  # how far the ramp may reach in from the filled region
FLOOR = 0.06  # alpha below this becomes 0, rather than near-invisible speckle
DECON_MIN = 0.15  # do not unmix below this: the division amplifies noise

img = Image.open(SRC).convert("RGB")
rgb = np.asarray(img).astype(np.float64)
h, w, _ = rgb.shape

# --- 1. the background colour, from the border it occupies -------------------
border = np.concatenate([rgb[0], rgb[-1], rgb[:, 0], rgb[:, -1]])
bg = np.median(border, axis=0)
dist = np.linalg.norm(rgb - bg, axis=2)
print(f"background colour: {bg.round(1)}")

# --- 2. flood fill from the border ------------------------------------------
candidate = dist < FILL_TOL
is_bg = np.zeros((h, w), dtype=bool)
queue: deque[tuple[int, int]] = deque()

edge = (
    [(0, i) for i in range(w)]
    + [(h - 1, i) for i in range(w)]
    + [(i, 0) for i in range(h)]
    + [(i, w - 1) for i in range(h)]
)
for y, x in edge:
    if candidate[y, x] and not is_bg[y, x]:
        is_bg[y, x] = True
        queue.append((y, x))

while queue:
    y, x = queue.popleft()
    for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)):
        ny, nx = y + dy, x + dx
        if 0 <= ny < h and 0 <= nx < w and candidate[ny, nx] and not is_bg[ny, nx]:
            is_bg[ny, nx] = True
            queue.append((ny, nx))

print(f"flooded: {is_bg.sum()} px ({is_bg.mean() * 100:.1f}%)")

# --- 3. ramped alpha over the transition band --------------------------------
alpha = np.ones((h, w), dtype=np.float64)
alpha[is_bg] = 0.0

near = is_bg.copy()
for _ in range(BAND_PX):
    grown = near.copy()
    grown[1:, :] |= near[:-1, :]
    grown[:-1, :] |= near[1:, :]
    grown[:, 1:] |= near[:, :-1]
    grown[:, :-1] |= near[:, 1:]
    near = grown

band = near & ~is_bg
ramp = np.clip((dist - FILL_TOL) / (SOLID_AT - FILL_TOL), 0.0, 1.0)
alpha[band] = ramp[band]
alpha[alpha < FLOOR] = 0.0
print(f"edge band: {band.sum()} px, {((alpha > 0) & (alpha < 1)).sum()} partly transparent")

# --- 4. decontaminate the edge colour ----------------------------------------
out = rgb.copy()
soft = (alpha >= DECON_MIN) & (alpha < 0.996)
a3 = alpha[soft][:, None]
out[soft] = np.clip((rgb[soft] - (1.0 - a3) * bg[None, :]) / a3, 0, 255)
print(f"decontaminated: {soft.sum()} px")

# Fully transparent pixels keep the background colour in their RGB, which some
# naive scalers bleed back in. Zero them so there is no grey left to find.
out[alpha == 0.0] = 0.0

rgba = np.dstack([out, alpha * 255.0]).round().astype(np.uint8)
Image.fromarray(rgba, mode="RGBA").save(DST, optimize=True)
print(f"wrote {DST}")
