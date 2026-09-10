# Logo assets

| File | Use it for |
|---|---|
| `sopuli-dba-logo-glow.png` | **what the top-level README embeds**, at `width="240"`. 480x480, keeping the artwork's soft outer halo, which is what stops the badge reading as cut out on a dark page |
| `sopuli-dba-logo-glow-960.png` | the halo version at 960x960 |
| `sopuli-dba-logo.png` | 400x400, no halo. For a light ground, or anywhere the halo would fight the surround |
| `sopuli-dba-logo-800.png` | the plain version at 800x800 |
| `sopuli-dba-logo-original.jpg` | the source render. Not for embedding — it is a JPEG with a light-grey background baked in, which is a grey square on a dark page |

The sizes pair up: 400 and 480 both place the badge at 329 px, 800 and 960 both
place it at 658. So the glow and plain variants of a size are swappable, and
only the margin round the badge changes. The glow canvas is the larger of each
pair because the halo needs somewhere to go — **which is why the README embeds
the glow one at 240 rather than 200.** Same `width` on both would render the
glow badge smaller by exactly that margin.

Below about 64 px the halo starts to close over the artwork; use the plain one
for favicons and anything else that small.

800 is the honest maximum: the badge is 730 px in the source, so anything
larger upscales.

## Regenerating them

`make-transparent.py` produces all four from the original, and is the
provenance of the binaries rather than part of the package — nothing imports
it, it needs `pillow` and `numpy`, which are not project dependencies, and
`docs/` is outside ruff's and mypy's scope.

```
python -m venv .imgvenv && .imgvenv/bin/pip install pillow numpy
.imgvenv/bin/python docs/assets/make-transparent.py \
    docs/assets/sopuli-dba-logo-original.jpg docs/assets/sopuli-dba-logo.png
.imgvenv/bin/python docs/assets/make-transparent.py \
    docs/assets/sopuli-dba-logo-original.jpg docs/assets/sopuli-dba-logo-800.png --size 800
.imgvenv/bin/python docs/assets/make-transparent.py \
    docs/assets/sopuli-dba-logo-original.jpg docs/assets/sopuli-dba-logo-glow.png --glow
.imgvenv/bin/python docs/assets/make-transparent.py \
    docs/assets/sopuli-dba-logo-original.jpg docs/assets/sopuli-dba-logo-glow-960.png \
    --glow --size 960
```

Its docstring carries the measurements the parameters were chosen from — read
that before changing one. The short version: the background is a specific grey
rather than white, so the key is flood-filled from the border to avoid punching
holes in the otter's white coat; the badge sits in a soft halo that has to be
keyed out deliberately, because keying it out *partway* is what produced the
ragged fringe an earlier version of this script shipped.
