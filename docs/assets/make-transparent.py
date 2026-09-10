"""Give the logo a transparent background.

Produces every `sopuli-dba-logo*.png` in this directory from
`sopuli-dba-logo-original.jpg`, which is committed beside it so a clone can
reproduce them. It is kept here as the provenance of those files rather than as
part of the package: it is not imported by anything, it needs `pillow` and
`numpy` (neither of which is a project dependency), and `docs/` is outside
ruff's and mypy's scope.

    python -m venv .imgvenv && .imgvenv/bin/pip install pillow numpy
    .imgvenv/bin/python docs/assets/make-transparent.py SRC.jpg DST.png [options]

The committed set, and the exact commands that made it:

    make-transparent.py ORIG.jpg sopuli-dba-logo.png
    make-transparent.py ORIG.jpg sopuli-dba-logo-800.png      --size 800
    make-transparent.py ORIG.jpg sopuli-dba-logo-glow.png     --glow
    make-transparent.py ORIG.jpg sopuli-dba-logo-glow-960.png --glow --size 960

The two sizes pair up: 400 and 480 both put the badge at 329 px, 800 and 960
both put it at 658. So the glow and plain variants of a size are swappable, and
only the margin round the badge changes.

## Which source

**The full-resolution original render.** An earlier version of this script keyed
a 400 px JPEG that was in the tree, and produced the ragged edge this was
rewritten to fix -- at 400 px the badge boundary is one pixel wide, so there is
nothing to antialias from. The original is 1191x892 after trimming, with the
badge about 730 px across.

## What the background actually is

Three facts about the source, all measured rather than assumed:

- The background is a flat light grey (227,231,232), and nothing else in the
  image is that colour -- the lab coat is 255 and the database cylinders are
  bluer. So the key is on the background's own colour, flood-filled from the
  border, rather than on "anything near white": a global colour key would punch
  holes in the coat.
- **The badge sits in a soft light glow.** It runs 234,238,241 against that
  ground and decays to nothing over about 200 px. Keying it *out* is the whole
  reason FILL_TOL is 60 rather than the 20 this script used to carry. At 20 the
  flood stopped partway through the glow and stranded the rest as fully-opaque
  islands -- a dotted pale fringe all round the badge on a dark page, plus 45 px
  of detached speckle and 80 pinholes. That fringe was the "rough edges", and it
  was not an antialiasing problem at all.
- The badge's own boundary is a near-black outline: the step across it is about
  350 in RGB distance, against a glow that peaks near 35. That gap is why the
  result is insensitive to FILL_TOL -- 40, 60 and 90 differ by a mean of
  0.07/255 across the whole image. The outline is also closed, so the flood
  cannot reach the white coat inside (distance 42, well under the tolerance)
  however high the tolerance goes. Verified by checking the output for enclosed
  transparent pixels and for opaque islands not connected to the badge: zero of
  each.

## Why supersample

The edge is antialiased by *coverage*, not by a hand-rolled ramp. The mask is
built at SS times the source resolution and the result is downsampled onto
premultiplied alpha, so each output pixel averages tens of mask samples. The old
script ramped alpha over a 3 px band at output resolution and got 1073
partly-transparent pixels for a circle with a ~1000 px circumference -- roughly
one level of grey per edge pixel, which is a stair-step. This gets 3586 at the
same size.

SS=3 is where it converges at 400 px: going 2 -> 3 moves the composited result
by a mean of 1.8/255, and 3 -> 4 by 0.5/255 for twice the work.

Downsampling *premultiplied* is the other half of it. Blending colour and alpha
separately lets the RGB of a transparent pixel bleed into its neighbours, which
is the classic dark-halo bug; premultiplying makes the average correct by
construction.

## --glow, and what it can and cannot reproduce

Without `--glow` the halo is discarded and the mask is the badge silhouette.
That is the right default: the glow is the render's own soft shadow, and
`over` compositing turns a light halo that reads as +7 against this grey ground
into roughly +90 against a dark page. What is subtle in the source is not
subtle on a dark background.

With `--glow` it is kept, unmixed against the measured background by the
minimal-alpha rule -- the smallest alpha that keeps the recovered foreground in
gamut on every channel, which reproduces the source exactly when composited
back over its own grey. That works out to a very slightly blue white,
(246,249,255), at about 0.39 alpha next to the badge.

**Only the near field is kept**, out to GLOW_REACH. The measured halo has a
faint tail running to about 200 px, and reproducing all of it looks wrong: on a
dark page it is a grey cloud the badge sits inside rather than a glow. Two
mechanisms close it, and they are not redundant:

- a window, which is a blurred copy of the silhouette -- isotropic by
  construction, and needing no distance transform;
- a taper over the last TAPER_PX of the source border, because **the source
  clips its own glow**. There are 243 and 237 px of room left and right of the
  badge, by which point the glow has decayed to nothing, but only 82 and 80 px
  above and below, where it is still at +5. Rather than invent the missing
  part, the halo is carried as far as the source has data and faded out.
  Vertically it is the taper rather than the window that closes it.

So the halo is slightly wider at the sides than above and below -- which the
source itself shows, independently of the clipping: at 50-75 px out the glow
measures 7.9/8.2 left and right against 4.6/5.4 up and down. Left and right
agree with each other to within 0.2 at every distance, so this is the artwork,
not noise.

The glow is blurred before unmixing, by normalised convolution over the
background region only so the badge's own colours cannot bleed outwards. That
is denoising and nothing else -- GLOW_REACH sets the extent. It matters because
the unmix amplifies: the blue denominator is 255-232, so one JPEG noise level
becomes 0.04 of alpha, and unblurred that is visible speckle across the whole
halo. An earlier draft used the blur to set the extent too, by letting a large
sigma push the tail under GLOW_PEDESTAL. It looked acceptable and was wrong:
shaping by accident, with a lumpy contour where the pedestal cut a near-zero
noisy field.

`--glow-strength` and `--glow-reach` retune it without touching the badge.
Swept at 60/90/130/200 px and 0.5/0.7/1.0 against a dark ground; 90 at full
strength is the default, because it reads as a glow rather than as fog.

## The remaining steps

- **Decontaminate.** A partly-transparent pixel is a blend of background and
  subject and still carries some of the grey. Solving C = a*F + (1-a)*B for F
  removes it. Skipped below DECON_MIN, where the division amplifies noise.
- **Zero the fully transparent pixels.** They otherwise keep the background
  colour in their RGB, which naive scalers bleed back in.
- **Frame consistently.** The badge is BADGE_FRACTION of the canvas. The plain
  variant's fraction reproduces the framing of the PNG it replaces, so it stays
  a drop-in for the README's `width="200"`; the glow variant's is smaller, so
  the halo has somewhere to go. Both put the badge at 329 px by default, which
  is what makes them interchangeable. The run prints the alpha found on the
  canvas border -- 0 means nothing was clipped, and it is worth rechecking
  after raising `--glow-reach`.

## A note on --size

800 is the honest maximum for the plain variant: the badge is 730 px in the
source and 658 px at that size, so it is still a genuine downsample. Asking for
more upscales, and invents detail the render does not contain.
"""

from __future__ import annotations

import argparse
from collections import deque

import numpy as np
from PIL import Image

TRIM = 2  # the outermost row and column of the JPEG are a darker artefact
FILL_TOL = 60.0  # within this of the background colour: flooded. Clears the glow
SOLID_AT = 200.0  # at this distance: fully opaque. Between the two: ramped
BAND_PX = 4  # how far the ramp may reach in from the filled region, pre-scaling
FLOOR = 0.06  # alpha below this becomes 0, rather than near-invisible speckle
DECON_MIN = 0.15  # do not unmix below this: the division amplifies noise

GLOW_BLUR = 20  # sigma, source px. Denoising only -- see GLOW_REACH for extent
GLOW_REACH = 90  # source px the halo carries before the window closes it
GLOW_PEDESTAL = 0.015  # unmixed alpha below this is background noise, not glow
TAPER_PX = 40  # fade the glow out over this much of the source border

BADGE_FRACTION = {False: 329 / 400, True: 329 / 480}  # of the canvas, by --glow


def box_blur(a: np.ndarray, radius: int) -> np.ndarray:
    """Separable box blur by cumulative sum, edge-clamped. Three of these
    approximate a Gaussian closely enough for something this smooth, and it
    avoids a scipy dependency for one call."""
    for axis in (0, 1):
        a = np.moveaxis(a, axis, 0)
        pad = np.concatenate([np.repeat(a[:1], radius, 0), a, np.repeat(a[-1:], radius, 0)])
        cs = np.cumsum(pad, axis=0)
        cs = np.concatenate([np.zeros_like(cs[:1]), cs])
        a = (cs[2 * radius + 1 :] - cs[: -(2 * radius + 1)]) / (2 * radius + 1)
        a = np.moveaxis(a, 0, axis)
    return a


def gaussian(a: np.ndarray, sigma: float) -> np.ndarray:
    radius = max(1, int(round(sigma * 1.04)))
    for _ in range(3):
        a = box_blur(a, radius)
    return a


def flood_background(dist: np.ndarray, tol: float) -> np.ndarray:
    """Pixels within `tol` of the background colour and connected to the border.
    Connectivity is what keeps the white coat and the pale cylinders intact."""
    h, w = dist.shape
    candidate = dist < tol
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
    return is_bg


def glow_layer(
    rgb: np.ndarray, bg: np.ndarray, is_bg: np.ndarray, strength: float, reach: float
) -> tuple[np.ndarray, np.ndarray]:
    """Unmix the halo into (alpha, colour), tapered to zero at the source border.

    Minimal-alpha unmixing: the smallest alpha for which the recovered
    foreground stays inside [0,255] on every channel. Compositing the result
    back over `bg` reproduces the source.
    """
    h, w, _ = rgb.shape

    # Blur over the background region only -- normalised convolution, so the
    # badge's own colours cannot bleed outwards into the halo.
    mask = is_bg.astype(np.float64)
    weight = gaussian(mask, GLOW_BLUR)
    smooth = gaussian(rgb * mask[:, :, None], GLOW_BLUR)
    # Deep inside the badge the blur has no background to average, so the
    # extrapolation is meaningless there. It is also invisible -- the badge is
    # opaque over it -- but left in it would read as alpha 1 and skew the
    # reported peak, so cut it at the point where support runs out. Just inside
    # the boundary support is partial and the extrapolation is what carries the
    # halo under the badge edge, which is wanted.
    supported = weight > 0.05
    colour = np.zeros_like(rgb)
    colour[supported] = smooth[supported] / weight[supported][:, None]

    lighter = np.clip((colour - bg) / (255.0 - bg), 0.0, None)
    darker = np.clip((bg - colour) / bg, 0.0, None)
    alpha = np.maximum(lighter, darker).max(axis=2)
    alpha = np.clip((alpha - GLOW_PEDESTAL) / (1.0 - GLOW_PEDESTAL), 0.0, 1.0)
    alpha[~supported] = 0.0

    # Confine the halo to the near field. The measured glow has a faint tail
    # running to ~200 px; against this grey ground it is imperceptible, but
    # `over` compositing turns it into visible fog on a dark page -- and the
    # source clips it vertically anyway. The window is a blurred copy of the
    # silhouette, which is isotropic by construction and needs no distance
    # transform: it is 1 at the boundary and reaches 0 about `reach` px out.
    alpha *= np.clip(gaussian(1.0 - mask, reach / 2.0) * 2.0, 0.0, 1.0)

    yy, xx = np.mgrid[0:h, 0:w]
    to_border = np.minimum(np.minimum(yy, h - 1 - yy), np.minimum(xx, w - 1 - xx))
    t = np.clip(to_border / TAPER_PX, 0.0, 1.0)
    # Smoothstep, so the taper has no corner. Not redundant with the window
    # above: there are only 80 px of source above and below the badge against a
    # reach of 90, so vertically it is the taper that closes the halo.
    alpha *= t * t * (3.0 - 2.0 * t)
    alpha = np.clip(alpha * strength, 0.0, 1.0)

    front = np.zeros_like(rgb)
    live = alpha > 1e-4
    a3 = alpha[live][:, None]
    front[live] = np.clip((colour[live] - (1.0 - a3) * bg[None, :]) / a3, 0, 255)
    return alpha, front


def upsample(a: np.ndarray, size: tuple[int, int]) -> np.ndarray:
    """Bicubic resize of a float plane or 3-plane array. Only ever used on the
    glow, which is smooth, so interpolation loses nothing."""
    if a.ndim == 2:
        return np.asarray(Image.fromarray(a.astype(np.float32), "F").resize(size, Image.BICUBIC))
    planes = [
        np.asarray(Image.fromarray(a[:, :, c].astype(np.float32), "F").resize(size, Image.BICUBIC))
        for c in range(a.shape[2])
    ]
    return np.dstack(planes)


def main() -> None:
    ap = argparse.ArgumentParser(description="Give the logo a transparent background.")
    ap.add_argument("src", help="the full-resolution original render, not a 400 px copy")
    ap.add_argument("dst", help="output PNG")
    ap.add_argument(
        "--size", type=int, help="output canvas, square (default 400, or 480 with --glow)"
    )
    ap.add_argument("--glow", action="store_true", help="keep the artwork's outer halo")
    ap.add_argument("--glow-strength", type=float, default=1.0, help="scale the halo (default 1)")
    ap.add_argument("--glow-reach", type=float, default=GLOW_REACH, help="halo extent in source px")
    ap.add_argument("--supersample", type=int, default=3, help="mask oversampling (default 3)")
    args = ap.parse_args()

    ss = args.supersample
    # The glow needs a wider margin than the badge does, so its default canvas
    # is larger. BADGE_FRACTION then puts the badge at the same 329 px either
    # way, which is what makes the two variants interchangeable.
    size = args.size if args.size else (480 if args.glow else 400)
    badge_out = round(size * BADGE_FRACTION[args.glow])

    # --- 1. the background colour, from the border it occupies ---------------
    img = Image.open(args.src).convert("RGB")
    img = img.crop((TRIM, TRIM, img.width - TRIM, img.height - TRIM))
    base = np.asarray(img).astype(np.float64)
    border = np.concatenate([base[0], base[-1], base[:, 0], base[:, -1]])
    bg = np.median(border, axis=0)
    print(f"source {img.width}x{img.height}, background {bg.round(1)}, badge -> {badge_out} px")

    # --- 2. the glow, at source resolution -----------------------------------
    if args.glow:
        is_bg_1x = flood_background(np.linalg.norm(base - bg, axis=2), FILL_TOL)
        glow_a, glow_c = glow_layer(base, bg, is_bg_1x, args.glow_strength, args.glow_reach)
        outside = glow_a[is_bg_1x]
        print(
            f"glow: peak alpha {outside.max():.3f}, reaches "
            f"{(outside > 0.01).sum() / is_bg_1x.sum() * 100:.0f}% of the background"
        )

    # --- 3. supersample, so the mask can be antialiased by coverage ----------
    big = img.resize((img.width * ss, img.height * ss), Image.LANCZOS)
    rgb = np.asarray(big).astype(np.float64)
    h, w, _ = rgb.shape
    dist = np.linalg.norm(rgb - bg, axis=2)

    is_bg = flood_background(dist, FILL_TOL)
    print(f"flooded {is_bg.mean() * 100:.1f}% at {ss}x")

    # --- 4. ramped alpha over the transition band ----------------------------
    alpha = np.ones((h, w), dtype=np.float64)
    alpha[is_bg] = 0.0
    near = is_bg.copy()
    for _ in range(BAND_PX * ss):
        grown = near.copy()
        grown[1:, :] |= near[:-1, :]
        grown[:-1, :] |= near[1:, :]
        grown[:, 1:] |= near[:, :-1]
        grown[:, :-1] |= near[:, 1:]
        near = grown
    band = near & ~is_bg
    alpha[band] = np.clip((dist[band] - FILL_TOL) / (SOLID_AT - FILL_TOL), 0.0, 1.0)
    alpha[alpha < FLOOR] = 0.0

    # --- 5. decontaminate the edge colour ------------------------------------
    colour = rgb.copy()
    soft = (alpha >= DECON_MIN) & (alpha < 0.996)
    a3 = alpha[soft][:, None]
    colour[soft] = np.clip((rgb[soft] - (1.0 - a3) * bg[None, :]) / a3, 0, 255)
    colour[alpha == 0.0] = 0.0

    # --- 6. composite the badge over the glow, premultiplied -----------------
    premul_rgb = colour * alpha[:, :, None]
    premul_a = alpha
    if args.glow:
        ga = np.clip(upsample(glow_a, (w, h)), 0.0, 1.0)
        gc = np.clip(upsample(glow_c, (w, h)), 0.0, 255.0)
        behind = ga * (1.0 - alpha)
        premul_rgb = premul_rgb + gc * behind[:, :, None]
        premul_a = alpha + behind

    # --- 7. downsample, which is where the antialiasing comes from -----------
    ys, xs = np.nonzero(alpha > 0.5)
    scale = badge_out / (ys.max() + 1 - ys.min())
    centre = ((ys.min() + ys.max() + 1) / 2 * scale, (xs.min() + xs.max() + 1) / 2 * scale)
    print(f"badge at {ss}x: {xs.max() + 1 - xs.min()}x{ys.max() + 1 - ys.min()}, scale {scale:.4f}")

    stack = np.dstack([premul_rgb, np.clip(premul_a, 0.0, 1.0) * 255.0])
    small = np.asarray(
        Image.fromarray(stack.round().clip(0, 255).astype(np.uint8), mode="RGBA").resize(
            (max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS
        )
    ).astype(np.float64)

    out_a = np.clip(small[:, :, 3] / 255.0, 0.0, 1.0)
    out_c = np.zeros_like(small[:, :, :3])
    live = out_a > 1e-4
    out_c[live] = np.clip(small[:, :, :3][live] / out_a[live][:, None], 0, 255)
    tile = np.dstack([out_c, out_a * 255.0]).round().astype(np.uint8)

    # --- 8. place it on the canvas, centred on the badge ---------------------
    canvas = np.zeros((size, size, 4), dtype=np.uint8)
    oy, ox = round(size / 2 - centre[0]), round(size / 2 - centre[1])
    sy0, sx0 = max(0, -oy), max(0, -ox)
    dy0, dx0 = max(0, oy), max(0, ox)
    ch = min(tile.shape[0] - sy0, size - dy0)
    cw = min(tile.shape[1] - sx0, size - dx0)
    canvas[dy0 : dy0 + ch, dx0 : dx0 + cw] = tile[sy0 : sy0 + ch, sx0 : sx0 + cw]

    Image.fromarray(canvas, mode="RGBA").save(args.dst, optimize=True)

    a = canvas[:, :, 3]
    clipped = max(a[0].max(), a[-1].max(), a[:, 0].max(), a[:, -1].max())
    print(
        f"wrote {args.dst}: {size}x{size}, badge {badge_out} px, "
        f"{int(((a > 0) & (a < 255)).sum())} partial px, canvas-edge alpha {clipped}"
    )


if __name__ == "__main__":
    main()
