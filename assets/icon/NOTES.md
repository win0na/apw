# apw — one key in deep glass

One measured key, one hue, a quiet plate, four appearances. The key is a glass pane with the colour
painted on its back short of the edge: the pane's bevel looks outward, finds the plate, and the paint's
edge appears inside it. That band between the silhouette and the painted face is the wall, and it is the
thing this pass rebuilt.

## What ships

| path | what |
|---|---|
| `renders/icon-{1024,512,256,70,40}.png` | Default, plate included |
| `renders/icon-{size}-dark.png` | Dark |
| `renders/icon-{size}-clear.png`, `-clearDark.png` | Clear Light, Clear Dark |
| `icon.json` | Default recipe |
| `icon-dark.json`, `icon-clear.json` | the other appearances |
| `icon-bundle.json` + `apw.icon/` | the Icon Composer document (Default, three layers) |
| `src/<appearance>/key.svg`, `key-face.svg` | the pane and the painted face, 1024 × 3072 frame |
| `preview/` | contact sheet, 70 and 40 rows, circle crops, refraction pair |

## The key

The outline is Apple's Passwords key, the blue front one, parsed from the reference icon's own vector
paths and unchanged except for placement: the reference puts it on the right of a three-key group, so it is
moved left by 120.48 pt until the bow sits on the canvas centre line. Vertically it stays where the
reference put it, at the reference's scale (1.0).

| landmark | at 1024 pt |
|---|---|
| bow centre / radius | (512.0, 331.8) / 192.9 |
| hole centre / radius | (512.6, 265.8) / 51.5 (offset +0.6, −66.0 from the bow) |
| shaft width | 116.3 (top-left 443.6, 512.2; top-right 559.9, 518.7) |
| tooth 1 out / notch / tooth 2 out | (643.9, 604.3) / (561.2, 702.6) / (621.0, 763.0) |
| tip left / right | (505.0, 882.0) / (520.9, 881.6) |
| heel | (446.3, 820.6) |
| key box | x 319.1–704.9, y 138.9–884.4 (386 × 745) |

Reference units scale by K = 3.18659 pt. Nothing is redrawn: the beziers are the reference's.

## Layers

The frame is 3072 pt tall with the artwork in its bottom third (`layout y −100 %, scale 300 %`), so the
translucency ramp runs over 3072 pt and reaches the key as a gentle gradient instead of a hard band.

| # | layer | kind | artwork | frame |
|---|---|---|---|---|
| 1 | Key | glass | `key.svg`, the measured path | 1024 × 3072, y −1024 |
| 2 | Key face | plain | `key-face.svg`, the same path offset 8 pt inward | 1024 × 3072, y −1024 |
| 3 | plate | recipe background | `#ffffff → #e9eef7` (Default), `#1f1f1f → #0f0f0f` (Dark) | full canvas |

## Material

| | Default | Dark | Clear Light | Clear Dark |
|---|---|---|---|---|
| plate | `#ffffff → #e9eef7` | `#1f1f1f → #0f0f0f` | engine plate, 188 grey | engine plate, 115 grey |
| back paint | `#0079ff`, flat | `#70d4ff → #0a84ff` | `#7c8b9c → #5a6b7d` | same |
| paint inset | 8 pt | 8 pt | 8 pt | 8 pt |
| pane fill | `#2ea8f2 → #0050c8` | `#0a84ff` | `#c2cfdd` | same |
| translucency | 40 | 45 | 50 | 50 |
| pane opacity A, bow top → tip | 0.82 → 0.65 | 0.78 → 0.58 | 0.74 → 0.50 | same |
| bevel | 4.5 % (46 pt) | 4.5 % | 4.5 % | 4.5 % |
| refraction | −10 (−64 pt) | −10 | −10 | −10 |
| dispersion | 20 | 20 | 20 | 20 |
| specular | inside, 100 | inside, 100 | inside, 100 | inside, 100 |
| key / fill / darklight gain | 180 / 0 / 240 | 180 / 0 / 240 | 220 / 0 / 300 | same |
| shadow, blur, frost | off | off | off | off |

Why these numbers.

- **Refraction −10, not +100.** The sign decides what the bevel sees. Positive samples farther into the
  shape: the bevel jumps past the paint's near edge and can only show the far side, which is why the
  first pass had a pale band on the shaft and none on the bow (the bow is 386 pt wide, wider than any
  displacement the engine gives). Negative samples outward: the bevel sees the margin between the
  silhouette and the paint, so the wall runs the whole way round and the paint's edge appears inside it.
  The magnitude sets how much: at −64 pt the 8 pt margin is displayed at 19 pt, a 2.4× minification of
  the face, and the fold stays at the extreme edge with no contour loops.
- **Bevel 4.5 % (46 pt).** The bevel is a fraction of the depth, so it reads differently on each part:
  it is 19 pt of wall on the shaft, 20 pt round the hole, and the same at the bow, because the wall is
  set by the paint's inset and the refraction, not by the local width. Above ~5.6 % the SDF's medial
  axis creases the shaft; below 3 % the bevel stops mattering.
- **Paint 8 pt inset.** A uniform offset, not a scale: the wall keeps one width along the bow's rim, the
  shaft's sides and the teeth. The hole grows with it (radius 51.5 → 59.5), which is what gives the hole
  its pale ring without drawing one.
- **Translucency 40** keeps the pane nearly opaque at the bow (A 0.82) and open at the tip (A 0.65), so
  the paint's depth shows more down the blade and the slab reads as thicker at the bottom.
- **The pane's tint ramp** `#2ea8f2 → #0050c8` is the material's shading: a slab that absorbs more light
  as it goes down its length. The paint under it is one flat colour, so the gradient a viewer sees is not
  painted on the artwork.
- **Dispersion 20** splits red and blue on the refracted edge; it shows on the wall's inner boundary, not
  as colour noise.
- **Gains 180 / 0 / 240.** The 4 px key band and its 16 px soft band land on top-facing edges; the fill
  light is off so the bottom does not go glossy; the 4 px dark band at ±90° draws the side edges. The
  first pass ran 250 / 250 / 300, which is what made the broad sheen across the bow.

## Light and specular placement

Light comes from directly above (the engine's default angle; nothing is rotated). The key highlight lands
on the bow's top arc, the top of each tooth and the hole's top rim; the dark band on the two sides of the
shaft, the bow's flanks and the teeth's flanks. Specular is `inside`: no paint lands outside the
silhouette, which T3 confirms at every size (0 px).

The fill light is off, so the bottom edges are not lit from below. The engine's darklight table only has
bands at ±90°, so a crisp dark edge along the bottom is not available; the bottom reads as an unlit wall
with the silhouette's own dark line.

## Why the paint stops short of the edge

A back-painted glass slab has three visible surfaces at its rim: the top face (paint behind glass), the
chamfer where the glass turns down, and the side wall. Seen from directly above, the chamfer is what you
see as a band, and it is empty of paint. So the paint stops where the chamfer begins.

That is the layer structure: the pane is the measured path, the paint is the same path offset 8 pt
inward, and the band between them is the chamfer. The pane's refraction decides what that band shows: at
−64 pt of displacement it shows the plate, and the edge of the paint is displayed about 11 pt inside
where it is painted.

This is not an offset outline. The face is a separate layer with its own material (flat paint with no
edge treatment), and the band is not drawn at all: it is a hole in the paint with the glass over it, and
its width is measured (T4) rather than assumed. Turn refraction off and the band stays, but the paint's
edge no longer moves inside it (T5).

## The plate

Deliberately plain and structureless: a vertical falloff from white to a cool `#e9eef7`, no lines, dots,
rings or patterns. The earlier probes put rules, dot grids and hairlines on the plate for the bevel to
bend; at the displacement the first pass needed they turned into contour maps and moiré at 512. The
contrast that has to bend here is the paint's own edge, so the plate stays a plate.

## The four appearances

- **Default.** Flat `#0079ff` paint, the pane's tint ramping `#2ea8f2 → #0050c8` at translucency 40.
  Wall and face are both tinted plate, so the wall is a lighter, less saturated step, and the dark side
  band holds the silhouette.
- **Dark.** A dark plate with a brighter key, not the light image dimmed: back paint `#70d4ff → #0a84ff`
  under a flat `#0a84ff` pane at 45. The wall samples the dark plate, so in Dark the wall is a dark band
  instead of a pale one, which is the clearest thickness read of the four.
- **Clear Light / Clear Dark.** Every plain layer becomes a lightening mask clamped at the plate, so the
  paint's only job is a value ramp. A light `#c2cfdd` pane over a mid grey paint gives the face a
  lightening of 40 levels above the plate, and the wall (plate seen through the pane, without the paint)
  sits below it as a darker band. Key against plate: 228 on 188 (light), 198 on 115 (dark).

## Registration

Two layers in register means: each lands on its own path, the paint never paints outside the pane, and
the composite has no seam where the paint's silhouette would show. Five tests per appearance and size;
the numbers are in the tables below.

- **T1** each layer alone, bare, against its own path rasterised analytically: bounding box at 50 %
  coverage, centroid, area, alpha. The face's path is the pane's path offset inward, so the test also
  measures the inset the render actually produced.
- **T2** the paint's contribution inside the composite (icon minus pane-only) against the paint alone on
  the plate: does it stay inside the pane's silhouette, and does the composite keep the pane's shape.
- **T3** the pane's edge treatment: depth from the silhouette, and paint outside it.
- **T4** seams and the wall: pixels inside the silhouette that are not fully opaque; the wall measured as
  the pixels where the paint makes no difference; the hole.
- **T5** the icon with refraction on against the same icon with refraction off.

Reading, at every size and appearance:

- Both layers sit on their own paths: bounding-box delta 0 px, centroid within 0.08 pt, area ratio
  1.000–1.002 for the pane and 0.921–0.923 for the face (the face's area is 92.1 % of the pane's, which
  is what an 8 pt offset gives). The one exception is a single 1024 bottom row (−1 px).
- The inset is real and exact: the face's rendered bounding box is `[+8, +8, −8, −8]` pt from the pane's
  at 1024, `[+4, +4, −4, −4]` at 512, `[+2, +2, −2, −2]` at 256, and the geometry says the same. The
  paint never paints outside the pane: 0 px at every size (6 px at 1024, all within 0.65 px of the edge,
  which is antialiasing).
- Nothing is painted outside the silhouette: 0 px in every case at every size (T3).
- Seams: no pixel inside the silhouette is lower than alpha 0.94, and every partial pixel is within
  1.5 px of the edge. The hole is 7,703 px at 1024 and 0 of them show the key.
- The wall is 42,438 px at 1024, 26.5 % of the key, reaching 18.9 px in from the silhouette; 25.3 % at
  512, 22.5 % at 256, 3.1 % at 70 and 0 % at 40. It is a large-size feature and the numbers say so.

## Refraction evidence

Default at 1024: **29,131 pixels — 18.2 % of the key — change when refraction goes from −10 to 0.** The
median distance of a changed pixel from the silhouette is 13.8 px, the 95th percentile 19.4 px, the
maximum 20.1 px; the largest single change is 77/255. They sit in the wall: the band all round the
silhouette and the ring round the hole, where the paint's edge moves about 11 px inward when refraction
is on.

| size | px moved | % of key | median depth | p95 | max | peak change |
|---|---|---|---|---|---|---|
| 1024 | 29,131 | 18.2 | 13.8 | 19.4 | 20.1 | 77 |
| 512 | 7,834 | 19.8 | 6.7 | 9.8 | 10.3 | 76 |
| 256 | 2,168 | 22.2 | 3.4 | 5.0 | 5.4 | 76 |
| 70 | 192 | 29.6 | 1.2 | 1.9 | 2.1 | 56 |
| 40 | 48 | 26.2 | 1.0 | 1.3 | 1.3 | 39 |

Dark behaves the same way (29,949 px, 18.7 %, peak 94/255). Clear moves the same pixels but by 12–24/255,
because the mask has almost no contrast for the displacement to reveal.

## The `.icon`

`apw.icon/` is the Default document: three groups, `Key` (glass, bevel depth 0.1368, strength 1,
translucency 0.4, specular inside) and `Key face` (plain, inset through its SVG), no shadow. Its
`features` are `refractivity` and `specular-location`, so it needs Xcode 27 / Icon Composer 2 to render
as designed; older Xcode opens it without refraction.

The format does not carry dispersion or the three highlight gains. Rendering the exported document and
comparing with `renders/icon-512.png`: identical beyond 15 px inside the silhouette (0 px differ), and inside
that band up to 58/255 at the rim, because Xcode computes the rim with its own default gains and no
dispersion. The PNGs are the shipped artwork; the bundle is the editable document.

## 70 and 40: the honest verdict

**70 px.** The key is 51 px tall, the shaft 8 px wide, the hole 7 px across. It reads as a key: the
silhouette, the zigzag and the hole all survive, and the bright top rim and dark side line are still
there. The wall does not survive: 3.1 % of the key's pixels, less than 1 px wide. What is left at 70 is
the pane's ramp and the rim, not the chamfer. Key against plate is 226/255 in Default and 216/255 in
Dark, so either ground works.

**40 px.** The key is 29 px tall, the shaft 4.5 px wide, the hole a 4 px dot with no fully covered
pixel left. Default and Dark still read as a key. The wall is gone (0 px) and so is the bevel: what
carries the shape is the silhouette and the rim. Clear Light holds up better than it did (40 levels
above the plate instead of 25) but it is still a pale key on a pale plate.

So: ship 70. 40 is usable for Default and Dark, marginal for Clear Light, and it is not a size where the
glass reads as glass.

## Where the appearance is a compromise

- **The wall is pale on the light plate, and has to be.** The bevel shows the plate through a tinted
  pane; on a white plate that is lighter than the paint behind it. A dark wall would need a dark plate
  (which Dark has) or a painted rim (which is exactly the fake edge this pass avoids). Fixing the page
  background cannot change it.
- **No dark edge along the bottom in Default.** The engine's darklight is a 4 px band at ±90°; the fill
  light is the only bottom-facing term, and turning it off (as here) leaves the bottom unlit rather than
  dark. The reviewer's "crisp dark edge at the bottom" is available on the sides only.
- **The face cannot darken with thickness.** The engine has no absorption term, so the only material
  gradient is the pane's tint and its translucency, both vertical. The bow is therefore a smooth ramp
  rather than a domed solid, and at 1:1 the depth read comes from the wall and the rim.
- **Clear cannot be deep at all**: only lightening exists, clamped at the plate.

## Reproduce

```sh
cd assets/icon
npx -y liquid-composer validate icon.json
npx -y liquid-composer apply icon.json --out renders
npx -y liquid-composer apply icon-dark.json --out renders
npx -y liquid-composer apply icon-clear.json --out renders
npx -y liquid-composer apply icon-bundle.json --out .
```

Those four commands write the 20 PNGs in `renders/` and regenerate `apw.icon/`. Each prints one JSON
object; check that its `state.webgl` is `"active"`, because without WebGL2 the engine falls back to
Canvas 2D and the renders lose refraction and blur.

The registration tests and the tables below were measured with a local build harness that does not ship
with the repository. Each test says what it compares, so the numbers can be re-derived from the renders
and the SVGs.

## Measurements

### T1 each layer on its own path

| mode / px | glass bbox delta | glass centroid delta | face bbox delta | face centroid delta | glass area ratio | face area ratio | face inset, render | face inset, geometry | face px outside glass |
|---|---|---|---|---|---|---|---|---|---|
| default 1024 | [0, 0, 0, -1] | [0.018, -0.065] | [0, 0, 0, 0] | [0.016, -0.051] | 1.00071 | 0.99974 | [8, 8, -8, -8] | [8.0, 8.0, -8.0, -8.0] | 0 |
| default 512 | [0, 1, 0, 0] | [0.001, 0.001] | [-1, 0, 0, 0] | [-0.003, -0.012] | 1.00216 | 0.99994 | [3, 3, -4, -4] | [4.0, 4.0, -4.0, -4.0] | 0 |
| default 256 | [0, 0, 0, 0] | [0.0, -0.0] | [0, 0, 0, 0] | [-0.001, -0.003] | 1.00210 | 0.99995 | [2, 2, -2, -2] | [2.0, 2.0, -2.0, -2.0] | 0 |
| default 70 | [0, 0, 0, 0] | [-0.0, -0.001] | [0, 0, 0, 0] | [-0.007, 0.014] | 1.00233 | 1.00055 | [0, 0, 0, 0] | [0.55, 0.55, -0.55, -0.55] | 0 |
| default 40 | [0, 0, 0, 0] | [0.005, -0.012] | [0, 0, 0, 0] | [-0.001, 0.013] | 0.99923 | 1.00226 | [1, 1, -1, 0] | [0.31, 0.31, -0.31, -0.31] | 0 |
| dark 1024 | [0, 0, 0, -1] | [0.017, -0.069] | [0, 0, 0, 0] | [0.016, -0.051] | 1.00064 | 0.99974 | [8, 8, -8, -8] | [8.0, 8.0, -8.0, -8.0] | 0 |
| dark 512 | [0, 1, 0, 0] | [-0.0, -0.006] | [-1, 0, 0, 0] | [-0.003, -0.012] | 1.00198 | 0.99994 | [3, 3, -4, -4] | [4.0, 4.0, -4.0, -4.0] | 0 |
| dark 256 | [0, 0, 0, 0] | [-0.0, -0.004] | [0, 0, 0, 0] | [-0.001, -0.003] | 1.00191 | 0.99995 | [2, 2, -2, -2] | [2.0, 2.0, -2.0, -2.0] | 0 |
| dark 70 | [0, 0, 0, 0] | [-0.0, -0.002] | [0, 0, 0, 0] | [-0.007, 0.014] | 1.00211 | 1.00055 | [0, 0, 0, 0] | [0.55, 0.55, -0.55, -0.55] | 0 |
| dark 40 | [0, 0, 0, 0] | [0.005, -0.013] | [0, 0, 0, 0] | [-0.001, 0.013] | 0.99891 | 1.00226 | [1, 1, -1, 0] | [0.31, 0.31, -0.31, -0.31] | 0 |
| clear 1024 | [0, 0, 0, -1] | [0.017, -0.073] | [0, 0, 0, 0] | [0.016, -0.051] | 1.00055 | 0.99974 | [8, 8, -8, -8] | [8.0, 8.0, -8.0, -8.0] | 0 |
| clear 512 | [0, 1, 0, 0] | [-0.001, -0.013] | [-1, 0, 0, 0] | [-0.003, -0.012] | 1.00179 | 0.99994 | [3, 3, -4, -4] | [4.0, 4.0, -4.0, -4.0] | 0 |
| clear 256 | [0, 0, 0, 0] | [-0.001, -0.009] | [0, 0, 0, 0] | [-0.001, -0.003] | 1.00173 | 0.99995 | [2, 2, -2, -2] | [2.0, 2.0, -2.0, -2.0] | 0 |
| clear 70 | [0, 0, 0, 0] | [-0.001, -0.002] | [0, 0, 0, 0] | [-0.007, 0.014] | 1.00189 | 1.00055 | [0, 0, 0, 0] | [0.55, 0.55, -0.55, -0.55] | 0 |
| clear 40 | [0, 0, 0, 0] | [0.005, -0.014] | [0, 0, 0, 0] | [-0.001, 0.013] | 0.99861 | 1.00226 | [1, 1, -1, 0] | [0.31, 0.31, -0.31, -0.31] | 0 |
| clearDark 1024 | [0, 0, 0, -1] | [0.017, -0.073] | [0, 0, 0, 0] | [0.016, -0.051] | 1.00055 | 0.99974 | [8, 8, -8, -8] | [8.0, 8.0, -8.0, -8.0] | 0 |
| clearDark 512 | [0, 1, 0, 0] | [-0.001, -0.013] | [-1, 0, 0, 0] | [-0.003, -0.012] | 1.00179 | 0.99994 | [3, 3, -4, -4] | [4.0, 4.0, -4.0, -4.0] | 0 |
| clearDark 256 | [0, 0, 0, 0] | [-0.001, -0.009] | [0, 0, 0, 0] | [-0.001, -0.003] | 1.00173 | 0.99995 | [2, 2, -2, -2] | [2.0, 2.0, -2.0, -2.0] | 0 |
| clearDark 70 | [0, 0, 0, 0] | [-0.001, -0.002] | [0, 0, 0, 0] | [-0.007, 0.014] | 1.00189 | 1.00055 | [0, 0, 0, 0] | [0.55, 0.55, -0.55, -0.55] | 0 |
| clearDark 40 | [0, 0, 0, 0] | [0.005, -0.014] | [0, 0, 0, 0] | [-0.001, 0.013] | 0.99861 | 1.00226 | [1, 1, -1, 0] | [0.31, 0.31, -0.31, -0.31] | 0 |

### T2 the colour never shows outside the glass

| mode / px | body px in composite | body px on plate | body px outside the glass | max distance outside | bbox delta | px where composite and solo differ | furthest from edge | edge-band px |
|---|---|---|---|---|---|---|---|---|
| default 1024 | 117489 | 143633 | 6 | 0.65 | [11, 11, -11, -13] | 26290 | 18.91 | 62 |
| default 512 | 29650 | 36270 | 0 | 0.0 | [6, 6, -6, -7] | 6634 | 9.25 | 7 |
| default 256 | 7565 | 9267 | 0 | 0.0 | [3, 3, -3, -4] | 1708 | 4.37 | 611 |
| default 70 | 638 | 815 | 0 | 0.0 | [2, 1, -2, -2] | 177 | 0.84 | 177 |
| default 40 | 238 | 297 | 0 | 0.0 | [1, 1, -1, -1] | 59 | 0.76 | 59 |
| dark 1024 | 116757 | 143633 | 5 | 0.64 | [11, 11, -11, -13] | 27050 | 19.18 | 68 |
| dark 512 | 29473 | 36270 | 0 | 0.0 | [6, 6, -6, -7] | 6819 | 9.41 | 11 |
| dark 256 | 7528 | 9263 | 0 | 0.0 | [3, 3, -3, -4] | 1743 | 4.48 | 608 |
| dark 70 | 633 | 814 | 0 | 0.0 | [2, 1, -2, -2] | 181 | 0.91 | 181 |
| dark 40 | 238 | 295 | 0 | 0.0 | [1, 1, -1, -1] | 57 | 0.53 | 57 |
| clear 1024 | 116903 | 143632 | 0 | 0.0 | [11, 11, -11, -13] | 26813 | 19.09 | 36 |
| clear 512 | 29511 | 36269 | 0 | 0.0 | [6, 6, -6, -7] | 6764 | 9.42 | 3 |
| clear 256 | 7513 | 9194 | 0 | 0.0 | [3, 3, -3, -3] | 1685 | 4.56 | 537 |
| clear 70 | 619 | 767 | 0 | 0.0 | [1, 1, -1, -1] | 148 | 0.95 | 148 |
| clear 40 | 217 | 275 | 0 | 0.0 | [1, 1, -1, -1] | 58 | 0.4 | 58 |
| clearDark 1024 | 117199 | 143633 | 2 | 0.64 | [11, 11, -11, -13] | 26530 | 18.93 | 41 |
| clearDark 512 | 29628 | 36270 | 0 | 0.0 | [6, 6, -6, -7] | 6652 | 9.28 | 5 |
| clearDark 256 | 7551 | 9239 | 0 | 0.0 | [3, 3, -3, -4] | 1696 | 4.43 | 584 |
| clearDark 70 | 630 | 802 | 0 | 0.0 | [2, 1, -2, -1] | 172 | 0.84 | 172 |
| clearDark 40 | 230 | 292 | 0 | 0.0 | [1, 1, -1, -1] | 62 | 0.48 | 62 |

### T3 glass edge treatment (glass layer alone)

`n/a` below 256 px: too few pixels 30 px inside the edge to take a row reference. The
painted-outside count is measured at every size.

| mode / px | edge band px | band max depth | band p99 depth | depth as % of icon | painted outside silhouette |
|---|---|---|---|---|---|
| default 1024 | 10515 | 12.19 | 10.63 | 1.19 | 45 |
| default 512 | 2402 | 6.02 | 5.63 | 1.18 | 14 |
| default 256 | 487 | 2.96 | 2.76 | 1.16 | 3 |
| default 70 | n/a | n/a | n/a | n/a | 59 |
| default 40 | n/a | n/a | n/a | n/a | 29 |
| dark 1024 | 10604 | 11.31 | 10.3 | 1.1 | 39 |
| dark 512 | 2371 | 5.72 | 5.18 | 1.12 | 6 |
| dark 256 | 466 | 2.77 | 2.74 | 1.08 | 3 |
| dark 70 | n/a | n/a | n/a | n/a | 56 |
| dark 40 | n/a | n/a | n/a | n/a | 9 |
| clear 1024 | 9463 | 10.84 | 9.12 | 1.06 | 63 |
| clear 512 | 2111 | 5.38 | 4.54 | 1.05 | 25 |
| clear 256 | 438 | 2.53 | 2.33 | 0.99 | 8 |
| clear 70 | n/a | n/a | n/a | n/a | 28 |
| clear 40 | n/a | n/a | n/a | n/a | 10 |
| clearDark 1024 | 11705 | 13.38 | 11.77 | 1.31 | 54 |
| clearDark 512 | 2675 | 6.56 | 5.92 | 1.28 | 18 |
| clearDark 256 | 575 | 3.22 | 3.01 | 1.26 | 6 |
| clearDark 70 | n/a | n/a | n/a | n/a | 26 |
| clearDark 40 | n/a | n/a | n/a | n/a | 6 |

### T4 seams, the wall and the hole

The wall is measured, not assumed: inside the glass, the pixels where the paint under it makes no
difference to the composite. Its depth is the distance from the silhouette.

| mode / px | silhouette interior px | interior not opaque | wall px | wall % of key | wall max depth | inset px | inset not opaque | min distance from bare plate /255 | partial-alpha max dist from edge | hole px | hole px not plate |
|---|---|---|---|---|---|---|---|---|---|---|---|
| default 1024 | 159899 | 324 | 42438 | 26.5 | 18.91 | 156255 | 0 | 60.0 | 0.93 | 7703 | 0 |
| default 512 | 39667 | 86 | 10024 | 25.3 | 9.25 | 39016 | 3 | 102.0 | 1.13 | 1759 | 0 |
| default 256 | 9763 | 29 | 2201 | 22.5 | 4.37 | 9480 | 0 | 118.0 | 0.71 | 366 | 0 |
| default 70 | 649 | 78 | 20 | 3.1 | 0.84 | 595 | 39 | 158.0 | 1.49 | 4 | 0 |
| default 40 | 183 | 47 | 0 | 0.0 | 0.0 | 162 | 27 | 174.0 | 1.46 | 0 | 0 |
| dark 1024 | 159899 | 325 | 43171 | 27.0 | 19.18 | 156255 | 0 | 102.0 | 0.93 | 7703 | 0 |
| dark 512 | 39667 | 88 | 10203 | 25.7 | 9.41 | 39016 | 3 | 114.0 | 1.13 | 1759 | 0 |
| dark 256 | 9763 | 36 | 2239 | 22.9 | 4.48 | 9480 | 0 | 126.0 | 0.9 | 366 | 0 |
| dark 70 | 649 | 79 | 23 | 3.5 | 0.91 | 595 | 39 | 151.0 | 1.49 | 4 | 0 |
| dark 40 | 183 | 47 | 0 | 0.0 | 0.0 | 162 | 27 | 169.0 | 1.46 | 0 | 0 |
| clear 1024 | 159899 | 327 | 43013 | 26.9 | 19.09 | 156255 | 0 | 0.0 | 0.93 | 7703 | 0 |
| clear 512 | 39667 | 88 | 10159 | 25.6 | 9.42 | 39016 | 3 | 0.0 | 1.13 | 1759 | 0 |
| clear 256 | 9763 | 37 | 2252 | 23.1 | 4.56 | 9480 | 0 | 0.0 | 0.9 | 366 | 0 |
| clear 70 | 649 | 79 | 32 | 4.9 | 0.95 | 595 | 39 | 16.0 | 1.49 | 4 | 0 |
| clear 40 | 183 | 47 | 0 | 0.0 | 0.0 | 162 | 27 | 25.0 | 1.46 | 0 | 0 |
| clearDark 1024 | 159899 | 327 | 42722 | 26.7 | 18.93 | 156255 | 0 | 0.0 | 0.93 | 7703 | 0 |
| clearDark 512 | 39667 | 88 | 10044 | 25.3 | 9.28 | 39016 | 3 | 0.0 | 1.13 | 1759 | 0 |
| clearDark 256 | 9763 | 37 | 2216 | 22.7 | 4.43 | 9480 | 0 | 1.0 | 0.9 | 366 | 0 |
| clearDark 70 | 649 | 79 | 22 | 3.4 | 0.84 | 595 | 39 | 48.0 | 1.49 | 4 | 0 |
| clearDark 40 | 183 | 47 | 0 | 0.0 | 0.0 | 162 | 27 | 60.0 | 1.46 | 0 | 0 |

### T5 refraction: the icon with refraction on against the same icon with it off

| mode / px | px moved | % of silhouette | max depth moved | median depth | p95 depth | % within 8 px | max colour change /255 |
|---|---|---|---|---|---|---|---|
| default 1024 | 29131 | 18.22 | 20.08 | 13.79 | 19.39 | 4.6 | 77.0 |
| default 512 | 7834 | 19.75 | 10.26 | 6.72 | 9.83 | 68.3 | 76.0 |
| default 256 | 2168 | 22.21 | 5.35 | 3.38 | 5.02 | 100.0 | 76.0 |
| default 70 | 192 | 29.58 | 2.05 | 1.21 | 1.93 | 100.0 | 56.0 |
| default 40 | 48 | 26.23 | 1.28 | 1.02 | 1.26 | 100.0 | 39.0 |
| dark 1024 | 29949 | 18.73 | 20.41 | 13.91 | 19.74 | 4.6 | 94.0 |
| dark 512 | 8037 | 20.26 | 10.45 | 6.82 | 10.0 | 66.7 | 94.0 |
| dark 256 | 2257 | 23.12 | 5.46 | 3.49 | 5.22 | 100.0 | 93.0 |
| dark 70 | 199 | 30.66 | 2.09 | 1.23 | 1.95 | 100.0 | 68.0 |
| dark 40 | 65 | 35.52 | 1.46 | 1.05 | 1.27 | 100.0 | 49.0 |
| clear 1024 | 29097 | 18.2 | 92.73 | 13.91 | 19.57 | 3.3 | 12.0 |
| clear 512 | 7755 | 19.55 | 46.46 | 6.87 | 9.96 | 66.8 | 12.0 |
| clear 256 | 2099 | 21.5 | 23.32 | 3.55 | 5.15 | 96.2 | 12.0 |
| clear 70 | 169 | 26.04 | 2.04 | 1.18 | 1.64 | 100.0 | 8.0 |
| clear 40 | 35 | 19.13 | 1.28 | 0.98 | 1.2 | 100.0 | 7.0 |
| clearDark 1024 | 28492 | 17.82 | 61.91 | 13.69 | 19.16 | 4.2 | 24.0 |
| clearDark 512 | 7725 | 19.47 | 30.98 | 6.71 | 9.77 | 68.6 | 24.0 |
| clearDark 256 | 2140 | 21.92 | 9.4 | 3.37 | 5.01 | 100.0 | 24.0 |
| clearDark 70 | 187 | 28.81 | 2.7 | 1.18 | 1.86 | 100.0 | 17.0 |
| clearDark 40 | 52 | 28.42 | 1.28 | 1.03 | 1.26 | 100.0 | 13.0 |

### Small sizes from renders/: what the hole and the bevel do

| appearance / px | face px | face px in key | hole diameter px | hole px | hole px not plate |
|---|---|---|---|---|---|
| default 1024 | 117461 | 73.5 % | 103.1 | 7703 | 0 |
| default 512 | 29643 | 74.7 % | 51.5 | 1759 | 0 |
| default 256 | 7562 | 77.5 % | 25.8 | 366 | 0 |
| default 70 | 629 | 96.9 % | 7.0 | 4 | 0 |
| default 40 | 183 | 100.0 % | 4.0 | 0 | 0 |
| dark 1024 | 116728 | 73.0 % | 103.1 | 7703 | 0 |
| dark 512 | 29464 | 74.3 % | 51.5 | 1759 | 0 |
| dark 256 | 7524 | 77.1 % | 25.8 | 366 | 0 |
| dark 70 | 626 | 96.5 % | 7.0 | 4 | 0 |
| dark 40 | 183 | 100.0 % | 4.0 | 0 | 0 |
| clear 1024 | 116886 | 73.1 % | 103.1 | 7703 | 0 |
| clear 512 | 29508 | 74.4 % | 51.5 | 1759 | 0 |
| clear 256 | 7511 | 76.9 % | 25.8 | 366 | 0 |
| clear 70 | 617 | 95.1 % | 7.0 | 4 | 0 |
| clear 40 | 183 | 100.0 % | 4.0 | 0 | 0 |
| clearDark 1024 | 117177 | 73.3 % | 103.1 | 7703 | 0 |
| clearDark 512 | 29623 | 74.7 % | 51.5 | 1759 | 0 |
| clearDark 256 | 7547 | 77.3 % | 25.8 | 366 | 0 |
| clearDark 70 | 627 | 96.6 % | 7.0 | 4 | 0 |
| clearDark 40 | 183 | 100.0 % | 4.0 | 0 | 0 |

### Against the shipped three-key version, and against the first v4 pass

| | three keys (shipped) | v4 first pass | this pass |
|---|---|---|---|
| artwork | three keys, three colours | one key, one hue | one key, one hue |
| layers | three glass layers | glass + full-size paint | glass + paint inset 8 pt |
| refraction | 6 (+64 pt) | +100 (+640 pt) | −10 (−64 pt) |
| what the bevel shows | almost nothing | the far side of the shape | the margin between pane and paint |
| bevel | 2 % | 4.5 % | 4.5 % |
| specular gains | 150 / 150 / 150 | 250 / 250 / 300 | 180 / 0 / 240 |
| the face's shading | flat fill | painted ramp | the pane's tint ramp and translucency |
| wall (T4, 1024) | none | 15.7 % "plate showing", uneven | 26.5 %, one band all the way round |
| Clear sizes | 1024–256 | 1024–40 | 1024–40 |

The shipped version had 64 pt of displacement inside a 2 % bevel on a fill the engine never refracts
against a white plate: flat colour with a thin rim. The first pass fixed the refraction but left the
shading in the paint and the specular too broad. This pass moves the shading into the pane, narrows the
specular, and cuts the paint back so the bevel has a real margin to show.

### What is still not glass

At 1:1 the key reads as a bevelled slab of tinted glass with a painted back, not as a solid block of
glass: the face is a vertical ramp, and the thickness is carried by the wall and the rim rather than by
anything inside the volume. In Dark the read is the strongest, because the wall goes dark and the
silhouette gets a real dark edge. In Default the wall must be pale, and at 70 px the wall is under a
pixel wide, so the small size is a key with a bright rim and no chamfer.
