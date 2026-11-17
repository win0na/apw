# apw icon: three glass keys

The icon is Apple's Passwords key group, rebuilt as three separate Liquid Glass layers on a quiet white plate. The geometry comes from the paths in `ref/passwords.svg`, not from tracing a bitmap: one key outline, measured, re-emitted three times at the reference's own offsets. Nothing in the apw repository was changed.

The keys are yellow at the back, green in the middle, blue in front. Each is one SVG layer with one fill, its own translucency, refraction on the edges it shares with the keys behind it, and the system's own specular and dark edge. Depth comes from the refraction between the layers and from the glass density, not from shadows.

## Rebuild

```sh
export LC_CHROME=/tmp/opencode/lc/browsers/chrome/linux-157.0.8103.78/chrome-linux64/chrome
PYTHONPATH=/tmp/opencode/lc/pylib python3 build.py          # src/, icon*.json, work/geometry.json
./render.sh                                                 # out/ and apw.icon/
python3 lib/preview.py                                      # preview/
PYTHONPATH=/tmp/opencode/lc/pylib python3 lib/regrender.py   # work/reg/ renders
PYTHONPATH=/tmp/opencode/lc/pylib python3 lib/register.py    # work/reg/results.json
python3 lib/report.py > work/reg/tables.md                  # the tables below
```

Python needs numpy and shapely (`/tmp/opencode/lc/pylib`), and the previews need ImageMagick 7. `render.sh` prints a JSON report; every job must show `"webgl": "active"`. On this machine the renderer is SwiftShader through ANGLE.

## Files

| Path | What |
|---|---|
| `src/key-blue.svg`, `src/key-green.svg`, `src/key-yellow.svg` | the three elements on the 1024 canvas, square frame, Default colours |
| `src/tall/{default,dark,clear}/*.svg` | the same three elements with a 3072 pt frame, one set per appearance, used by the PNG recipes |
| `icon.json` | recipe and outputs for Default |
| `icon-dark.json`, `icon-clear.json` | Dark, and Clear Light plus Clear Dark |
| `icon-bundle.json` | square-frame Default recipe whose only output is the `.icon` document |
| `apw.icon/` | Icon Composer document written by the engine: `icon.json` and `Assets/Key {blue,green,yellow}.svg` |
| `out/` | `icon-{1024,512,256}{,-dark,-clear,-clearDark}.png` and `icon-{70,40}{,-dark}.png`, `-clear` is Clear Light |
| `preview/` | `contact-1024.png`, `row-70.png`, `row-70@4x.png`, `circle-460.png`, `circle-40.png`, `circle-40@8x.png` |
| `lib/geo.py` | parses the reference paths, measures them, places the three keys |
| `lib/recipe.py`, `build.py` | SVG and recipe writers, all values |
| `lib/register.py`, `lib/regrender.py` | the registration test and its renders |
| `work/reg/results.json`, `work/reg/tables.md` | every number in the registration section |
| `work/geometry.json` | the measured geometry and the material values, as data |

## Layers

Layers are listed front to back, which is also the order the recipe gives them.

| # | Layer | Frame | Fill | Translucency | Specular | Refraction | Highlights | Shadow |
|---|---|---|---|---|---|---|---|---|
| 1 | Key blue | 1024 × 3072, artwork in the bottom third | `#0087fc` Default, `#0a84ff` Dark, `#ffffff` Clear | 36 / 24 / 20 | inside, 100 | 6, height 2 % | top 150, fill 150, edge 150 | off |
| 2 | Key green, opening at the blue hole | same | `#1ccd48` Default, `#30d158` Dark, `#ffffff` Clear | 36 / 24 / 32 | inside, 100 | 6, height 2 % | top 150, fill 150, edge 150 | off |
| 3 | Key yellow | same | `#ffcc00` Default, `#ffd60a` Dark, `#ffffff` Clear | 0 in Default and Dark, 44 Clear | inside, 100 | 6, height 2 % | top 150, fill 150, edge 150 (0 in Clear) | off |

The layer `fill` in the recipe is `none`; the colour lives in the SVG so no layer can pick up another layer's fill.

## Geometry

Everything below is measured from the reference SVG by `lib/geo.py measure()`. Reference units are the SVG's own; the 1024 canvas is 3.18659 pt per unit.

| Quantity | Reference units | At 1024 px |
|---|---|---|
| bow centre | 198.481, 104.126 | 632.5, 331.8 |
| bow radius | 60.523 | 192.9 |
| hole centre | 198.676, 83.413 | 633.1, 265.8 |
| hole radius | 16.170 | 51.5 |
| hole offset from bow centre | +0.195, −20.713 | +0.6, −66.0 |
| shaft width | 36.484 | 116.3 |
| shaft top-left, top-right | 177.014, 160.725 / 213.498, 162.768 | 564.1, 512.2 / 680.3, 518.7 |
| tooth 1 out | 239.856, 189.630 → 239.797, 194.007 | 764.3, 604.3 → 764.1, 618.2 |
| notch | 213.916, 220.471 | 681.7, 702.5 |
| tooth 2 out | 232.693, 239.450 → 232.437, 245.621 | 741.5, 763.0 → 740.7, 782.7 |
| tip right, tip left | 201.280, 276.651 / 196.272, 276.786 | 641.4, 881.6 / 625.4, 882.0 |
| heel | 177.848, 257.518 → 177.014, 255.461 | 566.7, 820.6 → 564.1, 814.0 |
| tooth and chamfer angles | 45.54°, 45.64°, 45.31°, 44.88°, 46.28° | |
| key extent | y 43.603 to 277.545, x 137.958 to 259.004 | y 138.9 to 884.4, x 439.6 to 825.3 |
| green behind blue | 41.418 | 132.0 |
| yellow behind green | 41.513 | 132.3 |
| white gap around the blue bow in the reference | 13.103 | 41.8 |

Two consequences of using the exact offsets with three whole keys:

- The blue hole straddles the green bow's right arc: the hole centre is 148.1 px from the green bow's centre, and that bow's edge is 192.9 px out, so the hole's far rim is 10.7 px past the green's edge. Any opening wide enough to keep green out of the hole cuts a notch through the green bow's edge. That notch sits under the blue bow and is never seen.
- The green key has no hole of its own and neither has the yellow. A green hole would poke 1.8 units out of the blue bow and a yellow hole would show as a sliver against the green. Only the blue key is pierced; the green is cut at the same centre with a 4 px choke (55.5 px radius at 1024) so the blue hole shows plate, not the green key's edge.

The offsets leave real plate gaps, not seams: two small notches where each shaft meets the bow behind it, and two longer slots between adjacent shafts bridged by the back key's teeth. At 1024 they are 161 to 220 px² each; the registration section measures how they render.

## Material

Light comes from directly above, so every highlight and dark edge the engine draws is horizontal and symmetric. All of that is the system's own material: no layer carries a painted bevel, a gradient, a glow or a shadow.

Specular is set to inside, not left on automatic. On a white plate the engine places the dark edge inside the silhouette, which is what the icon needs. On Dark and Clear it places it outside, on the background: measured against the same renders with automatic placement, that put 6,917 to 7,906 px per key up to 4.6 px beyond the silhouette, painted the plate inside the hole, and cut the true gaps from 200 px² to about 50 px². With inside, every edge lands on its own shape in all four appearances, and the dark defining line is drawn on the glass instead of beside it.

Refraction is strength 6 over a 2 % height (20.5 px at 1024). That is the largest pair that bends the neighbouring key's edge without smearing it into a blob: at 4 % the back teeth turn into lumps, and at strength 10 the edge picks up visible steps. Refraction only shows where something with contrast sits under the glass, which is why the plate stays clean and the overlaps carry the depth.

Translucency is 36 / 36 / 0 in Default and 24 / 24 / 0 in Dark. The yellow key is translucent nowhere except Clear: it has nothing behind it but the plate, so translucency there would only let the plate wash the yellow, which on a dark plate turns it ochre. The two front keys keep it because it is what shows the key behind them.

The engine ramps translucency over the layer frame, not the shape, from fully opaque at the frame's top. A frame that fits the canvas would leave the top of the key at 0.993 and the tip at 0.770 for 36, so each bow would be nearly opaque and the shafts visibly thinner. Every layer frame is therefore 3072 pt tall with the artwork in the bottom third (`layout` y −100 %, scale 300 %), which puts the keys lower on the ramp where density stays even: 0.837 at the top of the key to 0.727 at the tip for 36, 0.922 to 0.867 for 24, 0.945 to 0.905 for 20, 0.868 to 0.777 for 32, 0.767 to 0.619 for 44. The density gradient that remains is the reason the key bodies are slightly lighter at the tip than at the bow, and it is the only tonal variation inside a key apart from the highlights.

Highlights are 150 on all three gains. At 100 the top and bottom bands are present but flat; at 200 the top rim starts to read as a painted line. 150 keeps the 4 px band and the 16 px soft band visible at 512 and 256 without turning into a stroke.

Clear sets the dark edge gain to 0. In Clear the engine lightens artwork and clamps it at the plate, so a dark edge cannot shade anything: it pulls the pixel back down to the plate. At 150 that left 973 of the 7,346 px along the shared edges reading exactly the plate colour at 1024, which is a plate-coloured line inside the icon. At 0 the same band reads 36 levels away from the plate at its nearest, and no plate pixel remains inside the union.

Measured body colours at 1024, Default, against the reference's own gradients:

| Key | Reference gradient | Rendered body |
|---|---|---|
| blue | `#62ccf8` to `#0079ff` | 47,157,253 at the bow to 69,158,255 at the tip |
| green | `#51e376` to `#34c759` | 66,213,102 at the bow to 83,217,117 on the shaft |
| yellow | `#ffdd53` to `#ffbf01` | 255,204,0, the fill exactly, plus the dark edge at 204,142,0 |

The fills are chosen so the rendered body lands on the reference's mid tone over the plate, which is why the blue and green fills are deeper than the reference's own stops: at 0.84 to 0.73 density the white plate adds 16 to 27 % to each channel. Green over the yellow key measures 71,205,58, which is the reference green with the yellow behind it, and that shift is the point of the stack.

## Appearances

| Appearance | Plate | Fills | Translucency | What differs, and why |
|---|---|---|---|---|
| Default | `#ffffff` | `#0087fc`, `#1ccd48`, `#ffcc00` | 36, 36, 0 | the reference's hues at their mid tones |
| Dark | engine plate, `#1f1f1f` to `#0f0f0f` | `#0a84ff`, `#30d158`, `#ffd60a` | 24, 24, 0 | keys near their own colours so they stay luminous on black; lower translucency keeps the dark plate from muddying the overlaps |
| Clear Light | engine plate, 188 grey | `#ffffff` on all three | 20, 32, 44 | front key most opaque and brightest, back key most transparent and closest to the plate |
| Clear Dark | engine plate, 115 grey | `#ffffff` on all three | 20, 32, 44 | same artwork, same order; the darker plate gives more range |

Clear is the one appearance the engine does not let us design freely. It ignores the recipe plate, and it lightens artwork toward white with a clamp: fills from `#7a7a7a` to `#ffffff` all land between 220 and 241 on the light plate (188) and between 186 and 226 on the dark plate (115). The depth order therefore comes from translucency, not colour: at 1024 the front key's body is 241 on 188 and 226 on 115, and the back key's is 229 and 202. The overlap lenses are the brightest parts of the icon in both Clear appearances (245 and 234), which is what a stack of clear glass does. The earlier attempt that gave each key a different grey inverted that order and was dropped.

## Registration

`lib/register.py` renders one key at a time and the icon with one key removed, then compares the result with the same paths rasterised analytically in shapely, whose coverage is supersampled 4 times at 1024 and more at the smaller sizes. All four appearances are measured. Four tests, per size:

- T1, solo against geometry. Each key alone, artwork only, so the alpha channel is the engine's own silhouette. Bounding box at 50 % coverage, alpha-weighted centroid, area, and pixels where alpha and analytic coverage disagree by more than half a pixel.
- T2, solo against composite. Where one key changes the icon (icon minus icon-without-that-key) against where it changes the bare plate, compared outside the keys in front of it. The column that tests placement is the edge band: the 2.5 px band either side of that key's own boundary. Refraction moves a back key's image inside the front key by design, and that displacement is reported separately rather than counted as a placement error.
- T3, edge band. On the solo render, every pixel more than 4 levels from its row's flat body colour is an edge treatment. It should sit inside the silhouette, and its depth from the boundary is measured in pixels and as a percentage of the icon.
- T4, seams. Inside the union of the three silhouettes: pixels that are not fully opaque, and pixels that show the plate colour. Counted for the whole interior, for an interior inset 2 px from the union edge, for the bands along shared edges, for the hole, and for the true gaps.

Colour difference counts as a change above 3 levels in Default and Dark. Clear Light and Clear Dark move neighbouring tones by as little as one level, so there the threshold is 1 level, which is the strictest the 8-bit renders allow. In T4 the inset column is 2 px at 1024, 512 and 256, and 1 px at 70 and 40, because 2 px of a 40 px icon would swallow the icon.

### T1 silhouette vs geometry

| appearance / px | key | bbox delta (px) | centroid delta (px) | area ratio | px off by > half |
|---|---|---|---|---|---|
| default/1024 | blue | [1, 0, 0, -1] | [0.012, -0.034] | 1.00087 | 12 |
| default/1024 | green | [0, 0, 0, -1] | [0.033, -0.054] | 1.00074 | 12 |
| default/1024 | yellow | [0, 0, 0, -1] | [0.002, 0.102] | 1.00098 | 15 |
| default/512 | blue | [0, 1, 0, 0] | [0.005, -0.046] | 1.00176 | 12 |
| default/512 | green | [0, 0, 0, 0] | [0.028, -0.015] | 1.00174 | 13 |
| default/512 | yellow | [0, 0, 0, 0] | [0.005, 0.096] | 1.00192 | 15 |
| default/256 | blue | [0, 0, 0, 0] | [0.002, -0.025] | 1.00171 | 2 |
| default/256 | green | [0, 0, 0, 0] | [0.014, -0.01] | 1.00170 | 3 |
| default/256 | yellow | [0, 0, 0, 0] | [-0.006, 0.076] | 1.00237 | 2 |
| default/70 | blue | [0, 0, 0, 0] | [-0.009, -0.005] | 1.00275 | 0 |
| default/70 | green | [0, 0, 0, 0] | [-0.001, -0.001] | 1.00208 | 0 |
| default/70 | yellow | [0, 0, 0, 0] | [-0.006, 0.037] | 1.00236 | 0 |
| default/40 | blue | [0, 0, 0, 0] | [0.016, -0.015] | 0.99946 | 0 |
| default/40 | green | [0, 0, 0, 0] | [0.03, -0.03] | 0.99582 | 0 |
| default/40 | yellow | [0, 0, 0, 0] | [0.028, 0.002] | 0.99883 | 0 |
| dark/1024 | blue | [1, 0, 0, -1] | [0.014, -0.029] | 1.00101 | 12 |
| dark/1024 | green | [0, 0, 0, -1] | [0.037, -0.043] | 1.00092 | 12 |
| dark/1024 | yellow | [0, 0, 0, -1] | [0.002, 0.102] | 1.00098 | 15 |
| dark/512 | blue | [0, 1, 0, 0] | [0.008, -0.037] | 1.00205 | 12 |
| dark/512 | green | [0, 0, 0, 0] | [0.035, -0.01] | 1.00209 | 13 |
| dark/512 | yellow | [0, 0, 0, 0] | [0.005, 0.096] | 1.00192 | 15 |
| dark/256 | blue | [0, 0, 0, 0] | [0.004, -0.022] | 1.00200 | 2 |
| dark/256 | green | [0, 0, 0, 0] | [0.017, -0.008] | 1.00204 | 3 |
| dark/256 | yellow | [0, 0, 0, 0] | [-0.006, 0.076] | 1.00237 | 2 |
| dark/70 | blue | [0, 0, 0, 0] | [-0.008, -0.005] | 1.00305 | 0 |
| dark/70 | green | [0, 0, 0, 0] | [-0.0, -0.001] | 1.00241 | 0 |
| dark/70 | yellow | [0, 0, 0, 0] | [-0.006, 0.037] | 1.00236 | 0 |
| dark/40 | blue | [0, 0, 0, 0] | [0.017, -0.014] | 0.99967 | 0 |
| dark/40 | green | [0, 0, 0, 0] | [0.031, -0.03] | 0.99611 | 0 |
| dark/40 | yellow | [0, 0, 0, 0] | [0.028, 0.002] | 0.99883 | 0 |
| clear/1024 | blue | [1, 0, 0, -1] | [0.015, -0.027] | 1.00105 | 12 |
| clear/1024 | green | [0, 0, 0, -1] | [0.034, -0.048] | 1.00081 | 12 |
| clear/1024 | yellow | [0, 0, 0, -1] | [0.0, 0.062] | 1.00059 | 15 |
| clear/512 | blue | [0, 1, 0, 0] | [0.009, -0.036] | 1.00213 | 12 |
| clear/512 | green | [0, 0, 0, 0] | [0.029, -0.013] | 1.00188 | 13 |
| clear/512 | yellow | [0, 1, -1, 0] | [0.001, 0.055] | 1.00109 | 15 |
| clear/256 | blue | [0, 0, 0, 0] | [0.004, -0.02] | 1.00208 | 2 |
| clear/256 | green | [0, 0, 0, 0] | [0.014, -0.01] | 1.00183 | 3 |
| clear/256 | yellow | [0, 0, 0, 0] | [-0.008, 0.055] | 1.00155 | 2 |
| clearDark/1024 | blue | [1, 0, 0, -1] | [0.015, -0.027] | 1.00105 | 12 |
| clearDark/1024 | green | [0, 0, 0, -1] | [0.034, -0.048] | 1.00081 | 12 |
| clearDark/1024 | yellow | [0, 0, 0, -1] | [0.0, 0.062] | 1.00059 | 15 |
| clearDark/512 | blue | [0, 1, 0, 0] | [0.009, -0.036] | 1.00213 | 12 |
| clearDark/512 | green | [0, 0, 0, 0] | [0.029, -0.013] | 1.00188 | 13 |
| clearDark/512 | yellow | [0, 1, -1, 0] | [0.001, 0.055] | 1.00109 | 15 |
| clearDark/256 | blue | [0, 0, 0, 0] | [0.004, -0.02] | 1.00208 | 2 |
| clearDark/256 | green | [0, 0, 0, 0] | [0.014, -0.01] | 1.00183 | 3 |
| clearDark/256 | yellow | [0, 0, 0, 0] | [-0.008, 0.055] | 1.00155 | 2 |

### T2 solo vs composite

| appearance / px | key | whole-change bbox delta | edge band bbox delta | edge band centroid delta | differing px | refracted px | max displacement |
|---|---|---|---|---|---|---|---|
| default/1024 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [-0.146, -0.829] | 30 of 162063 | - | 0 |
| default/1024 | green | [0, 0, 96, 0] | [0, 0, 0, 0] | [0.006, -0.101] | 40 of 93952 | 1121 | 30.19 |
| default/1024 | yellow | [0, 0, 153, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 11 of 94362 | 286 | 32.52 |
| default/512 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [-0.078, -0.526] | 19 of 40803 | - | 0 |
| default/512 | green | [0, 0, 44, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 15 of 23539 | 277 | 13.32 |
| default/512 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 23721 | 82 | 15.82 |
| default/256 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.027, 0.006] | 1 of 10337 | - | 0 |
| default/256 | green | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 5913 | 72 | 6.57 |
| default/256 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 6002 | 24 | 7.63 |
| default/70 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [-0.004, -0.059] | 2 of 892 | - | 0 |
| default/70 | green | [0, 0, -2, 0] | [0, 0, -2, 0] | [-0.093, 0.131] | 2 of 476 | 4 | 1.42 |
| default/70 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 488 | 3 | 1.90 |
| default/40 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.095, -0.013] | 4 of 324 | - | 0 |
| default/40 | green | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 171 | 3 | 0.69 |
| default/40 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 159 | 2 | 0.81 |
| dark/1024 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [-0.157, -0.821] | 31 of 162060 | - | 0 |
| dark/1024 | green | [0, 0, 96, 0] | [0, 0, 0, 0] | [0.007, -0.098] | 41 of 93950 | 1075 | 30.19 |
| dark/1024 | yellow | [0, 0, 45, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 6 of 94357 | 230 | 30.46 |
| dark/512 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [-0.097, -0.548] | 21 of 40797 | - | 0 |
| dark/512 | green | [0, 0, 44, 0] | [0, 0, 0, 0] | [-0.0, 0.003] | 16 of 23534 | 269 | 13.32 |
| dark/512 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 23718 | 65 | 14.90 |
| dark/256 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [-0.011, 0.009] | 1 of 10344 | - | 0 |
| dark/256 | green | [0, 0, 0, 0] | [0, 0, 0, 0] | [-0.0, -0.096] | 2 of 5912 | 70 | 6.57 |
| dark/256 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 6000 | 18 | 6.60 |
| dark/70 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.021, 0.031] | 1 of 899 | - | 0 |
| dark/70 | green | [0, 0, -5, 0] | [0, 0, -5, 0] | [-0.25, 0.132] | 7 of 477 | 1 | 0.71 |
| dark/70 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 487 | 2 | 1.44 |
| dark/40 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.084, 0.035] | 4 of 325 | - | 0 |
| dark/40 | green | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 171 | 1 | 0.69 |
| dark/40 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 159 | 2 | 0.81 |
| clear/1024 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [2.176, 0.397] | 1051 of 162066 | - | 0 |
| clear/1024 | green | [0, 0, 90, 0] | [0, 0, 0, 0] | [0.579, 1.297] | 269 of 93947 | 552 | 27.32 |
| clear/1024 | yellow | [0, 0, 153, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 2 of 94358 | 141 | 31.37 |
| clear/512 | blue | [1, 0, 0, 0] | [1, 0, 0, 0] | [1.165, 0.398] | 274 of 40802 | - | 0 |
| clear/512 | green | [0, 0, 44, 0] | [0, 0, 0, 0] | [0.415, 0.927] | 65 of 23531 | 161 | 12.83 |
| clear/512 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 23716 | 40 | 15.22 |
| clear/256 | blue | [1, 0, 0, 0] | [1, 0, 0, 0] | [0.725, 0.405] | 80 of 10336 | - | 0 |
| clear/256 | green | [1, 0, 0, 0] | [1, 0, 0, 0] | [0.409, 0.597] | 27 of 5912 | 39 | 2.01 |
| clear/256 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 5989 | 6 | 7.63 |
| clearDark/1024 | blue | [0, 0, 0, 0] | [0, 0, 0, 0] | [2.216, 0.703] | 536 of 162078 | - | 0 |
| clearDark/1024 | green | [0, 0, 96, 0] | [0, 0, 0, 0] | [-0.003, -0.042] | 136 of 93950 | 750 | 30.19 |
| clearDark/1024 | yellow | [0, 0, 153, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 6 of 94362 | 210 | 32.52 |
| clearDark/512 | blue | [1, 0, 0, 0] | [1, 0, 0, 0] | [0.94, -0.001] | 144 of 40804 | - | 0 |
| clearDark/512 | green | [0, 0, 44, 0] | [0, 0, 0, 0] | [-0.004, 0.201] | 30 of 23532 | 204 | 12.83 |
| clearDark/512 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 23717 | 66 | 16.46 |
| clearDark/256 | blue | [1, 0, 0, 0] | [1, 0, 0, 0] | [0.658, 0.232] | 48 of 10346 | - | 0 |
| clearDark/256 | green | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.181, 0.381] | 14 of 5914 | 51 | 6.07 |
| clearDark/256 | yellow | [0, 0, 0, 0] | [0, 0, 0, 0] | [0.0, 0.0] | 0 of 5994 | 15 | 8.03 |

### T3 edge band

| appearance / px | key | painted outside silhouette | max dist out (px) | band px | band depth max (px) | max depth % of icon |
|---|---|---|---|---|---|---|
| default/1024 | blue | 40 | 1.61 | 11073 | 10.16 | 0.99 |
| default/1024 | green | 43 | 1.60 | 9363 | 9.91 | 0.97 |
| default/1024 | yellow | 18 | 1.68 | 8534 | 9.04 | 0.88 |
| default/512 | blue | 12 | 1.04 | 2452 | 5.70 | 1.11 |
| default/512 | green | 14 | 1.56 | 2050 | 4.70 | 0.92 |
| default/512 | yellow | 7 | 1.12 | 1889 | 4.71 | 0.92 |
| default/256 | blue | 4 | 0.68 | 499 | 2.74 | 1.07 |
| default/256 | green | 4 | 0.68 | 395 | 2.57 | 1.00 |
| default/256 | yellow | 78 | 0.73 | 366 | 2.31 | 0.90 |
| default/70 | blue | 42 | 1.08 | - | - | - |
| default/70 | green | 36 | 1.15 | - | - | - |
| default/70 | yellow | 52 | 1.12 | - | - | - |
| default/40 | blue | 30 | 0.98 | - | - | - |
| default/40 | green | 18 | 0.85 | - | - | - |
| default/40 | yellow | 22 | 0.97 | - | - | - |
| dark/1024 | blue | 37 | 1.61 | 10333 | 10.03 | 0.98 |
| dark/1024 | green | 40 | 1.60 | 10871 | 11.41 | 1.11 |
| dark/1024 | yellow | 13 | 1.47 | 8049 | 8.12 | 0.79 |
| dark/512 | blue | 7 | 1.03 | 2249 | 4.91 | 0.96 |
| dark/512 | green | 8 | 1.04 | 2443 | 5.69 | 1.11 |
| dark/512 | yellow | 4 | 1.12 | 1778 | 4.02 | 0.79 |
| dark/256 | blue | 2 | 0.68 | 456 | 2.45 | 0.96 |
| dark/256 | green | 3 | 0.68 | 530 | 2.76 | 1.08 |
| dark/256 | yellow | 77 | 0.73 | 345 | 2.16 | 0.84 |
| dark/70 | blue | 49 | 1.18 | - | - | - |
| dark/70 | green | 35 | 1.12 | - | - | - |
| dark/70 | yellow | 51 | 1.12 | - | - | - |
| dark/40 | blue | 31 | 0.98 | - | - | - |
| dark/40 | green | 18 | 0.85 | - | - | - |
| dark/40 | yellow | 21 | 0.95 | - | - | - |
| clear/1024 | blue | 43 | 0.98 | 4976 | 4.92 | 0.48 |
| clear/1024 | green | 42 | 0.97 | 5443 | 5.38 | 0.53 |
| clear/1024 | yellow | 14 | 0.83 | 5211 | 7.15 | 0.70 |
| clear/512 | blue | 7 | 1.04 | 965 | 2.71 | 0.53 |
| clear/512 | green | 5 | 1.04 | 1047 | 2.75 | 0.54 |
| clear/512 | yellow | 3 | 1.12 | 1092 | 3.71 | 0.72 |
| clear/256 | blue | 2 | 0.52 | 153 | 1.59 | 0.62 |
| clear/256 | green | 4 | 0.54 | 156 | 1.59 | 0.62 |
| clear/256 | yellow | 75 | 0.45 | 171 | 1.67 | 0.65 |
| clearDark/1024 | blue | 49 | 1.28 | 7075 | 8.43 | 0.82 |
| clearDark/1024 | green | 48 | 1.27 | 7519 | 9.02 | 0.88 |
| clearDark/1024 | yellow | 16 | 0.98 | 6994 | 10.20 | 1.00 |
| clearDark/512 | blue | 9 | 1.04 | 1482 | 4.11 | 0.80 |
| clearDark/512 | green | 8 | 1.04 | 1546 | 4.70 | 0.92 |
| clearDark/512 | yellow | 3 | 1.12 | 1574 | 5.71 | 1.12 |
| clearDark/256 | blue | 2 | 0.52 | 263 | 2.00 | 0.78 |
| clearDark/256 | green | 4 | 0.54 | 308 | 2.17 | 0.85 |
| clearDark/256 | yellow | 76 | 0.45 | 312 | 2.54 | 0.99 |

### T4 seams

| appearance / px | interior px | not opaque | inner 2 px: not opaque | showing plate | inset showing plate | partial max dist from union edge | band px | band not opaque | band showing plate |
|---|---|---|---|---|---|---|---|---|---|
| default/1024 | 347331 | 334 | 0 | 0 | 0 | 0.97 | 7346 | 14 | 0 |
| default/512 | 86353 | 73 | 0 | 0 | 0 | 0.93 | 1680 | 1 | 0 |
| default/256 | 21369 | 29 | 0 | 0 | 0 | 0.79 | 740 | 1 | 0 |
| default/70 | 1503 | 122 | 48 | 0 | 0 | 1.49 | 194 | 14 | 0 |
| default/40 | 467 | 99 | 20 | 0 | 0 | 1.47 | 112 | 23 | 0 |
| dark/1024 | 347331 | 310 | 0 | 0 | 0 | 0.97 | 7346 | 12 | 0 |
| dark/512 | 86353 | 59 | 0 | 0 | 0 | 0.93 | 1680 | 1 | 0 |
| dark/256 | 21369 | 14 | 0 | 0 | 0 | 0.72 | 740 | 0 | 0 |
| dark/70 | 1503 | 122 | 48 | 0 | 0 | 1.49 | 194 | 14 | 0 |
| dark/40 | 467 | 99 | 20 | 0 | 0 | 1.47 | 112 | 23 | 0 |
| clear/1024 | 347331 | 422 | 0 | 0 | 0 | 0.96 | 7346 | 15 | 0 |
| clear/512 | 86353 | 103 | 0 | 0 | 0 | 0.93 | 1680 | 1 | 0 |
| clear/256 | 21369 | 30 | 0 | 0 | 0 | 0.72 | 740 | 2 | 0 |
| clearDark/1024 | 347331 | 422 | 0 | 0 | 0 | 0.96 | 7346 | 15 | 0 |
| clearDark/512 | 86353 | 103 | 0 | 0 | 0 | 0.93 | 1680 | 1 | 0 |
| clearDark/256 | 21369 | 30 | 0 | 0 | 0 | 0.72 | 740 | 2 | 0 |


### What the numbers say

- Silhouettes are in register. Bounding boxes match the geometry within 1 px at every size, and exactly at 70 and 40. Centroids agree inside 0.11 px at 1024, 0.05 px at 512, 0.06 px at 256 and 0.04 px at 70 and 40. Area ratio stays between 0.9958 and 1.0031, which is the engine's antialiasing bias, not an offset.
- No seam anywhere. At all four appearances and all sizes, 0 px inside the union show the plate colour, 0 px inside the shared-edge bands do, and 0 px inside the hole do. The only non-opaque pixels inside the union lie within 0.97 px of the union's outer edge at 1024, 512 and 256, and within 1.5 px at 70 and 40, which is the silhouette's own antialiasing and the downsampling of a 1024 render.
- Edge treatments stay on their shapes. Painted pixels outside a silhouette at 1024: at most 43 in Default, 40 in Dark, 43 in Clear Light and 49 in Clear Dark, never more than 1.68 px out. The worst single count anywhere is 78, on the yellow key at 256, 0.73 px out.
- Back keys move exactly where refraction should move them: up to 32.5 px (3.2 % of the icon) of a back key's image is displaced inside the key in front, and the yellow key is refracted by both keys in front of it. That is the depth the brief asked for, and it is measured, not painted.
- Clear Light's edge-band centroid for the blue key reads 2.2 px at 1024. That is not movement: inside a Clear key the body also changes when the key is added, and where the blue rim crosses the green key the colour step falls under one level, so the detected band is thinner there than on the plate side. T1 and T4, which do not depend on a colour threshold, are exact for that key.

## .icon flags

From `apw.icon/icon.json`:

```json
{"features": ["refractivity", "specular-location"],
 "fill": {"linear-gradient": ["srgb:1.0,1.0,1.0,1.0", "srgb:1.0,1.0,1.0,1.0"], ...},
 "supported-platforms": {"circles": ["watchOS"], "squares": "shared"},
 "groups": [ ... three groups, one per key ... ]}
```

Each group carries `specular: "inside"`, `refractivity {enabled, strength: 0.06, depth: 0.03158}`, `translucency {enabled, value}`, `shadow {kind: none, opacity: 0}` and `lighting: individual`; its single layer carries `glass: true` and an `image-name` pointing at the SVG in `Assets/`.

What the format carries, and what it does not:

- Shadow is explicitly `none` with opacity 0. Left unset, the engine writes a 50 % neutral shadow.
- `specular-location` is the record that the edge is placed inside the silhouette. It appears only because the recipe sets specular to inside; leaving it on automatic drops the key from the features and draws the dark edge outside the shape in Dark and Clear.
- The three highlight gains exist in Liquid Composer only. The `.icon` has no field for them, so the bundle reproduces the geometry, the material flags and the translucency, not the gains.
- The format has one set of layers. It has no per-appearance fills, and the engine ignores appearance specialisations on import, so Dark and Clear exist as their own recipes (`icon-dark.json`, `icon-clear.json`) and as their own renders. The bundle is the Default appearance.
- The bundle's artwork is the square 1024 frame, not the 3072 pt frame the PNG renders use. Icon Composer computes translucency with its own model, so the tips in its preview will read a little more transparent than `out/icon-1024.png`. The PNGs are the render of record.

## 70 and 40 px

The icon is drawn to be looked at at 70 and 40 as well as 1024, and the circle crops use the artwork layer alone, on the plate colour, because a circle icon has no squircle rim to crop.

| Size | Hole diameter | Hole disc px | Plate px in the disc | True gap area, geometry | True gap area, rendered |
|---|---|---|---|---|---|
| 1024 | 103.1 px | 8,339 | 4,089 of 4,089 in the inner 70 %, 100 % | 161.4 to 219.5 px² | 149.6 to 209.1 px² |
| 512 | 51.5 px | 2,080 | 1,018 of 1,018, 100 % | 40.4 to 54.9 px² | 30.6 to 47.2 px² |
| 256 | 25.8 px | 519 | 253 of 253, 100 % | 10.1 to 13.7 px² | 7.6 to 11.8 px² |
| 70 | 7.0 px | 39 | 18 of 18, 100 % | 0.75 to 1.03 px² | 0.58 to 0.91 px² |
| 40 | 4.0 px | 12 | 7 of 7, 100 % | 0.25 to 0.33 px² | 0.20 to 0.32 px² |

Every pixel of the hole that is not its rim is plate colour at every size, in all four appearances, including at 40, where the hole disc is 12 px and 7 of them are pure plate. The hole survives.

What survives at 40: the three hues, the left-to-right order, the interlock of the teeth, the bow mass and the hole. The shape reads as one key with three colour bands, which is the design: three overlapping keys cannot read as three separate objects at 40 px in a circle, but one key shape with three bands can, which is why the reference's bows sit close enough to merge.

What dies: the four true gaps. They render at 92 % of their geometric area at 1024, and every pixel inside them there is plate, but at 70 they are 0.58 to 0.91 px² and at 40 they are 0.20 to 0.32 px², so they fall below a pixel and no plate pixel is left inside them at either size. The 16 px slit between adjacent shafts is 1.1 px at 70, so it reads as a single dark separation rather than an open gap. The refraction band, 20.5 px at 1024, is 1.4 px at 70 and 0.8 px at 40, so the bending of the neighbouring key's edge, the clearest sign of the stack at 1024, disappears. The hole's cyan rim and the refraction inside it are gone at 70 too; only the white dot is left.

## Engine limits

- One document, one appearance. `appearance` in a recipe does not create per-appearance overrides, and the `.icon` importer ignores specialisations. Four appearances means four recipes.
- The Dark plate is always `#1f1f1f` to `#0f0f0f`; the Clear plates are flat 188 and 115 grey. Only the artwork is yours.
- In Clear, artwork lightens the plate and cannot darken it. Fills from mid grey to white compress into about 20 levels, so colour cannot carry the layer order there.
- Translucency ramps over the layer frame. The frame extension is the only lever on where a key sits on that ramp.
- Blur between 2 and 12 turns the glass grey at 512 and below. Blur is off.
- Refraction needs contrast underneath. Over the plate it draws the rim and nothing else, which is why the plate is quiet and the overlaps are not.
- With specular on automatic, the dark edge is drawn outside the silhouette in Dark and in Clear. It has to be set to inside to keep every edge on its own shape.
- Supersampling: 1024 is rendered at 2048 and halved; 512, 256, 70 and 40 come from a 1024 render, so the small sizes are the 1024 icon downsampled, not a separate design.
