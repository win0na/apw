# About the apw icon

The apw icon is a Liquid Glass app icon for iOS 27. It is used as the repository avatar and as the logo at
the top of the README, where it renders at 70 px. It shows one key on a white plate, in the material Apple
uses for its own icons, so that it sits beside them instead of reading as a flat logo.

The icon is a set of layered recipes rather than a drawing. Every size and appearance renders from the same
geometry, so nothing is redrawn by hand.

## The mark

The key is the blue key from Apple's Passwords icon. Its outline is measured from the reference's own
vector paths, not traced by eye, and re-emitted at 1024 pt: bow centre (512, 331.8), bow radius 192.9,
hole radius 51.5, shaft 116.3 wide, tip at y 882. `assets/icon/NOTES.md` lists every landmark.

The only change to the geometry is position. The reference places that key on the right of a three-key
group; here it moves 120.48 pt left, until the bow sits on the canvas centre line. Nothing is rescaled,
redrawn or stylised, and there is one hue.

## How the glass is built

The key is two layers in the same frame. `Key` is the glass pane; `Key face` is the paint, inset 8 pt
inside the pane so that the bevel has a margin to look through.

Two layers are necessary because the engine refracts what lies below a glass layer, never the layer's own
fill. A single tinted pane on a white plate cannot be both saturated and see-through: the composite is
`fill·A + plate·(1−A)`, so the red channel never falls below `255·(1−A)`.

Refraction runs negative, at −10 (64 pt outward). Positive strength samples past the paint's near edge, so
the bevel can only show the far side and the bow ends up without a wall. Negative strength looks outward
into the 8 pt margin and shows the paint's edge about 11 pt inside where it is painted. That band runs the
whole way round the key: 26.5 % of its pixels at 1024, reaching 18.9 px in from the silhouette.

Nothing is painted on top of the shape. There is no glow, no drop shadow, no blur, no frost, and no offset
copy of the outline pretending to be an edge. The paint is the same path, inset, so a seam would show if
the two were out of register; the tables in `NOTES.md` measure that they are not.

The material follows iOS 27: light comes from directly above, the specular is set inside the silhouette so
no highlight falls outside it, the bevel is 4.5 % of the icon, dispersion is 20, and translucency is 40.
Every render reports `state.webgl` as `active`; without WebGL2 the engine drops refraction and blur and the
icon is not the one that ships.

The plate is deliberately plain. Structure on the plate, such as rules, dots or rings, turns into contour
lines and moiré, so the only contrast the glass bends is the key's own paint.

## Appearances

Default puts the reference's blue on a white plate. Dark keeps the geometry and puts the brighter blue on a
graphite plate, so the walls sample dark instead of pale and the key gets the defining edges it lacks on
white. Clear Light and Clear Dark use the engine's own grey plates, where a layer can only lighten what is
below it; the key's depth there comes from its dark edge rather than from refraction.

All four appearances exist at 1024, 512, 256, 70 and 40 px. At 70 the key is 51 px tall and still reads as
a key: the silhouette, the zigzag and the hole survive, and the rim survives. The wall does not, at 3.1 %
of the key and under a pixel wide. At 40 the outline still reads in Default and Dark, but the hole is a
4 px dot and neither the wall nor the bevel is left; Clear Light is marginal there.

## The Icon Composer package

`assets/icon/apw.icon/` opens in Icon Composer and Xcode. It carries the `refractivity` and
`specular-location` features, so it needs Xcode 27. The format holds one layer set and ignores
per-appearance specialisations, so the package is the Default appearance; the PNGs are the render of
record. Two of the pane's highlight gains exist only in Liquid Composer, so the package reproduces the
geometry, the material flags and the translucency, but not those gains.

## Limits

The output is not what Apple's Icon Composer would produce from the same artwork.

- A glass layer does not refract its own fill, which is why the paint is a second layer.
- Refraction needs contrast under the glass. Over a plain plate it draws a rim and little else, so the
  deep glass in this icon is made of the back paint, not of the plate.
- The bevel is bounded by the distance field. Past about 5.6 % the shaft creases along its medial axis, and
  past 8 % the crease breaks the outline everywhere.
- The wall is pale on a white plate and has to be: the bevel shows the plate through a tinted pane, which
  is lighter than the paint behind it. A dark wall needs a dark plate, or a painted rim, which is the fake
  edge this icon avoids.
- There is no absorption, so the face cannot darken with thickness. The only material gradient is the
  pane's vertical tint and translucency, and at 1024 the depth read comes from the wall and the rim rather
  than from the volume.
- The dark edge lands on the sides of the shaft, not along its bottom: the engine's darklight is a 4 px
  band at ±90°, and the fill light is the only bottom-facing term.
- Clear cannot be deep: the plate is flat, the mask is flat, and the key saturates near white at any useful
  translucency.
- Blur and frost grey the glass at 512 px and below, so both are off.
- Automatic specular places the dark edge outside the silhouette in Dark and Clear, so it is set to
  `inside` explicitly.
- Each size renders from the same recipe; sizes up to 1024 px are supersampled by the engine rather than
  downsampled from a larger render.

Files, commands and the README wiring live in [assets/icon](../assets/icon/README.md).
