# Icon

The apw icon is a Liquid Glass app icon for iOS 27. It is the repository avatar and the mark at the top of the README, where it renders at 70 px. It shows one key on a white plate, in the material Apple uses for its own icons.

The icon is a set of layered recipes, not a drawing. Every size and appearance renders from the same geometry.

## The mark

The key is the blue key from Apple's Passwords icon. Its outline is measured from the reference's own vector paths and re-emitted at 1024 pt: bow centre (512, 331.8), bow radius 192.9, hole radius 51.5, shaft 116.3 wide, tip at y 882. `assets/icon/NOTES.md` lists every landmark.

The only change to the geometry is position. The reference places the key on the right of a three-key group; here it moves 120.48 pt left until the bow sits on the centre line. Nothing is rescaled, redrawn, or stylised, and there is one hue.

## Glass

The key is two layers in the same frame. `Key` is the glass pane; `Key face` is the paint, inset 8 pt inside the pane so the bevel has a margin to look through.

Two layers are necessary because the engine refracts what lies below a glass layer, never the layer's own fill. A single tinted pane on a white plate cannot be both saturated and see-through.

Refraction runs at -10 (64 pt outward). That samples the 8 pt margin and shows the paint's edge about 11 pt inside where it is painted. The band runs the whole way round the key: 26.5% of its pixels at 1024, reaching 18.9 px in from the silhouette.

Nothing is painted on top of the shape. There is no glow, drop shadow, blur, frost, or offset copy of the outline. The paint is the same path, inset, so a seam would show if the two were out of register; `NOTES.md` has the measurements.

The material follows iOS 27: light from directly above, the specular inside the silhouette, a bevel at 4.5% of the icon, dispersion 20, and translucency 40. Every render reports `state.webgl` as `active`; without WebGL2 the engine drops refraction and blur, and the icon is not the one that ships.

The plate is plain. Structure on the plate turns into contour lines and moiré, so the only contrast the glass bends is the key's own paint.

## Appearances

Default puts the reference's blue on a white plate. Dark keeps the geometry and puts the brighter blue on a graphite plate. Clear Light and Clear Dark use the engine's grey plates, where a layer can only lighten what is below it; depth there comes from the key's dark edge.

All four appearances exist at 1024, 512, 256, 70, and 40 px. At 70 the key is 51 px tall and still reads as a key: silhouette, zigzag, hole, and rim survive. The wall does not, at 3.1% of the key and under a pixel wide. At 40 the outline reads in Default and Dark; the hole is a 4 px dot and neither wall nor bevel remains. Clear Light is marginal there.

## The Icon Composer package

`assets/icon/apw.icon/` opens in Icon Composer and Xcode. It carries the `refractivity` and `specular-location` features, so it needs Xcode 27. The package is the Default appearance; the PNGs are the render of record. Two highlight gains exist only in Liquid Composer, so the package reproduces the geometry, material flags, and translucency, but not those gains.

## Limits

- A glass layer does not refract its own fill, which is why the paint is a second layer.
- Refraction needs contrast under the glass. Over a plain plate it draws a rim and little else.
- The bevel is bounded by the distance field. Past about 5.6% the shaft creases along its medial axis; past 8% the crease breaks the outline.
- The wall is pale on a white plate and has to be. A dark wall needs a dark plate or a painted rim, which is the fake edge this icon avoids.
- There is no absorption, so the face cannot darken with thickness. At 1024 the depth read comes from the wall and the rim.
- The dark edge lands on the sides of the shaft, not along its bottom.
- Clear cannot be deep: the plate is flat, the mask is flat, and the key saturates near white at useful translucency.
- Blur and frost grey the glass at 512 px and below, so both are off.
- Each size renders from the same recipe; the engine supersamples up to 1024 px rather than downsampling a larger render.

Files, commands, and the README wiring live in [assets/icon](../assets/icon/README.md).
