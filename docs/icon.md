# About the icon

The apw mark is a Liquid Glass app icon for iOS 27. It follows Apple's current icon material so it can sit beside first-party icons instead of looking like a flat logo. The source is layered recipes, not a drawing, so every size and appearance renders from the same geometry.

The recipes target [Liquid Composer](https://github.com/frontedu/liquid-composer), an MIT reconstruction of Apple's Icon Composer 2. It is not Apple's tool, so the glass is an approximation. [Limits](#limits) lists where it differs.

## The mark

Three keys on a white plate, yellow behind green behind blue, borrowing the key group from Apple's Passwords icon. The outline is measured from that icon's own vector paths rather than traced: bow radius, hole, shaft width, tooth angles, and the offsets between the three keys, all re-emitted at 1024.

Each key is its own glass layer with one hue and no decoration. Depth comes from refraction between the layers, which displaces up to 32.5 px of a back key's image inside the key in front of it, and from the glass density. Nothing is painted: no bevel, no glow, no drop shadow, no gradient.

Only the blue key is pierced. The green carries an opening at the same centre, 55.5 px in radius, so the hole shows plate instead of the green key's edge; it sits under the blue bow and is never seen.

At 40 px the mark reads as one key with three colour bands, which is deliberate: three separate keys cannot resolve at that size, but the bands and the hole can. What goes at small sizes is the four plate gaps between the shafts and the refraction itself, both under a pixel by 70.

## Appearances

Default puts the three fills on a white plate. Dark keeps the same geometry on the engine's graphite plate with brighter fills, so the keys stay luminous. Clear Light and Clear Dark use the engine's flat grey plates, where artwork can only lighten the surface, so the layer order comes from translucency rather than colour.

Specular is set inside the silhouette in every appearance, not left on automatic. On Dark and Clear, automatic placement draws the dark edge outside the shape and paints the plate inside the hole; inside keeps every edge on its own key.

Four recipes exist because a Liquid Composer document holds one appearance. iOS 27 also has Tinted, which the engine does not implement.

## The Icon Composer package

`assets/icon/apw.icon/` opens in Icon Composer and Xcode. It carries `refractivity` and `specular-location`, so it needs Xcode 27.

The bundle is the Default appearance: the format has one set of layers and ignores per-appearance specialisations. Its artwork is the square 1024 frame, not the tall frame the PNG renders use, so Icon Composer's own translucency preview will read slightly more transparent at the tips. The PNGs are the render of record.

The three highlight gains exist only in Liquid Composer. The format has no field for them, so the bundle carries the geometry, the material flags and the translucency, not the gains.

## Limits

The output is not what Apple's Icon Composer would produce from the same artwork.

- Translucency ramps over the layer frame, not the shape. The PNG recipes use a 3072 pt frame with the artwork in the bottom third so each key sits on a flatter part of the ramp; a frame that fits the canvas leaves the bow nearly opaque and the tip visibly thin.
- In Clear, artwork lightens the plate and cannot darken it. Fills from mid grey to white compress into about 20 levels, so colour cannot carry the layer order there.
- Blur between 2 and 12 turns the glass grey at 512 px and below, so it is off.
- Refraction needs contrast under the glass. Over the quiet plate it draws the rim and nothing else, which is why the depth lives in the overlaps.
- One document, one appearance. Dark and Clear are separate recipes and separate renders, not overrides.
- The renders at 512, 256, 70 and 40 are the 1024 render downsampled, not a separate design for each size.

Files, commands and the README wiring live in [assets/icon](../assets/icon/README.md).
