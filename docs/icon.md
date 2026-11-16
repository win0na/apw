# About the icon

The apw mark is a Liquid Glass app icon for iOS 27. It follows Apple's current icon material so it can sit beside first-party icons instead of looking like a flat logo. The source is a layered recipe, not a drawing, so it renders at any size and in each of the four appearances.

The recipe targets [Liquid Composer](https://github.com/frontedu/liquid-composer), an MIT reconstruction of Apple's Icon Composer 2. It is not Apple's tool, so the glass is an approximation. [Limits](#limits) lists where it differs.

## The mark

A key at 45°, in Apple's light-appearance system blue (`#007aff`), on a frosted white plate. A `>` is cut through the bow, so the shell prompt is a hole in the glass instead of a glyph sitting on it. The shaft ends in a square-cut T bar whose long lower tooth is the flat bar of the prompt at caret stroke weight.

The shape is continuous. There is no ring, no second accent colour and no text. At 1024 the `>` reads as a caret. At 70 px it survives as a white chevron in the bow, and the bit reads as the key's teeth.

The underscore is not a horizontal `_`. A tooth perpendicular to a 45° shaft lies at 45°, and reaching the caret baseline would need an arm about half the icon long. The prompt therefore reads as `>` plus a wide flat bar. Steepening the key would make that bar horizontal, but it would lose the diagonal that holds a circle crop.

## Appearances

The recipe renders Default, Dark, Clear Light and Clear Dark. iOS 27 also has Tinted, which Liquid Composer does not implement.

Default places the specular highlight inside the key's edge, on a bright plate. Dark replaces the plate with graphite, moves the highlight outside the edge, and keeps the key brighter than the plate. Clear Light and Clear Dark use the engine's flat grey plates, and the key lightens with them instead of staying blue. Clear is the weakest of the four: the key loses contrast. That is how this engine renders Clear, not a design choice.

Liquid Composer keeps one fill and one set of glass values for all four appearances. The dark plate comes from a soft-light layer and the engine's own graphite, not from a per-appearance colour.

## The Icon Composer package

`assets/icon/apw.icon/` opens in Icon Composer and Xcode. The recipe turns refraction on, so the package needs Xcode 27.

The package carries the `refractivity` feature. It does not carry `specular-location`, because the recipe asks for automatic specular placement and Icon Composer resolves that per appearance when it builds.

## Limits

The output is not what Apple's Icon Composer would produce from the same artwork.

- The engine gives a glass layer a thin edge rim and little else, because a bright plate leaves refraction nothing to bend. The visible thickness comes from two drawn edge layers, `key-wall-light.svg` and `key-wall-shade.svg`, not from the glass shader.
- Most Advanced panel keys have no visible effect in this engine. The recipe sets only the ones that change a render.
- Refraction is a screen-space effect over a flat stack. The shadow is a soft halo, not Apple's material shadow.
- Dark mode replaces the background with the engine's graphite, so the plate takes no custom dark colour.

Files, commands and the README wiring live in [assets/icon](../assets/icon/README.md).
