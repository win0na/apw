# apw icon

A Liquid Glass icon for iOS 27, written as a [Liquid Composer](https://github.com/frontedu/liquid-composer) recipe. Liquid Composer is an MIT reconstruction of Apple's Icon Composer 2, not Apple's tool.

| Path | Contents |
| --- | --- |
| `icon.json` | the recipe: background, layers top to bottom, glass settings, outputs |
| `src/` | one SVG per layer |
| `renders/` | generated PNGs: four appearances at 1024, 512 and 256 px, plus 70 px |
| `apw.icon/` | generated Icon Composer document for Xcode |

Do not edit the PNGs or `apw.icon/`. Edit the recipe or the SVGs and render again.

```sh
npx -y liquid-composer validate icon.json
npx -y liquid-composer apply icon.json --out renders
```

`validate` needs no browser. `apply` drives Google Chrome headless over WebGL2 and takes about three minutes. It needs Node 22.12 or later. Check `state.webgl` in the command's JSON output for `active`: without WebGL2 the engine falls back to Canvas 2D and the renders lose refraction and blur.

The `.icon` package needs Xcode 27, because the recipe enables refraction.

## README

The logo in the repository README swaps with the page theme:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/icon/renders/icon-512-dark.png">
  <img alt="apw" src="assets/icon/renders/icon-512.png" width="70">
</picture>
```

Both files are 512 px, so they stay sharp on a high-density display at 70 CSS px.

[Icon](../../docs/icon.md) covers the mark, the appearances and the engine's limits.
