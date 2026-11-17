# apw icon

A Liquid Glass icon for iOS 27, written as [Liquid Composer](https://github.com/frontedu/liquid-composer) recipes. Liquid Composer is an MIT reconstruction of Apple's Icon Composer 2, not Apple's tool.

Three glass keys, yellow behind green behind blue, on a white plate. The key outline is measured from Apple's Passwords icon and re-emitted at the reference's own offsets; `NOTES.md` has the numbers.

| Path | Contents |
| --- | --- |
| `icon.json` | Default: background, three key layers, glass settings, outputs |
| `icon-dark.json` | Dark |
| `icon-clear.json` | Clear Light and Clear Dark |
| `icon-bundle.json` | Default, square frame, whose only output is the `.icon` document |
| `src/` | one SVG per key, on the 1024 canvas |
| `src/tall/` | the same keys in a 3072 pt frame, one set per appearance, for the PNG recipes |
| `renders/` | generated PNGs: four appearances at 1024, 512 and 256 px, plus 70 and 40 px in light and dark |
| `apw.icon/` | generated Icon Composer document for Xcode |
| `NOTES.md` | measured geometry, material values, registration tables, engine limits |

Four recipes, not one: a Liquid Composer document holds a single appearance, so Dark and Clear are drawn separately rather than derived.

Do not edit the PNGs or `apw.icon/`. Edit a recipe or the SVGs and render again.

```sh
npx -y liquid-composer validate icon.json
npx -y liquid-composer apply icon.json --out renders
npx -y liquid-composer apply icon-dark.json --out renders
npx -y liquid-composer apply icon-clear.json --out renders
npx -y liquid-composer apply icon-bundle.json --out .
```

The last one writes `apw.icon/` in place. `validate` needs no browser; `apply` drives Google Chrome headless over WebGL2 and takes about 30 seconds. Node 22.12 or later. Check `state.webgl` in the command's JSON output for `active`: without WebGL2 the engine falls back to Canvas 2D and the renders lose refraction and blur.

Without Google Chrome, point `LC_CHROME` at any Chrome or Chromium binary and patch the launch line in `scripts/agent/session.mjs` to use it.

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
