# Icon assets

A Liquid Glass icon for iOS 27, written as [Liquid Composer](https://github.com/frontedu/liquid-composer) recipes. Liquid Composer is an MIT reconstruction of Apple's Icon Composer 2, not Apple's tool.

The mark is one glass key on a quiet plate: the blue key from Apple's Passwords icon, measured from the reference and re-emitted at 1024 pt, with a glass pane over an inset painted face so the bevel has something real to refract. `NOTES.md` has the geometry, material values, and registration tables.

| Path | Contents |
| --- | --- |
| `icon.json` | Default: plate, two layers, glass settings, outputs |
| `icon-dark.json` | Dark |
| `icon-clear.json` | Clear Light and Clear Dark |
| `icon-bundle.json` | Default in the square frame, whose only output is the `.icon` document |
| `src/` | `key.svg` and `key-face.svg` per appearance, on a 1024 × 3072 frame |
| `renders/` | 20 PNGs: four appearances at 1024, 512, 256, 70, and 40 px |
| `preview/` | contact sheet, 70 and 40 px rows, circle crops, refraction pair |
| `apw.icon/` | generated Icon Composer document for Xcode |
| `NOTES.md` | measured geometry, material values, registration and refraction numbers, engine limits |

There are four recipes, not one. A Liquid Composer document holds a single appearance, so Dark and Clear are drawn separately rather than derived.

`renders/` and `apw.icon/` are generated. Change a recipe or an SVG and render again.

```sh
npx -y liquid-composer validate icon.json
npx -y liquid-composer apply icon.json --out renders
npx -y liquid-composer apply icon-dark.json --out renders
npx -y liquid-composer apply icon-clear.json --out renders
npx -y liquid-composer apply icon-bundle.json --out .
```

The last command writes `apw.icon/` in place. `validate` needs no browser; `apply` drives Google Chrome headless over WebGL2 and takes about 30 seconds. Node 22.12 or later. Check `state.webgl` in the JSON the command prints: without WebGL2 the engine falls back to Canvas 2D and the renders lose refraction and blur.

Without Google Chrome, point `LC_CHROME` at any Chrome or Chromium binary and patch the launch line in `scripts/agent/session.mjs` to use it.

## README

The logo in the repository README swaps with the page theme:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/icon/renders/icon-512-dark.png">
  <img alt="apw" src="./assets/icon/renders/icon-512.png" width="70" valign="middle">
</picture>
```

Both files are 512 px, so they stay sharp on a high-density display at 70 CSS px.
