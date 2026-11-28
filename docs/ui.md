# Interface

The terminal interface is apw's primary front end. This page is its visual and
interaction contract: the colors, spaces, glyphs, and keys the rewrite keeps.

The rules are reverse engineered from opencode 2.4.1 (`anomalyco/opencode` at
`68ea328`), the version the reference screenshots come from. The surfaces are
`packages/tui/src` and `packages/theme/src/tui`.

Decisions this page assumes:

- The palette follows the terminal (`System`), not a shipped hex theme.
- The reference is the current default treatment: the "new designs" rows and
  dialogs. `experimental.new-designs` defaults to on.
- apw keeps its screens: dashboard, categories, list, detail, help. opencode's
  transcript, session tabs, and sidebar are not ported.
- Keys are hybrid: opencode navigation and modal semantics, apw's single-key
  vault actions.

## Rules

1. A surface is a fill and a rail. Panels use `background.raised` and a 1-cell
   `┃` left border. No boxes around content, no rounded corners, no double
   borders. opencode uses rounded corners only on its crash screen.
2. Color comes from the terminal. The page is the terminal background and body
   text is the terminal foreground. Accents are ANSI hues; every surface step
   and muted tone is derived, never hand-picked.
3. Three text tones and two weights. `text.base`, `text.muted`, `text.faint`;
   regular and bold. No italics in chrome, no color for decoration.
4. One-cell rhythm. Padding and gaps are 0, 1, 2, or 3 cells. Page padding is 2
   (1 below 44 columns), content indent is 3, and one blank row separates
   blocks.
5. Selection is a fill plus a `┃` rail in the left cell. The rail cell stays
   unfilled, so the fill starts one cell in. The current item, as opposed to the
   cursor, is `▪`.
6. Keyboard first. Every action in a footer or dialog is bound; hints resolve
   from the live key map, and an unbound action is not shown.
7. Escape unwinds one layer: text selection, editor text, the top dialog, the
   current screen. `ctrl+c` does not quit from inside a dialog.
8. Chrome truncates with `…`; only prose wraps. Long labels lose their tail,
   paths lose their middle.

## Color

### Terminal derivation

apw reads the 16-color palette and the default foreground and background. The
palette is usable only when a default background or palette slot 0 exists and a
default foreground or slot 7 exists; otherwise the interface falls back to the
shipped palette rules below.

Mode is chosen from the background:

```text
luminance = 0.299 * r + 0.587 * g + 0.114 * b   (0..1)
mode      = luminance > 0.5 ? light : dark
```

The gray ramp has 12 steps, `i = 1..12`, with `L` the background luminance in
0..255 and `f = i / 12`:

```text
dark,  L < 10:   gray = floor(f * 0.4 * 255)
light, L > 245:  gray = floor(255 - f * 0.4 * 255)
otherwise:       next   = dark ? L + (255 - L) * f * 0.4 : L * (1 - f * 0.4)
                 ratio  = next / L
                 channel = floor(clamp(backgroundChannel * ratio, 0, 255))
```

Muted text:

```text
dark,  L < 10:   gray = 180
dark:            gray = min(floor(160 + L * 0.3), 200)
light, L > 245:  gray = 75
light:           gray = max(floor(100 - (255 - L) * 0.2), 60)
```

`tint(base, overlay, alpha)` interpolates sRGB channels and rounds.
Diff backgrounds use the background, the ANSI green or red, and alpha 0.22 in
dark mode or 0.14 in light mode.

### Seeds

The system theme starts as the legacy palette:

| Seed | Value |
| --- | --- |
| `primary`, `accent`, `info` | ANSI cyan, slot 6 |
| `secondary` | ANSI magenta, slot 5 |
| `error` | ANSI red, slot 1 |
| `warning` | ANSI yellow, slot 3 |
| `success` | ANSI green, slot 2 |
| `text` | default foreground, or slot 7 |
| `textMuted` | formula above |
| `background` | transparent, the terminal background shows through |
| `backgroundPanel` | gray 2 |
| `backgroundElement`, `backgroundMenu` | gray 3 |
| `borderSubtle` | gray 6 |
| `border` | gray 7 |
| `borderActive` | gray 8 |
| syntax and markdown | comments use the muted tone, keywords magenta, functions blue, strings green, numbers yellow, types cyan, operators cyan |

### Surface steps

The seeds are placed on opencode's step layout in OKLCH: text at 100, 200, and
300, the page at 900, raised surfaces at 700, 600, and 500, and each hue
anchored at 400. These profiles are exact:

| Profile | dark | light |
| --- | --- | --- |
| surface 900, 800, 700 | 0, 0.039, 0.057 | 0, -0.015, -0.039 |
| surface 600, 500, 400 | 0.11, 0.175, 0.253 | -0.102, -0.145, -0.227 |
| text 200, 300 | 0.719, 0.538 | 0.688, 0.484 |
| hue lightness 100, 200, 300 | -0.035, -0.023, -0.003 | 0.083, 0.13, 0.116 |
| hue lightness 600, 700, 800, 900 | 0.095, 0.071, 0.024, 0.012 | 0.021, -0.002, -0.004, -0.008 |
| hue chroma 100, 200, 300 | 0.1, 0.24, 0.22 | 0.19, 0.12, 0.16 |
| hue chroma 500, 600, 700 | 0.64, 0.2, 0.14 | 0.38, 0.17, 0.1 |
| hue chroma 800, 900 | 0.09, 0.07 | 0.05, 0.02 |
| hue mid | 0.55 | 0.65 |
| readable 900, 800, 700 | 0.99, 0.95, 0.92 | 0.97, 0.96, 0.89 |
| readable 600, 500 | 0.81, 0.66 | 0.74, 0.64 |
| readable hue 900, 800 | 0.99, 0.92 | 0.97, 0.93 |
| readable hue 700, 600 | 0.82, 0.7 | 0.88, 0.78 |

Step 500 sits between the hue anchor and step 600 by the hue mid factor. Steps
600 to 900 are pulled toward the page until text on them keeps a contrast share
`target = max(pageContrast * share, min(4.5, pageContrast * 0.95))`; the mix is
found with 12 bisection steps and capped at 0.6 toward the page. Surfaces 900
and 100 come straight from the terminal background and foreground. Transparent
legacy surfaces stay transparent.

Token assignment:

| Token | Value |
| --- | --- |
| `text.base`, `text.muted`, `text.faint` | neutral 100, 200, 300 |
| `text.action.primary.selected` | interactive 400 |
| `text.formfield.focused` and other formfield states | interactive 400 |
| `text.action.secondary.focused` | interactive 200 |
| `background.base` | neutral 900, the terminal background |
| `background.raised.base`, `.high`, `.max` | neutral 700, 600, 500 |
| `background.action.primary.focused` | interactive 600 |
| `background.action.primary.hovered` | neutral 700 |
| `background.action.destructive.base` | the error seed |
| `border.base` | the legacy border seed |
| `scrollbar.base` | the legacy active border seed |
| `@dialog.background.base` | raised base in dark, neutral 800 in light |
| `@dialog` hover fills | raised max in dark, neutral 600 in light |

apw uses these roles and no others:

| Role | Token |
| --- | --- |
| page | `background.base` |
| panel, prompt surface, toast | `background.raised.base` |
| hover, dialog footer band | `background.raised.high` |
| highest surface | `background.raised.max` |
| selected row fill, rail on focus | `background.action.primary.focused` |
| selected row text, body text | `text.base` |
| metadata, labels, placeholders, hints | `text.muted` |
| disabled, cancelled | `text.faint` |
| structural left rail, rules | `border.base` |
| scrollbar thumb | `scrollbar.base` |
| focused field value | `text.formfield.focused` |
| warning, error, success, info | `text.feedback.*.base` |
| destructive fill | `background.action.destructive.base` |

A computed example for the reference palette, page `#2e2d47` and text
`#cdd6f4`: panel `#323051`, hover `#3a385c`, selected `#324759`, muted
`#aeaeae`, faint `#7d82a2`, rail `#5b598d`. These are outcomes, not constants;
a different terminal produces different values from the same formulas.

## Metrics

| Element | Value |
| --- | --- |
| Page padding | 2 cells, 1 below 44 columns |
| Content indent | 3 cells from the pane edge |
| Sibling gap | 1 cell; footer groups 2 cells |
| Divider between blocks | one blank row |
| Rail | 1 cell, `┃`, heavy vertical |
| Dialog width | 60 medium, 88 large, 116 xlarge, clamped to terminal width - 2 |
| Dialog inset | 3 cells, list rows 4 |
| Dialog top | terminal height / 4, or centered |
| Dialog padding | 1 row above the header, 3 at the sides, 1 below |
| Scrim | black at alpha 150/255 |
| Palette list height | floor(terminal height / 2) - 6 |
| Prompt max width | 75 cells |
| Prompt text height | 1 to max(6, floor(terminal height / 3)) |
| Toast width | min(60, terminal width - 6) |
| Toast position | top 1, right 2 |
| Tab width | 22 preferred, 32 maximum, 8 minimum |

## Components

### Dashboard

A centered column, like opencode's home:

1. Growing spacer, then a 3-row spacer that collapses first.
2. The wordmark, hidden below 12 rows. Under 22 columns it is three rows of the
   right half only; under 44 it stacks the halves; otherwise the two halves sit
   side by side with a 1-cell gap.
3. One blank row.
4. A centered status line in `text.muted`: account, then ` · `, then signed in
   or out. Warnings follow on their own line in the warning color.
5. The counts, joined with ` · ` and wrapped to the column width. Under 44
   columns they wrap again inside the narrower column.
6. One blank row.
7. The filter prompt, capped at 75 cells and centered.
8. One blank row.
9. `Recent` in bold `text.base`, then up to six rows. The heading stays when
   there are no rows; the empty line is muted. A row is a title in
   `text.base`, an inline ` · ` and muted metadata, and a right-aligned relative
   time in `text.muted`. The selected row gets the fill and rail.
10. Growing spacer.
11. The footer bar.

The wordmark is a five-row block `apw` in bold `text.base`. Its shadow repeats
the final row one cell below in `text.shadow`, so the letters sit on a dark
base. Below 44 columns the wordmark collapses to the three letters `apw`; below
12 rows it is hidden. opencode's own art, for reference:

```text
█▀▀█ █▀▀█ █▀▀█ █▀▀▄   █▀▀▀ █▀▀█ █▀▀█ █▀▀█
█__█ █__█ █^^^ █__█   █___ █__█ █__█ █^^^
▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀~~▀   ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀
```

### Category strip

One row, height 1, above the list. Each tab is a label, truncated to 10 cells,
with the item count as muted text after a space. The active tab is bold
`text.base` on `background.raised.high`; inactive tabs are `text.muted` with no
fill. Tabs do not take focus; `ctrl+tab` and the palette switch categories.
Overflow shows `‹N` or `N›` at the ends.

### Item list

One line per item, no separator rows, no gaps:

```text
┃ Example            alice@example.com              2m
```

- Rail cell, 1 cell, on the page surface and never filled. `┃` on the selected
  row, space elsewhere.
- One space, then the title, `text.base`, truncated with `…`.
- Inline description after one space: username, then ` · `, then the host, in
  `text.muted`.
- Right-aligned metadata, `text.muted`, truncated from the left if needed:
  relative age for logins and notes, item count for groups.
- Selected row: fill from the cell after the rail to the pane edge,
  `background.action.primary.focused`, title in `text.base`, description and
  metadata in `text.action.secondary.focused`.
- The item open in the detail pane carries `▪` in the rail cell when it is not
  the cursor.

### Detail

A pane with page padding 2 and no border. Fields are label and value rows:

```text
Name        Example
Username    alice@example.com
Password    ••••••••
Code        123456  15s
```

The label column is 12 cells, `text.muted`; values are `text.base`. Sections
are separated by one blank row; section headings are bold `text.base`. A secret
is masked to 8 to 24 bullets. Action hints belong in the footer, not the pane.

### Palette

`ctrl+p` opens a 60-cell dialog, vertically at one quarter height, over the
scrim.

- Header row: the search input replaces the title. Placeholder `Search
  commands`, `text.muted`; close label `esc` on the right.
- The list starts after a blank row. Group headings are bold `text.muted`, one
  blank row before each group except the first.
- Row: 1-cell rail, title, inline description after a space, and a right-aligned
  `category · key` column. Title is `text.base`; description and shortcut are
  `text.muted`. Selected rows use the fill, the rail, and
  `text.action.secondary.focused` for the secondary column. No bold on the
  selected title.
- A current value shows `▪`; a choice shows `‹ value ›`; an open picker shows
  `value ↵`.
- Empty states: `No items available`, and `No results found` when a filter has
  no match.
- Matching is fuzzy over title, category, and description. Up and down wrap;
  page up and down move 10; home and end jump; alt+up and alt+down jump groups.

### Dialogs

Dialogs are flat rectangles on the scrim: no border, no title bar rule.

- Surface `@dialog.background.base`, width from the size table, padding 1 above
  and 3 at the sides.
- Header: title in `text.base`, bold only if the row itself needs emphasis;
  `esc` at the right in `text.muted`; optional muted description line.
- One blank row between header, body, and footer.
- Footer: a band in `background.raised.high` across the dialog body, padded 1
  row and 2 cells, with `gap 2`. Secondary actions sit
  left, primary actions right. Under 60 columns the groups stack.
- Action labels are `title key`, for example `Cancel esc` and `Confirm enter`.
  Disabled actions use `text.action.primary.disabled`.
- Mouse click on the scrim closes the dialog; text selection on release does
  not.

### Forms

The form is a dialog with fields, not a sequence of prompts.

- Label above the control, `text.base`; the focused control shows
  `text.formfield.focused`.
- One blank row between fields. Multi-line notes grow to at most 6 rows.
- Validation error on the footer right, `text.feedback.error.base`, cleared on
  the next edit.
- Footer hints: `tab` next field, `↑↓` move, `enter` submit, `esc` dismiss.
- The sign-in wizard is a form with steps. Show `Step N of M` in muted text
  under the title, and `esc escrow` warnings in `text.feedback.warning.base`.
  Masked fields use the same bullets as the detail pane.
- Destructive confirmation is two-step. The confirm dialog opens with Cancel
  focused; `←` and `→` or `tab` switch; `enter` runs the focused action:
  `Cancel esc` and `Delete enter`.

### Toasts

- Top right, 1 row from the top and 2 cells from the right.
- Width `min(60, terminal width - 6)`, surface `background.raised.high`.
- Left and right borders `┃` in the severity color; padding 1 row and 2 cells.
- Title bold, optional action `› label` at the right, message word-wrapped.
- One toast at a time, 5 seconds. Later toasts queue and show `+N more`.
  Hover pauses the timer.
- Severity changes only the rail color; the fill stays `background.raised.high`.

### Help

A 60-cell centered dialog titled `Help`, close label `esc`. Groups such as
`Vault`, `Sync`, and `Navigation`, each a bold heading followed by rows: a
shortcut column of 17 cells in `text.base`, then the description in
`text.muted`. The body scrolls; the footer is `ok enter`.

### Footer

One row at the bottom, page padding, `gap 2`:

- Left: location or scope in `text.muted`: `apw` on the dashboard, `help` in
  the help dialog, and `vault / <category>` with ` / <query>` while filtering.
- Right: hints as `key label`, each key in `text.base` and each label in
  `text.muted`, groups joined by ` · `.
- Below 60 columns the hints keep two or three entries and shrink to the
  available width. The location keeps at most 28 cells.

### Prompt

The composer is opencode's prompt, not a bordered input.

- Left border `┃`, no other sides. Border color `border.base`; the focused
  color is the active accent.
- Surface one step below `raised.base`; padding 1 row above and 2 cells at the
  sides (1 below 44 columns).
- Placeholder `Search the vault` in `text.muted`.
- Bottom cap: a `╹` corner under the rail and a `▀` fill row, so the box ends
  without a full border.
- A metadata row under the input: scope on the left, mode or count on the
  right, both `text.muted`.
- A footer row under it with the context hints.

## Interaction

| Key | Action |
| --- | --- |
| `ctrl+p` | Open the palette |
| `/` | Open the palette from the list or detail |
| `↑` `↓` | Move the cursor with wrap |
| `ctrl+n` `ctrl+p` | Move the cursor with wrap, inside lists |
| `pgup` `pgdn` | Move 10 rows |
| `home` `end` | First or last row |
| `alt+up` `alt+down` | Previous or next group |
| `enter` | Open, run, or submit |
| `esc` | Unwind one layer |
| `tab` `shift+tab` | Move focus |
| `ctrl+c` | Close the palette or dialog; at the base screen, quit |
| `ctrl+z` | Suspend |
| `y` | Copy the password, from the detail pane |
| `o` | Copy the one-time code |
| `r` | Reveal the password for 20 seconds |
| `e` | Edit the item |
| `t` | Move to Recently Deleted |
| `s` | Restore |
| `g` | Add or remove a group |
| `u` | Undo the last trash |
| `l` `v` | Keep the local change or take the remote version |

Typing in the list filters it. The single-key vault actions above run while
the detail pane has focus; `tab` moves there from the list.

Modal layers are a stack, not flags. Opening a dialog pushes a modal layer that
removes every base layer from reach; closing it restores focus to the widget
that opened it. Only the top dialog renders. Escape and `ctrl+c` follow the
ladder in the rules above. Destructive actions confirm with the cancel action
focused.

## Responsive

| Width | Change |
| --- | --- |
| under 44 | Page padding 1; prompt padding 1; footer hints collapse |
| under 60 | Tabs truncate to first letters with overflow counts; dialog footer stacks; modal width clamps to terminal - 2 |
| under 96 | List and detail stack instead of splitting |
| 96 and up | List 42%, detail the rest |
| 120 and up | Full two-column dashboard, six recents |

Below 40 columns or 16 rows the interface shows the compact dashboard only:
logo, status, prompt, and footer.

## Truncation

| Content | Rule |
| --- | --- |
| Titles, labels, hints | Cut at the cell budget, append `…` |
| Paths | Keep the root and basename, replace the middle with `…<sep>` |
| Metadata columns | Right align; truncate from the left |
| Tab overflow | `‹N` and `N›` |
| Picker values | `‹ value ›` |
| Actions | `title key`, never wrapped |

## Gap from today

| Today | Target |
| --- | --- |
| ANSI slot palette, blue selection | System-derived tokens, cyan interactive steps |
| Solid 5-row block wordmark | Shadow letterforms at 25% tint, opencode breakpoints |
| Bordered composer box | `┃` rail, raised surface, `╹▀` base |
| 64-cell bordered modal | 60/88/116 borderless dialogs on a scrim |
| Borderless detail with 14-cell labels | 12-cell muted labels, 2-cell page padding |
| Two-line list rows | One-line rows with inline muted description |
| Text blob group picker | Dialog list with rail and `▪` |
| Single overwritten banner | Toast queue, severity rail, 5 seconds |
| Footer hints hard-coded | Hints resolved from the key map |
| `ctrl+c` quits everywhere | Escape ladder, `ctrl+c` clears or closes first |
| Dashboard left column | Centered home layout with footer bar |

## Verification

Capture both applications at 120x36, 100x30, 80x24, 60x20, and 40x16, with the
same states: dashboard, list with a selection, detail open, palette open with a
filter, confirm dialog, form, toast, and help. Use a fixture vault in a clean
HOME, never the live vault.

```sh
tmux new-session -d -s cap -x 120 -y 36 "<command>"
tmux capture-pane -e -p -t cap > frame.ansi
```

Compare frames cell by cell. Shared structures must match: page padding, rail
position, row height, dialog width and top, footer layout, and truncation.
Colors must land on the same roles even when the terminal palette differs.

Headless tests assert the constants that screenshots cannot: dialog widths,
palette height, rail cell, label column, truncation budget, and the escape
ladder. The current tests reach into widgets and state directly; the rewrite
keeps their behavior assertions but not their private-field coupling.

## Non-goals

- The transcript, markdown, code blocks, diffs, and session tabs.
- A sidebar, a session list, and opencode's information architecture.
- A theme picker. The interface follows the terminal.
- Mouse as a required input. Selection and scroll wheel may work, but every
  action has a key.
- Animation. Spinners advance every 80 ms; nothing else moves.
