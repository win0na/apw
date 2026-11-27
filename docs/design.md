# Design

How `apw` is put together and why the interface behaves the way it does.

## Shape

`apw` is one Rust binary with two front ends over the same vault code:

- A terminal interface, opened by bare `apw` on a TTY.
- The command line, used by every subcommand and by scripts.

Both read and write the same encrypted snapshot. The command-line contract is
unchanged: arguments, flags, JSON envelopes, exit codes, pipe detection, and
signal handling. The interface never replaces a command or changes its output.

The interface uses the Rust bindings for OpenTUI 0.9.7. A local `opentui-sys`
shim builds the Zig native library once and links it statically, so the
installed executable is self-contained and needs no OpenTUI files at runtime.

## Startup

`src/cli.rs` parses the command line first. With no arguments, stdin and stdout
on terminals, and `TERM` not `dumb`, it calls `src/tui/mod.rs`. That module
resolves paths, loads the configuration, snapshot, and state, and hands a
`VaultView` to the app. Loading happens before the terminal is taken over, so a
key prompt or a load error does not leave the screen in raw mode.

A subcommand never enters the interface. A hidden probe and `install-units`
remain command-line only.

## Interface model

The interface follows opencode's chrome rather than copying a chat application:

- The terminal palette only. No hard-coded background or branded colors.
- A block `apw` wordmark on the dashboard.
- Square single-line borders.
- Muted uppercase section labels.
- A solid accent bar for the selected row.
- One composer at the bottom.
- A three-zone footer: breadcrumb, hints, sync state.
- A dimmed backdrop behind dialogs, with an opaque dialog surface.

The interaction grammar follows vault content:

- Dashboard: account and sync status, counts, warnings, action hints, recent
  items, and activity.
- Browser: category tabs with counts, then a list and detail split on wide
  screens.
- Detail: fields for the selected item, then the actions valid for its kind.
- Composer: plain text filters the focused list. A leading `/` opens command
  completion. Escape clears the query, then leaves the screen.

Breakpoints are based on content, not device names:

| Width | Layout |
| --- | --- |
| 96 or more | List and detail side by side |
| 60 to 95 | List above detail |
| 40 to 59 | List only; Enter opens the detail page |
| Below 40 | Not supported |

The dashboard uses two columns at 96 or more and stacks below that. `[tui]`
configuration can request the split or stacked layout and hide the wordmark.

## State

`src/tui/data.rs` holds a `VaultView` with the vault, state, config, and paths.
It builds rows, dashboard counts, warnings, recent items, and detail fields. Live
one-time codes are generated when the detail is rendered; the snapshot stores the
TOTP secret, not a code.

`src/tui/app.rs` holds the widget tree and a `UiState`. Widgets are cheap handles
owned by the UI thread. A background thread sends sync, login, join, and group
results back as app messages. Nothing from OpenTUI crosses a thread boundary.

The snapshot lock is held per operation, not for the life of the process. The
interface keeps no lock while idle, so the timer and the command line can run.
It reloads the snapshot when its mtime changes, checked on a timer and after its
own writes; the reload is skipped while a dialog is open or a sync is running.

## Writes

The command-line write functions and the interface share one mutation layer in
`src/commands/write.rs`:

- `prepare_*` builds an entry and a pending operation without saving.
- `commit_*` loads the vault, checks the queue limits, merges the operation, and
  saves.
- Delete and restore use the same split.

The interface can therefore show a review before saving while the command line
keeps its behavior.

Dialogs are absolute overlays above the app. Focus moves with Tab and Shift+Tab,
Enter reviews or confirms, and Escape cancels or backs out. A dirty form asks
before discarding, and destructive confirmations start with Cancel selected. The
password field is a custom widget that paints bullets and handles editing, paste,
and focus without exposing the text.

The interface collects Apple ID credentials in a wizard and calls a stepwise
login API. The password and two-factor code stay in the process; the escrow
passcode is sent once for a join. The wizard asks for the code when Apple
requests one.

## Sync

`commands::sync::run_quiet` runs without terminal output and returns a
`SyncOutcome`. The interface runs it on a worker thread, shows progress in the
footer, and displays completion or refusal in the banner. The five-minute floor
is enforced in the same function the CLI uses.

## Tests

- Unit tests cover vault views, row filtering, masking, one-time codes, forms,
  confirmations, and the login wizard.
- Headless `opentui::TestApp` tests cover the dashboard, palette, browser,
  reveal, forms, and an add-then-trash cycle against a temporary snapshot.
- The command-line suite covers the original contract.
- Manual checks run in a PTY at 100x30, 70x24, and 40x16.

## Limitations

- Mouse support depends on the widgets; there is no separate mouse grammar.
- Notes are edited as a single line in the interface; the CLI accepts a body.
- A passphrase prompt is line-mode when the snapshot has no usable key.
- The interface supports one vault at a time.
- SMS two-factor is not supported by the sign-in code.
