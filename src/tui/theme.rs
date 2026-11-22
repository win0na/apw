//! The visual system: terminal palette only, opencode chrome.
//!
//! Every color is an ANSI slot or a terminal default, so the TUI inherits the
//! user's palette instead of shipping a competing one.

use opentui::prelude::Color;

#[derive(Clone, Copy)]
pub struct Chrome {
    pub fg: Color,
    pub muted: Color,
    pub accent: Color,
    pub border: Color,
    pub warning: Color,
    pub error: Color,
    pub selected_fg: Color,
    pub selected_bg: Color,
}

impl Chrome {
    pub const fn terminal() -> Self {
        Self {
            fg: Color::DEFAULT_FOREGROUND,
            muted: Color::BRIGHT_BLACK,
            accent: Color::BLUE,
            border: Color::BRIGHT_BLACK,
            warning: Color::YELLOW,
            error: Color::RED,
            selected_fg: Color::BRIGHT_WHITE,
            selected_bg: Color::BLUE,
        }
    }
}

/// Five-row block `apw`, the same wordmark treatment opencode uses.
pub const WORDMARK: &str = "\
 ███  ████  █   █
█   █ █   █ █   █
█████ ████  █ █ █
█   █ █     ██ ██
█   █ █     █   █";

pub const HINTS_DASHBOARD: &str = "type to search   / commands   tab focus   ctrl+c quit";
pub const HINTS_BROWSER: &str = "↑↓ move   enter open   / commands   esc back   ctrl+c quit";
