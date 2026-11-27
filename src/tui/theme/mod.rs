//! The visual system: the terminal's System palette and opencode chrome.
//!
//! Colors come from [`Tokens::system`], which derives every surface and accent
//! from the terminal's sixteen colors. Nothing is hand-picked, so the interface
//! follows the terminal it runs in.

mod oklch;
mod system;

pub use system::{Mode, Tokens};

use opentui::prelude::Color;

/// The subset of the palette the first-pass widgets use, kept while the
/// interface is rebuilt on [`Tokens`].
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

impl From<&Tokens> for Chrome {
    fn from(tokens: &Tokens) -> Self {
        Self {
            fg: tokens.text,
            muted: tokens.muted,
            accent: tokens.info,
            border: tokens.rail,
            warning: tokens.warning,
            error: tokens.error,
            selected_fg: tokens.selected_text,
            selected_bg: tokens.selected,
        }
    }
}

impl Chrome {
    pub fn terminal() -> Self {
        Self::from(&Tokens::fallback())
    }
}

/// Five-row block `apw`, the same wordmark treatment opencode uses.
pub const WORDMARK: &str = "\
 ███  ████  █   █
█   █ █   █ █   █
█████ ████  █ █ █
█   █ █     ██ ██
█   █ █     █   █";

pub const WORDMARK_COMPACT: &str = "apw";

pub const HINTS_DASHBOARD: &str = "type to search   / commands   tab focus   ctrl+c quit";
pub const HINTS_BROWSER: &str = "↑↓ move   enter open   / commands   esc back   ctrl+c quit";
