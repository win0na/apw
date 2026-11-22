//! Full-screen vault interface.
//!
//! The CLI stays the machine interface; this module is only built with the
//! default `tui` feature and only entered from a bare `apw` on a terminal.

pub mod app;
pub mod data;
pub mod theme;

use crate::config::Paths;
use crate::error::Result;

/// Enter the interface. The snapshot is loaded before the terminal is taken
/// over, so a passphrase prompt still uses the normal terminal.
pub fn run() -> Result<()> {
    let paths = Paths::resolve()?;
    let view = data::VaultView::load(&paths)?;
    app::run(view)
}

#[cfg(test)]
mod tests {
    use opentui::prelude::*;
    use opentui::testing::TestApp;

    #[test]
    fn renders_a_wordmark() {
        let app = TestApp::new(30, 3);
        let text = Text::new(&app, "apw");
        app.root().add(&text);
        let frame = app.render();
        assert!(frame.text().contains("apw"), "{}", frame.text());
    }
}
