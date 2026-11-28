//! Full-screen vault interface.
//!
//! The CLI stays the machine interface; this module is only built with the
//! default `tui` feature and only entered from a bare `apw` on a terminal.

pub mod app;
pub mod data;
pub mod page;
pub mod secret;
pub mod theme;
pub mod view;

use crate::config::Paths;
use crate::error::Result;

/// Enter the interface. The snapshot is loaded before the terminal is taken
/// over, so a passphrase prompt still uses the normal terminal.
pub fn run() -> Result<()> {
    let paths = Paths::resolve()?;
    let mut view = data::VaultView::load(&paths)?;
    // A first run has no snapshot. Create the snapshot key here, before raw
    // mode, so the interface can sign in without handing the terminal back.
    if !paths.snapshot_file.is_file() {
        crate::vault::prepare(&paths, &mut view.config)?;
        let salt = view.config.kdf_salt.clone();
        view.config = crate::config::Config::update(&paths, |config| {
            config.kdf_salt = salt;
        })?;
    }
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
