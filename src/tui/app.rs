//! The app shell: state, widgets, and event wiring.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use chrono::Utc;
use opentui::prelude::*;

use crate::error::{Error, Result};

use super::data::{Category, Row, RowSource, VaultView, CATEGORIES};
use super::theme::{Chrome, HINTS_BROWSER, HINTS_DASHBOARD, WORDMARK};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Screen {
    Dashboard,
    Browser,
    Help,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    List,
    Notes,
    Wifi,
    Passkeys,
    Groups,
    Trash,
    Pending,
    Status,
    Get,
    Help,
    Quit,
}

const COMMANDS: &[Command] = &[
    Command::List,
    Command::Notes,
    Command::Wifi,
    Command::Passkeys,
    Command::Groups,
    Command::Trash,
    Command::Pending,
    Command::Status,
    Command::Get,
    Command::Help,
    Command::Quit,
];

impl Command {
    fn name(self) -> &'static str {
        match self {
            Command::List => "list",
            Command::Notes => "notes",
            Command::Wifi => "wifi",
            Command::Passkeys => "passkeys",
            Command::Groups => "groups",
            Command::Trash => "trash",
            Command::Pending => "pending",
            Command::Status => "status",
            Command::Get => "get",
            Command::Help => "help",
            Command::Quit => "quit",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Command::List => "browse logins",
            Command::Notes => "browse secure notes",
            Command::Wifi => "browse wi-fi networks",
            Command::Passkeys => "browse passkeys",
            Command::Groups => "browse groups",
            Command::Trash => "browse deleted items",
            Command::Pending => "browse queued changes",
            Command::Status => "account and sync status",
            Command::Get => "open the selected item",
            Command::Help => "keys and commands",
            Command::Quit => "leave apw",
        }
    }

    fn category(self) -> Option<Category> {
        match self {
            Command::List => Some(Category::Logins),
            Command::Notes => Some(Category::Notes),
            Command::Wifi => Some(Category::Wifi),
            Command::Passkeys => Some(Category::Passkeys),
            Command::Groups => Some(Category::Groups),
            Command::Trash => Some(Category::Trash),
            Command::Pending => Some(Category::Pending),
            _ => None,
        }
    }
}

const HELP_TEXT: &str = "\
Keys
  up / down      move through a list
  enter          open the selected item
  tab            move focus
  /              command palette
  ctrl+p         command palette
  esc            back
  ctrl+c         quit

Commands
  list     notes     wifi      passkeys
  groups   trash     pending   status
  get      help      quit

Every command works from the palette. Type to filter.";

struct UiState {
    view: VaultView,
    screen: Screen,
    category: Category,
    query: String,
    rows: Vec<Row>,
    recents: Vec<Row>,
    selected: usize,
    size: (u16, u16),
    detail_open: bool,
    palette_open: bool,
    palette_commands: Vec<Command>,
    revealed: bool,
}

#[derive(Clone)]
struct Ui {
    state: Rc<RefCell<UiState>>,
    app: App,
    dashboard: View,
    browser: View,
    wordmark: Text,
    columns: View,
    left: View,
    right: View,
    status: Text,
    counts: Text,
    warnings: Text,
    recents: Select,
    activity: Text,
    tabs: TabSelect,
    split: View,
    list_pane: View,
    list: Select,
    detail: ScrollBox,
    detail_text: Text,
    help: View,
    palette: View,
    palette_select: Select,
    composer: Input,
    breadcrumb: Text,
    hints: Text,
    sync: Text,
}

pub fn run(view: VaultView) -> Result<()> {
    let options = AppOptions::default().with_theme(Theme::terminal());
    let app = App::new(options).map_err(|error| Error::Message(error.to_string()))?;
    let ui = Ui::build(app.clone(), view);
    ui.wire();
    let (width, height) = app.size();
    if width > 0 && height > 0 {
        ui.resize(width, height);
    }
    ui.refresh();
    app.run().map_err(|error| Error::Message(error.to_string()))
}

impl Ui {
    fn build(app: App, view: VaultView) -> Self {
        let chrome = Chrome::terminal();
        let root = app.root();
        root.column();

        let state = Rc::new(RefCell::new(UiState {
            view,
            screen: Screen::Dashboard,
            category: Category::Logins,
            query: String::new(),
            rows: Vec::new(),
            recents: Vec::new(),
            selected: 0,
            size: {
                let (width, height) = app.size();
                if width == 0 || height == 0 {
                    (100, 30)
                } else {
                    (width, height)
                }
            },
            detail_open: false,
            palette_open: false,
            palette_commands: Vec::new(),
            revealed: false,
        }));

        let dashboard = View::new(&app).column().grow(1.0).padding(1).gap(1);
        let wordmark = Text::new(&app, WORDMARK)
            .fg(chrome.fg)
            .bold()
            .align(Alignment::Center)
            .width(Length::percent(100.0));
        dashboard.add(&wordmark);

        let columns = View::new(&app).row().gap(2).grow(1.0);
        let left = View::new(&app).column().gap(1).width(Length::percent(40.0));
        let right = View::new(&app).column().gap(1).grow(1.0);
        let status = Text::new(&app, "").fg(chrome.muted);
        let counts = Text::new(&app, "").fg(chrome.fg);
        let warnings = Text::new(&app, "").fg(chrome.warning);
        let actions = Text::new(&app, "sync   search   add   groups   trash").fg(chrome.muted);
        left.add(&status);
        left.add(&counts);
        left.add(&warnings);
        left.add(&actions);

        let recent_label = Text::new(&app, "RECENT").fg(chrome.muted).bold();
        let recents = Select::new(&app)
            .grow(1.0)
            .show_description(true)
            .selected_colors(chrome.selected_fg, chrome.selected_bg)
            .description_colors(chrome.muted, chrome.selected_fg);
        let activity_label = Text::new(&app, "ACTIVITY").fg(chrome.muted).bold();
        let activity = Text::new(&app, "").fg(chrome.muted).wrap(WrapMode::Word);
        right.add(&recent_label);
        right.add(&recents);
        right.add(&activity_label);
        right.add(&activity);

        columns.add(&left);
        columns.add(&right);
        dashboard.add(&columns);

        let browser = View::new(&app).column().grow(1.0).padding(1).gap(1);
        let tabs = TabSelect::new(&app)
            .options(CATEGORIES.iter().map(|category| category.label()))
            .tab_width(12)
            .selected_colors(chrome.selected_fg, chrome.selected_bg)
            .description_color(chrome.muted);
        let split = View::new(&app).row().gap(2).grow(1.0);
        let list = Select::new(&app)
            .grow(1.0)
            .height(Length::percent(100.0))
            .show_description(true)
            .selected_colors(chrome.selected_fg, chrome.selected_bg)
            .description_colors(chrome.muted, chrome.selected_fg);
        let list_pane = View::new(&app).width(Length::percent(42.0)).child(&list);
        let detail = ScrollBox::new(&app).grow(1.0).padding_x(1).focusable(true);
        let detail_text = Text::new(&app, "").fg(chrome.fg).wrap(WrapMode::Word);
        detail.add(&detail_text);
        split.add(&list_pane);
        split.add(&detail);
        browser.add(&tabs);
        browser.add(&split);

        let composer_box = View::new(&app)
            .border(BorderStyle::Single)
            .border_color(chrome.border)
            .padding_x(1)
            .height(3);
        let composer = Input::new(&app).placeholder("Search the vault, or type / for commands");
        composer_box.add(&composer);

        let palette = View::new(&app)
            .column()
            .border(BorderStyle::Single)
            .border_color(chrome.border)
            .padding(1)
            .gap(1)
            .height(12)
            .visible(false);
        let palette_title = Text::new(&app, "COMMANDS").fg(chrome.muted).bold();
        let palette_select = Select::new(&app)
            .grow(1.0)
            .show_description(true)
            .selected_colors(chrome.selected_fg, chrome.selected_bg)
            .description_colors(chrome.muted, chrome.selected_fg);
        palette.add(&palette_title);
        palette.add(&palette_select);

        let help = View::new(&app).column().padding(1).grow(1.0).visible(false);
        let help_text = Text::new(&app, HELP_TEXT)
            .fg(chrome.fg)
            .wrap(WrapMode::Word);
        help.add(&help_text);

        let footer = View::new(&app).row().height(1).padding_x(1);
        let breadcrumb = Text::new(&app, "")
            .fg(chrome.muted)
            .width(Length::percent(28.0));
        let hints = Text::new(&app, HINTS_DASHBOARD)
            .fg(chrome.muted)
            .align(Alignment::Center)
            .grow(1.0);
        let sync = Text::new(&app, "")
            .fg(chrome.muted)
            .align(Alignment::Right)
            .width(Length::percent(22.0));
        footer.add(&breadcrumb);
        footer.add(&hints);
        footer.add(&sync);

        root.add(&dashboard);
        root.add(&browser);
        root.add(&help);
        root.add(&palette);
        root.add(&composer_box);
        root.add(&footer);

        let ui = Self {
            state,
            app,
            dashboard,
            browser,
            wordmark,
            columns,
            left,
            right,
            status,
            counts,
            warnings,
            recents,
            activity,
            tabs,
            split,
            list_pane,
            list,
            detail,
            detail_text,
            help,
            palette,
            palette_select,
            composer,
            breadcrumb,
            hints,
            sync,
        };
        ui.apply_layout();
        ui
    }

    fn apply_layout(&self) {
        let (width, detail_open) = {
            let state = self.state.borrow();
            (state.size.0, state.detail_open)
        };
        let wide = width >= 96;
        let two_columns = width >= 60;
        let compact = width < 60;
        self.wordmark.visible(!compact);
        if two_columns {
            self.columns.row();
        } else {
            self.columns.column();
        }
        self.left.width(if two_columns {
            Length::percent(42.0)
        } else {
            Length::percent(100.0)
        });
        self.right.visible(two_columns);
        if wide {
            self.split.row();
            self.list_pane
                .width(Length::percent(42.0))
                .height(Length::percent(100.0));
        } else {
            self.split.column();
            self.list_pane
                .width(Length::percent(100.0))
                .height(Length::percent(50.0));
        }
        self.list_pane.visible(!(compact && detail_open));
        self.detail.visible(!compact || detail_open);
        self.tabs.visible(!(compact && detail_open));
    }

    fn resize(&self, width: u16, height: u16) {
        self.state.borrow_mut().size = (width, height);
        self.apply_layout();
    }

    fn wire(&self) {
        let ui = self.clone();
        self.composer
            .on_change(move |_cx, value| ui.set_query(value.to_string()));
        let ui = self.clone();
        self.composer.on_submit(move |cx, _| ui.submit(cx));
        let ui = self.clone();
        self.tabs
            .on_change(move |_cx, index, _| ui.set_category(index));
        let ui = self.clone();
        self.list
            .on_change(move |_cx, index, _| ui.select_row(index));
        let ui = self.clone();
        self.list
            .on_select(move |_cx, index, _| ui.activate_row(index));
        let ui = self.clone();
        self.recents
            .on_select(move |_cx, index, _| ui.open_recent(index));
        let ui = self.clone();
        self.palette_select
            .on_select(move |cx, index, _| ui.run_palette(cx, index));
        let ui = self.clone();
        self.app.on_key(move |cx, key| ui.key(cx, key));
        let ui = self.clone();
        self.app
            .on_resize(move |_cx, width, height| ui.resize(width, height));
        self.composer.focus();
    }

    fn refresh(&self) {
        let (screen, palette_open) = {
            let state = self.state.borrow();
            (state.screen, state.palette_open)
        };
        self.dashboard.visible(screen == Screen::Dashboard);
        self.browser.visible(screen == Screen::Browser);
        self.help.visible(screen == Screen::Help);
        self.palette.visible(palette_open);
        self.apply_layout();
        self.refresh_rows();
        self.refresh_dashboard();
        self.refresh_footer();
    }

    fn refresh_rows(&self) {
        let (rows, selected, reveal) = {
            let state = self.state.borrow();
            let rows = state.category.rows(&state.view, &state.query);
            let selected = state.selected.min(rows.len().saturating_sub(1));
            (rows, selected, state.revealed)
        };
        let detail = rows
            .get(selected)
            .map(|row| row.detail_rows(Utc::now(), reveal));
        self.list.options(
            rows.iter()
                .map(|row| SelectOption::new(row.title.clone(), row.subtitle.clone())),
        );
        self.list.select(selected);
        self.detail_text.set_text(detail_text(detail.as_ref()));
        let mut state = self.state.borrow_mut();
        state.rows = rows;
        state.selected = selected;
    }

    fn refresh_dashboard(&self) {
        let dashboard = self.state.borrow().view.dashboard(Utc::now());
        let account = dashboard.account.as_deref().unwrap_or("not signed in");
        self.status
            .set_text(format!("{account}   {}", sync_label(dashboard.last_sync)));
        let counts = dashboard
            .counts
            .iter()
            .map(|(label, count)| format!("{count} {label}"))
            .collect::<Vec<_>>();
        self.counts.set_text(
            counts
                .chunks(3)
                .map(|chunk| chunk.join("   "))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        self.warnings.set_text(dashboard.warnings.join("\n"));
        self.recents.options(
            dashboard
                .recents
                .iter()
                .map(|row| SelectOption::new(row.title.clone(), row.subtitle.clone())),
        );
        self.activity.set_text(dashboard.activity.join("\n"));
        let recents = dashboard.recents;
        self.state.borrow_mut().recents = recents;
    }

    fn refresh_footer(&self) {
        let state = self.state.borrow();
        let breadcrumb = match state.screen {
            Screen::Dashboard => "dashboard".to_string(),
            Screen::Help => "help".to_string(),
            Screen::Browser => {
                let mut text = format!("vault / {}", state.category.label());
                if !state.query.is_empty() {
                    text.push_str(" / ");
                    text.push_str(&state.query);
                }
                text
            }
        };
        let hints = match (state.screen, state.size.0) {
            (Screen::Dashboard, 90..) => HINTS_DASHBOARD,
            (Screen::Dashboard, 60..) => "type /   tab   ctrl+c",
            (Screen::Dashboard, _) => "/  tab  ^c",
            (Screen::Browser, 90..) => HINTS_BROWSER,
            (Screen::Browser, 60..) => "↑↓   enter   /   esc   ctrl+c",
            (Screen::Browser, _) => "↑↓  enter  /  esc",
            (Screen::Help, _) => "esc back",
        };
        let sync = sync_label(state.view.last_sync());
        drop(state);
        self.breadcrumb.set_text(breadcrumb);
        self.hints.set_text(hints);
        self.sync.set_text(sync);
    }

    fn set_query(&self, query: String) {
        let palette = query.starts_with('/');
        {
            let mut state = self.state.borrow_mut();
            state.query = query;
            state.palette_open = palette;
            state.selected = 0;
        }
        if palette {
            self.refresh_palette();
        } else {
            self.palette.visible(false);
            self.refresh_rows();
        }
        self.refresh_footer();
    }

    fn refresh_palette(&self) {
        let term = {
            let state = self.state.borrow();
            state.query.trim_start_matches('/').trim().to_lowercase()
        };
        let commands = COMMANDS
            .iter()
            .copied()
            .filter(|command| {
                command.name().contains(&term)
                    || command.description().to_lowercase().contains(&term)
            })
            .collect::<Vec<_>>();
        self.palette_select.options(
            commands
                .iter()
                .map(|command| SelectOption::new(command.name(), command.description())),
        );
        self.palette_select.select(0);
        self.palette.visible(true);
        self.state.borrow_mut().palette_commands = commands;
        self.composer.focus();
    }

    fn close_palette(&self) {
        self.state.borrow_mut().palette_open = false;
        self.palette.visible(false);
        self.composer.set_value("");
        self.set_query(String::new());
        self.composer.focus();
    }

    fn move_palette(&self, step: isize) {
        let count = self.palette_select.option_count();
        if count == 0 {
            return;
        }
        let current = self.palette_select.selected() as isize;
        let next = (current + step).rem_euclid(count as isize) as usize;
        self.palette_select.select(next);
    }

    fn run_palette(&self, cx: &mut Cx<'_>, index: usize) {
        let command = self.state.borrow().palette_commands.get(index).copied();
        if let Some(command) = command {
            self.run_command(cx, command);
        }
    }

    fn run_command(&self, cx: &mut Cx<'_>, command: Command) {
        if command == Command::Quit {
            cx.quit();
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            state.palette_open = false;
            state.query.clear();
        }
        self.palette.visible(false);
        self.composer.set_value("");
        match command {
            Command::Help => {
                self.state.borrow_mut().screen = Screen::Help;
                self.refresh();
                self.composer.focus();
            }
            Command::Status => {
                self.state.borrow_mut().screen = Screen::Dashboard;
                self.refresh();
                self.composer.focus();
            }
            Command::Get => {
                self.state.borrow_mut().screen = Screen::Browser;
                self.refresh();
                let index = self.list.selected();
                self.activate_row(index);
            }
            _ => {
                if let Some(category) = command.category() {
                    {
                        let mut state = self.state.borrow_mut();
                        state.screen = Screen::Browser;
                        state.category = category;
                        state.selected = 0;
                        state.detail_open = false;
                        state.revealed = false;
                    }
                    self.tabs.select(category.index());
                    self.refresh();
                    self.list.focus();
                }
            }
        }
    }

    fn set_category(&self, index: usize) {
        let Some(category) = CATEGORIES.get(index).copied() else {
            return;
        };
        {
            let mut state = self.state.borrow_mut();
            state.category = category;
            state.selected = 0;
            state.revealed = false;
        }
        self.refresh_rows();
        self.refresh_footer();
    }

    fn select_row(&self, index: usize) {
        let detail = {
            let mut state = self.state.borrow_mut();
            if state.selected != index {
                state.revealed = false;
            }
            state.selected = index;
            let reveal = state.revealed;
            state
                .rows
                .get(index)
                .map(|row| row.detail_rows(Utc::now(), reveal))
        };
        self.detail_text.set_text(detail_text(detail.as_ref()));
    }

    fn activate_row(&self, index: usize) {
        self.select_row(index);
        self.state.borrow_mut().detail_open = true;
        self.apply_layout();
        self.detail.focus();
    }

    fn selected_entry(&self) -> Option<crate::model::Entry> {
        let state = self.state.borrow();
        match &state.rows.get(state.selected)?.source {
            RowSource::Entry(entry) => Some((**entry).clone()),
            RowSource::Trash(trash) => Some(trash.entry.clone()),
            _ => None,
        }
    }

    fn copy_password(&self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        if let Some(password) = entry.password.as_deref().filter(|value| !value.is_empty()) {
            self.app.copy_to_clipboard(password);
        }
    }

    fn copy_otp(&self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let Some(totp) = entry.totp.as_ref() else {
            return;
        };
        if let Ok(code) = crate::totp::generate(totp, SystemTime::now()) {
            self.app.copy_to_clipboard(&code);
        }
    }

    fn reveal_password(&self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        if entry.password.is_none() {
            return;
        }
        self.state.borrow_mut().revealed = true;
        self.refresh_rows();
        let ui = self.clone();
        self.app.set_timeout(Duration::from_secs(20), move |_cx| {
            ui.state.borrow_mut().revealed = false;
            ui.refresh_rows();
        });
    }

    fn open_recent(&self, index: usize) {
        let Some(row) = self.state.borrow().recents.get(index).cloned() else {
            return;
        };
        let category = match &row.source {
            RowSource::Entry(entry) => match entry.kind {
                crate::model::EntryKind::Note => Category::Notes,
                crate::model::EntryKind::Wifi => Category::Wifi,
                crate::model::EntryKind::Passkey => Category::Passkeys,
                _ => Category::Logins,
            },
            RowSource::Group(_) => Category::Groups,
            RowSource::Trash(_) => Category::Trash,
            RowSource::Pending(_) => Category::Pending,
        };
        {
            let mut state = self.state.borrow_mut();
            state.screen = Screen::Browser;
            state.category = category;
            state.query = row.title.clone();
            state.selected = 0;
            state.detail_open = state.size.0 < 60;
            state.revealed = false;
        }
        self.tabs.select(category.index());
        self.composer.set_value(row.title.clone());
        self.refresh();
        if self.state.borrow().detail_open {
            self.detail.focus();
        } else {
            self.list.focus();
        }
    }

    fn submit(&self, cx: &mut Cx<'_>) {
        if self.state.borrow().palette_open {
            let index = self.palette_select.selected();
            self.run_palette(cx, index);
            return;
        }
        match self.state.borrow().screen {
            Screen::Dashboard => {
                self.state.borrow_mut().screen = Screen::Browser;
                self.refresh();
                self.list.focus();
            }
            Screen::Browser => {
                self.list.focus();
            }
            Screen::Help => {
                self.state.borrow_mut().screen = Screen::Dashboard;
                self.refresh();
                self.composer.focus();
            }
        }
    }

    fn open_palette(&self) {
        self.composer.set_value("/");
        self.set_query("/".into());
        self.composer.focus();
    }

    fn back(&self) {
        let (screen, compact, detail_open, palette_open) = {
            let state = self.state.borrow();
            (
                state.screen,
                state.size.0 < 60,
                state.detail_open,
                state.palette_open,
            )
        };
        if palette_open {
            self.close_palette();
            return;
        }
        if compact && detail_open {
            self.state.borrow_mut().detail_open = false;
            self.apply_layout();
            self.list.focus();
            return;
        }
        match screen {
            Screen::Help => {
                self.state.borrow_mut().screen = Screen::Dashboard;
                self.refresh();
                self.composer.focus();
            }
            Screen::Browser => {
                self.state.borrow_mut().screen = Screen::Dashboard;
                self.refresh();
                self.composer.focus();
            }
            Screen::Dashboard => {
                if !self.state.borrow().query.is_empty() {
                    self.composer.set_value("");
                    self.set_query(String::new());
                }
            }
        }
    }

    fn key(&self, cx: &mut Cx<'_>, key: &KeyEvent) {
        if key.matches("ctrl+c") {
            cx.quit();
            return;
        }
        if key.matches("escape") {
            if self.state.borrow().palette_open {
                self.close_palette();
            } else {
                self.back();
            }
            return;
        }
        if self.state.borrow().palette_open {
            if key.matches("enter") {
                let index = self.palette_select.selected();
                self.run_palette(cx, index);
                cx.stop_propagation();
                return;
            }
            if key.matches("down") {
                self.move_palette(1);
                cx.stop_propagation();
                return;
            }
            if key.matches("up") {
                self.move_palette(-1);
                cx.stop_propagation();
                return;
            }
        }
        if key.matches("ctrl+p") {
            self.open_palette();
            cx.stop_propagation();
            return;
        }
        let (browser, palette_open) = {
            let state = self.state.borrow();
            (state.screen == Screen::Browser, state.palette_open)
        };
        if browser && !palette_open && !self.composer.is_focused() {
            if key.matches("y") {
                self.copy_password();
                cx.stop_propagation();
                return;
            }
            if key.matches("o") {
                self.copy_otp();
                cx.stop_propagation();
                return;
            }
            if key.matches("r") {
                self.reveal_password();
                cx.stop_propagation();
                return;
            }
        }
        if key.matches("ctrl+tab") {
            self.cycle_category(1);
            cx.stop_propagation();
            return;
        }
        if key.matches("ctrl+shift+tab") {
            self.cycle_category(-1);
            cx.stop_propagation();
            return;
        }
        if key.matches("/") && !self.composer.is_focused() {
            self.open_palette();
            cx.stop_propagation();
            return;
        }
        if key.matches("q") && !self.composer.is_focused() {
            cx.quit();
        }
    }

    fn cycle_category(&self, step: isize) {
        let index = self.state.borrow().category.index() as isize;
        let next = (index + step).rem_euclid(CATEGORIES.len() as isize) as usize;
        self.tabs.select(next);
        self.set_category(next);
    }
}

fn detail_text(rows: Option<&Vec<(String, String)>>) -> String {
    let Some(rows) = rows else {
        return String::new();
    };
    let mut text = rows
        .iter()
        .map(|(label, value)| format!("{label:<14} {value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let has_password = rows.iter().any(|(label, _)| label == "Password");
    let has_otp = rows.iter().any(|(label, _)| label == "One-time code");
    let mut actions = Vec::new();
    if has_password {
        actions.push("y copy password");
        actions.push("r reveal 20s");
    }
    if has_otp {
        actions.push("o copy otp");
    }
    if !actions.is_empty() {
        text.push_str("\n\nactions  ");
        text.push_str(&actions.join("   "));
    }
    text
}

fn sync_label(last: Option<chrono::DateTime<Utc>>) -> String {
    match last {
        Some(at) => format!("synced {}", super::data::relative(at, Utc::now())),
        None => "no sync yet".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, State};
    use crate::model::{Entry, EntryKind, Vault};
    use opentui::testing::TestApp;

    fn view() -> VaultView {
        VaultView {
            vault: Vault {
                entries: vec![
                    Entry {
                        id: "one".into(),
                        kind: EntryKind::Login,
                        title: Some("Example".into()),
                        username: Some("alice".into()),
                        password: Some("hunter2".into()),
                        updated_at: Some(Utc::now()),
                        ..Entry::default()
                    },
                    Entry {
                        id: "two".into(),
                        kind: EntryKind::Login,
                        title: Some("Other".into()),
                        username: Some("bob".into()),
                        updated_at: Some(Utc::now()),
                        ..Entry::default()
                    },
                ],
                ..Vault::default()
            },
            state: State::default(),
            config: Config::default(),
        }
    }

    fn ui(app: &TestApp) -> Ui {
        let ui = Ui::build((**app).clone(), view());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();
        ui
    }

    fn ui_sized(app: &TestApp, width: u16, height: u16) -> Ui {
        let ui = Ui::build((**app).clone(), view());
        ui.wire();
        ui.resize(width, height);
        ui.refresh();
        ui
    }

    #[test]
    fn dashboard_renders_counts_and_recents() {
        let app = TestApp::new(100, 30);
        let _ui = ui(&app);
        let text = app.render().text();
        assert!(text.contains("RECENT"), "{text}");
        assert!(text.contains("2 logins"), "{text}");
        assert!(text.contains("Example"), "{text}");
    }

    #[test]
    fn typing_filters_the_list() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.set_query("exam".into());
        assert_eq!(ui.list.option_count(), 1);
        ui.set_query("nobody".into());
        assert_eq!(ui.list.option_count(), 0);
    }

    #[test]
    fn slash_opens_and_filters_the_command_palette() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.set_query("/".into());
        assert!(ui.state.borrow().palette_open);
        assert_eq!(ui.palette_select.option_count(), COMMANDS.len());
        ui.set_query("/qui".into());
        assert_eq!(ui.palette_select.option_count(), 1);
        ui.set_query("/not".into());
        assert_eq!(ui.palette_select.option_count(), 1);
        ui.back();
        assert!(!ui.state.borrow().palette_open);
        assert!(ui.state.borrow().query.is_empty());
    }

    #[test]
    fn palette_enter_runs_the_selected_command() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.set_query("/notes".into());
        app.press("enter");
        assert_eq!(ui.state.borrow().screen, Screen::Browser);
        assert_eq!(ui.state.borrow().category, Category::Notes);

        ui.set_query("/help".into());
        app.press("enter");
        assert_eq!(ui.state.borrow().screen, Screen::Help);
        app.press("escape");
        assert_eq!(ui.state.borrow().screen, Screen::Dashboard);
    }

    #[test]
    fn reveal_shows_the_password_until_the_selection_moves() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        {
            let mut state = ui.state.borrow_mut();
            state.screen = Screen::Browser;
            state.query.clear();
            state.selected = 0;
        }
        ui.refresh();
        ui.reveal_password();
        let text = app.render().text();
        assert!(text.contains("hunter2"), "{text}");
        ui.select_row(1);
        let text = app.render().text();
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn browser_shows_the_selected_entry() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        {
            let mut state = ui.state.borrow_mut();
            state.screen = Screen::Browser;
            state.query.clear();
        }
        ui.refresh();
        let text = app.render().text();
        assert!(text.contains("Logins"), "{text}");
        assert!(text.contains("Username"), "{text}");
        assert!(text.contains("alice"), "{text}");
    }

    #[test]
    #[ignore]
    fn dump_palette() {
        let app = TestApp::new(100, 30);
        let ui = ui_sized(&app, 100, 30);
        ui.set_query("/".into());
        let frame = app.render();
        println!("--- palette 100x30 ---");
        for y in 0..30u32 {
            println!("{y:02}|{}|", frame.row(y));
        }
    }

    #[test]
    #[ignore]
    fn dump_browser() {
        for (width, height) in [(100, 30), (70, 24), (40, 16)] {
            let app = TestApp::new(width, height);
            let ui = ui_sized(&app, width, height);
            {
                let mut state = ui.state.borrow_mut();
                state.screen = Screen::Browser;
                state.query.clear();
            }
            ui.refresh();
            let frame = app.render();
            println!("--- browser {width}x{height} ---");
            for y in 0..height as u32 {
                println!("{y:02}|{}|", frame.row(y));
            }
        }
    }

    #[test]
    #[ignore]
    fn dump_frame() {
        for (width, height) in [(100, 30), (70, 24), (40, 16)] {
            let app = TestApp::new(width, height);
            let _ui = ui_sized(&app, width, height);
            let frame = app.render();
            println!("--- {width}x{height} ---");
            println!(
                "columns {:?} left {:?} right {:?} split {:?}",
                _ui.columns.rect(),
                _ui.left.rect(),
                _ui.right.rect(),
                _ui.split.rect()
            );
            for y in 0..height as u32 {
                println!("{y:02}|{}|", frame.row(y));
            }
        }
    }
}
