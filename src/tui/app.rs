//! The app shell: state, widgets, and event wiring.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use chrono::Utc;
use opentui::prelude::*;

use crate::error::{Error, Result};

use super::data::{Category, DashboardPhase, Row, RowSource, VaultView, CATEGORIES};
use super::page::{
    home_layout, palette_rect, Browser, Help, Home, Page, PageHandle, PageModel, PageView, Palette,
};
use super::secret::{SecretField, SecretValue};
use super::theme::{Tokens, WORDMARK, WORDMARK_COMPACT};
use super::view::{truncate, Line};

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
    PasskeyImport,
    PasskeyExport,
    Groups,
    Trash,
    Pending,
    AddLogin,
    AddWifi,
    AddNote,
    Edit,
    Remove,
    Restore,
    ResolveLocal,
    ResolveRemote,
    Login,
    LoginRefresh,
    Join,
    Sync,
    SyncForce,
    Status,
    Get,
    Otp,
    Group,
    Help,
    Quit,
}

const COMMANDS: &[Command] = &[
    Command::List,
    Command::Notes,
    Command::Wifi,
    Command::Passkeys,
    Command::PasskeyImport,
    Command::PasskeyExport,
    Command::Groups,
    Command::Trash,
    Command::Pending,
    Command::AddLogin,
    Command::AddWifi,
    Command::AddNote,
    Command::Edit,
    Command::Remove,
    Command::Restore,
    Command::ResolveLocal,
    Command::ResolveRemote,
    Command::Login,
    Command::LoginRefresh,
    Command::Join,
    Command::Sync,
    Command::SyncForce,
    Command::Status,
    Command::Get,
    Command::Otp,
    Command::Group,
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
            Command::PasskeyImport => "passkey import",
            Command::PasskeyExport => "passkey export",
            Command::Groups => "groups",
            Command::Trash => "trash",
            Command::Pending => "pending",
            Command::AddLogin => "add",
            Command::AddWifi => "add wifi",
            Command::AddNote => "add note",
            Command::Edit => "edit",
            Command::Remove => "rm",
            Command::Restore => "restore",
            Command::ResolveLocal => "resolve --local",
            Command::ResolveRemote => "resolve --remote",
            Command::Login => "login",
            Command::LoginRefresh => "login --refresh",
            Command::Join => "join",
            Command::Sync => "sync",
            Command::SyncForce => "sync --force",
            Command::Status => "status",
            Command::Get => "get",
            Command::Otp => "otp",
            Command::Group => "group",
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
            Command::PasskeyImport => "import passkeys from a credential export",
            Command::PasskeyExport => "export passkeys to a credential file",
            Command::Groups => "browse groups",
            Command::Trash => "browse deleted items",
            Command::Pending => "browse queued changes",
            Command::AddLogin => "add a login",
            Command::AddWifi => "add a wi-fi network",
            Command::AddNote => "add a secure note",
            Command::Edit => "edit the selected item",
            Command::Remove => "move the selected item to Recently Deleted",
            Command::Restore => "restore the selected trashed item",
            Command::ResolveLocal => "keep the local change for the selected pending op",
            Command::ResolveRemote => "take the remote version for the selected pending op",
            Command::Login => "sign in to Apple ID",
            Command::LoginRefresh => "refresh the service URLs without signing in",
            Command::Join => "join the trust with the escrow passcode",
            Command::Sync => "sync with iCloud now",
            Command::SyncForce => "sync and override the 5 minute floor",
            Command::Status => "account and sync status",
            Command::Get => "open the selected item",
            Command::Otp => "copy the selected one-time code",
            Command::Group => "add or remove the selected item's group",
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

#[derive(Clone)]
struct SyncFinished(std::result::Result<crate::commands::sync::SyncOutcome, String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthStep {
    Anisette,
    Account,
    Password,
    TwoFactor,
    Escrow,
    JoinConfirm,
}

struct AuthState {
    step: AuthStep,
    anisette: String,
    account: String,
    password: String,
    code: String,
    escrow: String,
    flow: Option<crate::auth::TwoFactor>,
    busy: bool,
    error: Option<String>,
    join_only: bool,
}

enum AuthEvent {
    Started {
        attempt: u64,
        account: String,
        result: std::result::Result<crate::auth::LoginStart, String>,
    },
    Joined {
        attempt: u64,
        result: std::result::Result<String, String>,
    },
    Refreshed(std::result::Result<(String, crate::model::Session), String>),
}

impl AuthEvent {
    fn attempt(&self) -> Option<u64> {
        match self {
            AuthEvent::Started { attempt, .. } | AuthEvent::Joined { attempt, .. } => {
                Some(*attempt)
            }
            AuthEvent::Refreshed(_) => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FocusTarget {
    Composer,
    List,
    Detail,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormKind {
    AddLogin,
    AddWifi,
    AddNote,
    EditLogin,
    EditWifi,
    EditNote,
    PasskeyImport,
    PasskeyExport,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RowKey {
    Site,
    Username,
    Title,
    Password,
    Totp,
    Notes,
}

struct FormState {
    kind: FormKind,
    editing: Option<String>,
    focus: usize,
    error: Option<String>,
    review: Option<Vec<String>>,
    prepared: Option<PreparedForm>,
    original: OriginalValues,
}

#[derive(Default)]
struct OriginalValues {
    url: String,
    username: String,
    title: String,
    notes: String,
    totp: String,
}

enum PreparedForm {
    Add(Box<crate::commands::write::PendingAdd>),
    Edit(Box<crate::commands::write::PendingEdit>),
    PasskeyImport(std::path::PathBuf),
    PasskeyExport(std::path::PathBuf),
}

struct ConfirmState {
    action: PendingAction,
    armed: bool,
}

struct PickerItem {
    label: String,
    detail: String,
    zone: String,
}

struct PickerState {
    items: Vec<PickerItem>,
    selected: usize,
}

#[derive(Clone)]
enum PendingAction {
    Trash {
        id: String,
        name: String,
    },
    Restore {
        id: String,
        name: String,
    },
    Resolve {
        id: String,
        local: bool,
        label: String,
    },
    GroupRemove {
        zone: String,
        record: String,
        name: String,
    },
    DiscardForm,
}

#[derive(Clone)]
struct FormRow {
    view: View,
    label: Text,
    input: Option<Input>,
    textarea: Option<Textarea>,
    secret: bool,
}

impl FormKind {
    fn rows(self) -> &'static [RowKey] {
        match self {
            FormKind::AddLogin => &[
                RowKey::Site,
                RowKey::Username,
                RowKey::Title,
                RowKey::Password,
                RowKey::Totp,
                RowKey::Notes,
            ],
            FormKind::EditLogin => &[RowKey::Title, RowKey::Password, RowKey::Totp, RowKey::Notes],
            FormKind::AddWifi => &[RowKey::Site, RowKey::Password],
            FormKind::EditWifi => &[RowKey::Password],
            FormKind::AddNote | FormKind::EditNote => &[RowKey::Title, RowKey::Notes],
            FormKind::PasskeyImport | FormKind::PasskeyExport => &[RowKey::Site],
        }
    }

    fn title(self) -> &'static str {
        match self {
            FormKind::AddLogin => "NEW LOGIN",
            FormKind::AddWifi => "NEW WI-FI NETWORK",
            FormKind::AddNote => "NEW NOTE",
            FormKind::EditLogin => "EDIT LOGIN",
            FormKind::EditWifi => "EDIT WI-FI NETWORK",
            FormKind::EditNote => "EDIT NOTE",
            FormKind::PasskeyImport => "IMPORT PASSKEYS",
            FormKind::PasskeyExport => "EXPORT PASSKEYS",
        }
    }

    fn label(self, row: RowKey) -> &'static str {
        match (self, row) {
            (FormKind::AddWifi, RowKey::Site) => "Network",
            (FormKind::PasskeyImport | FormKind::PasskeyExport, RowKey::Site) => "File",
            (FormKind::AddNote | FormKind::EditNote, RowKey::Notes) => "Body",
            (_, RowKey::Site) => "Site",
            (_, RowKey::Username) => "Username",
            (_, RowKey::Title) => "Title",
            (_, RowKey::Password) => "Password",
            (_, RowKey::Totp) => "One-time code",
            (_, RowKey::Notes) => "Notes",
        }
    }

    fn is_add(self) -> bool {
        matches!(
            self,
            FormKind::AddLogin | FormKind::AddWifi | FormKind::AddNote
        )
    }

    fn is_standalone(self) -> bool {
        matches!(self, FormKind::PasskeyImport | FormKind::PasskeyExport)
    }
}

impl RowKey {
    fn index(self) -> usize {
        match self {
            RowKey::Site => 0,
            RowKey::Username => 1,
            RowKey::Title => 2,
            RowKey::Password => 3,
            RowKey::Totp => 4,
            RowKey::Notes => 5,
        }
    }
}

struct UiState {
    view: VaultView,
    screen: Screen,
    help_return: Screen,
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
    syncing: bool,
    modal_open: bool,
    modal_focus: FocusTarget,
    form: Option<FormState>,
    picker: Option<PickerState>,
    confirm: Option<ConfirmState>,
    auth: Option<AuthState>,
    auth_attempt: u64,
    last_trash: Option<(String, String)>,
    snapshot_mtime: Option<SystemTime>,
    focus: FocusTarget,
    recent_selected: usize,
    detail_scroll: usize,
    help_scroll: usize,
    palette_selected: usize,
}

#[derive(Clone)]
struct Ui {
    state: Rc<RefCell<UiState>>,
    app: App,
    tokens: Tokens,
    page_view: Custom<PageView>,
    page: PageHandle,
    prompt_box: View,
    prompt_row: View,
    prompt_rail: View,
    prompt: Input,
    prompt_cap: Custom<PromptCap>,
    location: Text,
    hints: Text,
    overlay: View,
    scrim: View,
    modal: View,
    modal_title: Text,
    modal_body: Text,
    modal_band: View,
    modal_error: Text,
    modal_help: Text,
    form_scroll: ScrollBox,
    rows: Vec<FormRow>,
    secret: Custom<SecretField>,
    secret_value: SecretValue,
    toast: View,
    toast_text: Text,
    toast_more: Text,
    toast_start: Text,
    toast_end: Text,
}

struct PromptCap {
    rail: Color,
    surface: Color,
}

impl Component for PromptCap {
    fn paint(&self, painter: &mut Painter<'_>) {
        let (width, _) = painter.size();
        if width == 0 {
            return;
        }
        painter.cell(0, 0, '╹', Style::new().fg(self.rail));
        if width > 1 {
            painter.text(
                1,
                0,
                &"▀".repeat(width.saturating_sub(1) as usize),
                Style::new().fg(self.surface),
            );
        }
    }
}

pub fn run(view: VaultView) -> Result<()> {
    let mut options = AppOptions::default().with_theme(Theme::terminal());
    options.palette_size = 16;
    let app = App::new(options).map_err(|error| Error::Message(error.to_string()))?;
    let tokens = Tokens::system(app.palette().as_ref());
    let ui = Ui::build(app.clone(), view, tokens);
    ui.wire();
    let (width, height) = app.size();
    if width > 0 && height > 0 {
        ui.resize(width, height);
    }
    ui.refresh();
    app.run().map_err(|error| Error::Message(error.to_string()))
}

impl Ui {
    fn build(app: App, view: VaultView, tokens: Tokens) -> Self {
        let root = app.root();
        root.column();

        let initial_category = view
            .config
            .tui
            .last_category
            .as_deref()
            .and_then(Category::from_key)
            .unwrap_or(Category::Logins);
        let state = Rc::new(RefCell::new(UiState {
            view,
            screen: Screen::Dashboard,
            help_return: Screen::Dashboard,
            category: initial_category,
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
            syncing: false,
            modal_open: false,
            modal_focus: FocusTarget::Composer,
            form: None,
            picker: None,
            confirm: None,
            auth: None,
            auth_attempt: 0,
            last_trash: None,
            snapshot_mtime: None,
            focus: FocusTarget::Composer,
            recent_selected: 0,
            detail_scroll: 0,
            help_scroll: 0,
            palette_selected: 0,
        }));

        let (page_view, page) = PageView::new(&app, &tokens);
        page_view.grow(1.0).focusable(true);
        root.add(&page_view);

        let footer = View::new(&app)
            .row()
            .height(1)
            .padding_x(2)
            .gap(2)
            .justify(Justify::SpaceBetween);
        let location = Text::new(&app, "").fg(tokens.muted).truncate(true);
        let hints = Text::new(&app, "")
            .fg(tokens.muted)
            .truncate(true)
            .shrink(1.0);
        footer.add(&location);
        footer.add(&hints);
        root.add(&footer);

        let prompt_box = View::new(&app).column().absolute().height(3).visible(false);
        let prompt_row = View::new(&app)
            .column()
            .height(2)
            .padding_edge(Edge::Top, 1)
            .bg(tokens.panel);
        let prompt_rail = View::new(&app)
            .row()
            .height(1)
            .padding_edge(Edge::Left, 2)
            .border(BorderStyle::Heavy)
            .border_sides(Sides::LEFT)
            .border_color(tokens.rail)
            .grow(1.0);
        let prompt = Input::new(&app)
            .placeholder("Search the vault, or type / for commands")
            .colors(tokens.text, tokens.panel)
            .focused_colors(tokens.text, tokens.panel)
            .grow(1.0);
        prompt_rail.add(&prompt);
        prompt_row.add(&prompt_rail);
        let prompt_cap = Custom::new(
            &app,
            PromptCap {
                rail: tokens.rail,
                surface: tokens.panel,
            },
        );
        prompt_box.add(&prompt_row);
        prompt_box.add(&prompt_cap);
        root.add(&prompt_box);

        let secret_value = SecretValue::new("");
        let secret = Custom::new(&app, SecretField::new(secret_value.clone()))
            .grow(1.0)
            .height(1)
            .focusable(true);
        let overlay = View::new(&app)
            .absolute()
            .size(Length::percent(100.0), Length::percent(100.0))
            .row()
            .justify(Justify::Center)
            .align_items(Align::Start)
            .z_index(100)
            .visible(false);
        let scrim = View::new(&app)
            .absolute()
            .size(Length::percent(100.0), Length::percent(100.0))
            .bg(Color::rgba(0, 0, 0, 150));
        overlay.add(&scrim);
        let modal = View::new(&app)
            .column()
            .bg(tokens.dialog)
            .padding_y(1)
            .gap(1)
            .width(Length::Cells(60.0));
        let modal_header = View::new(&app)
            .row()
            .height(1)
            .padding_x(3)
            .justify(Justify::SpaceBetween);
        let modal_title = Text::new(&app, "").fg(tokens.text).bold();
        let modal_close = Text::new(&app, "esc").fg(tokens.muted);
        modal_header.add(&modal_title);
        modal_header.add(&modal_close);
        let modal_body = Text::new(&app, "")
            .fg(tokens.muted)
            .wrap(WrapMode::Word)
            .padding_x(3)
            .visible(false);
        let modal_action = View::new(&app)
            .row()
            .height(3)
            .bg(tokens.hover)
            .padding_y(1)
            .padding_x(2)
            .justify(Justify::End)
            .visible(false);
        let modal_action_text = Text::new(&app, "review and save").fg(tokens.text);
        modal_action.add(&modal_action_text);
        let modal_error = Text::new(&app, "")
            .fg(tokens.error)
            .wrap(WrapMode::Word)
            .padding_x(3)
            .visible(false);
        let form_scroll = ScrollBox::new(&app)
            .column()
            .gap(1)
            .scrollbars(true)
            .scrollbar_colors(tokens.faint, tokens.hover)
            .shrink(1.0)
            .visible(false);
        let mut rows = Vec::new();
        for index in 0..6 {
            let field = View::new(&app)
                .column()
                .gap(0)
                .padding_x(3)
                .height(Length::Cells(2.0));
            let label = Text::new(&app, "").fg(tokens.text).height(1);
            field.add(&label);
            let (input, textarea) = if index == 3 {
                field.add(&secret);
                (None, None)
            } else if index == 5 {
                let textarea = Textarea::new(&app)
                    .grow(1.0)
                    .height(Length::Cells(3.0))
                    .colors(tokens.text, tokens.panel)
                    .focused_colors(tokens.text, tokens.panel)
                    .placeholder("Notes");
                field.add(&textarea);
                (None, Some(textarea))
            } else {
                let input = Input::new(&app)
                    .grow(1.0)
                    .colors(tokens.text, tokens.panel)
                    .focused_colors(tokens.text, tokens.panel);
                field.add(&input);
                (Some(input), None)
            };
            rows.push(FormRow {
                view: field,
                label,
                input,
                textarea,
                secret: index == 3,
            });
        }
        let modal_help = Text::new(&app, "")
            .fg(tokens.muted)
            .padding_x(3)
            .height(1)
            .truncate(true);
        modal.add(&modal_header);
        modal.add(&modal_body);
        for row in &rows {
            form_scroll.add(&row.view);
        }
        modal.add(&form_scroll);
        modal.add(&modal_action);
        modal.add(&modal_error);
        modal.add(&modal_help);
        overlay.add(&modal);
        root.add(&overlay);

        let toast = View::new(&app)
            .absolute()
            .position(Edge::Right, 2)
            .position(Edge::Top, 1)
            .column()
            .bg(tokens.hover)
            .padding_y(1)
            .padding_x(2)
            .width(Length::Cells(60.0))
            .z_index(200)
            .visible(false);
        let toast_text = Text::new(&app, "")
            .fg(tokens.text)
            .wrap(WrapMode::Word)
            .grow(1.0);
        let toast_more = Text::new(&app, "").fg(tokens.muted);
        let toast_row = View::new(&app).row().gap(1);
        let toast_rail = Text::new(&app, "┃").fg(tokens.text);
        let toast_end = Text::new(&app, "┃").fg(tokens.text);
        toast_row.add(&toast_rail);
        toast_row.add(&toast_text);
        toast_row.add(&toast_end);
        toast.add(&toast_row);
        toast.add(&toast_more);
        root.add(&toast);

        let ui = Self {
            state,
            app,
            tokens,
            page_view,
            page,
            prompt_box,
            prompt_row,
            prompt_rail,
            prompt,
            prompt_cap,
            location,
            hints,
            overlay,
            scrim,
            modal,
            modal_title,
            modal_body,
            modal_band: modal_action,
            modal_error,
            modal_help,
            form_scroll,
            rows,
            secret,
            secret_value,
            toast,
            toast_text,
            toast_more,
            toast_start: toast_rail,
            toast_end,
        };
        ui.apply_layout();
        ui
    }

    fn focus(&self, target: FocusTarget) {
        self.state.borrow_mut().focus = target;
        match target {
            FocusTarget::Composer => self.prompt.focus(),
            FocusTarget::List | FocusTarget::Detail => self.page_view.focus(),
        }
    }

    fn apply_layout(&self) {
        let (width, height) = {
            let state = self.state.borrow();
            state.size
        };
        let w = u32::from(width);
        let h = u32::from(height);
        let prompt_height = 3;
        let footer_top = h.saturating_sub(1);
        let pad = if w < 44 { 1 } else { 2 };
        let column = w.saturating_sub(pad * 2).min(75);
        let x = w.saturating_sub(column) / 2;
        let (palette_open, screen, modal_open) = {
            let state = self.state.borrow();
            (state.palette_open, state.screen, state.modal_open)
        };
        if palette_open {
            let rect = palette_rect(w, h);
            self.prompt_box
                .position(Edge::Left, Length::Cells((rect.x + 2) as f32))
                .position(Edge::Top, Length::Cells(rect.y as f32))
                .width(Length::Cells((rect.width.saturating_sub(10)) as f32))
                .height(Length::Cells(1.0));
            self.prompt_row
                .height(Length::Cells(1.0))
                .padding_edge(Edge::Top, 0)
                .bg(self.tokens.dialog);
            self.prompt_rail
                .padding_edge(Edge::Left, 0)
                .border_sides(Sides::NONE)
                .bg(self.tokens.dialog);
            self.prompt_cap.visible(false);
            self.prompt
                .placeholder("Search commands")
                .colors(self.tokens.text, self.tokens.dialog)
                .focused_colors(self.tokens.text, self.tokens.dialog);
        } else {
            let (prompt_y, prompt_width) = match screen {
                Screen::Dashboard => {
                    let home = self.home_model();
                    let layout = home_layout(w, h, &home);
                    (layout.prompt.y, layout.prompt.width)
                }
                _ => (footer_top.saturating_sub(prompt_height), column),
            };
            self.prompt_box
                .position(Edge::Left, Length::Cells(x as f32))
                .position(Edge::Top, Length::Cells(prompt_y as f32))
                .width(Length::Cells(prompt_width as f32))
                .height(Length::Cells(3.0));
            self.prompt_row
                .height(Length::Cells(2.0))
                .padding_edge(Edge::Top, 1)
                .bg(self.tokens.panel);
            self.prompt_rail
                .padding_edge(Edge::Left, 2)
                .border_sides(Sides::LEFT)
                .border_color(self.tokens.rail)
                .bg(self.tokens.panel);
            self.prompt_cap.visible(true);
            self.prompt
                .placeholder("Search the vault, or type / for commands")
                .colors(self.tokens.text, self.tokens.panel)
                .focused_colors(self.tokens.text, self.tokens.panel);
        }
        self.prompt_box
            .visible(palette_open || (!modal_open && screen != Screen::Help));
        self.location.visible(!modal_open);
        self.hints.visible(!modal_open);

        let notes_height = if height < 20 { 2.0 } else { 4.0 };
        self.rows[5].view.height(Length::Cells(notes_height));
        if let Some(textarea) = &self.rows[5].textarea {
            textarea.height(Length::Cells((notes_height - 1.0).max(1.0)));
        }

        let (form_open, auth_open, confirm_open, picker_open) = {
            let state = self.state.borrow();
            (
                state.form.is_some(),
                state.auth.is_some(),
                state.confirm.is_some(),
                state.picker.is_some(),
            )
        };
        let form_like = (form_open || auth_open) && !confirm_open && !picker_open;
        let fields_height = if form_open {
            let keys = self.visible_keys();
            let rows = keys
                .iter()
                .map(|key| {
                    if *key == RowKey::Notes {
                        notes_height as u32
                    } else {
                        2
                    }
                })
                .sum::<u32>();
            (rows + keys.len().saturating_sub(1) as u32).max(1)
        } else if auth_open {
            2
        } else {
            0
        };
        let available = h.saturating_sub(2);
        let chrome = 10;
        let viewport = fields_height.min(available.saturating_sub(chrome)).max(1);
        self.form_scroll
            .height(Length::Cells(viewport as f32))
            .visible(form_like);
        self.modal
            .width(Length::Cells((w.saturating_sub(2)).min(60) as f32))
            .max_height(Length::Cells(available as f32))
            .margin_edge(
                Edge::Top,
                if form_like {
                    (h / 4).min(h.saturating_sub(viewport + chrome))
                } else {
                    h / 4
                },
            );
        self.location.width(Length::Cells((w / 2).min(28) as f32));
    }

    fn resize(&self, width: u16, height: u16) {
        self.state.borrow_mut().size = (width, height);
        self.apply_layout();
        self.refresh();
    }

    fn wire(&self) {
        let ui = self.clone();
        self.prompt
            .on_change(move |_cx, value| ui.set_query(value.to_string()));
        let ui = self.clone();
        self.prompt.on_submit(move |cx, _| ui.submit(cx));
        let ui = self.clone();
        self.app
            .on_key_capture(move |cx, key| ui.modal_key(cx, key));
        let ui = self.clone();
        self.app.on_key(move |cx, key| ui.key(cx, key));
        let ui = self.clone();
        self.app
            .on_resize(move |_cx, width, height| ui.resize(width, height));
        let ui = self.clone();
        self.app.set_interval(Duration::from_secs(5), move |_cx| {
            ui.reload_if_changed();
        });
        let ui = self.clone();
        self.app
            .on_message(move |_cx, message: &SyncFinished| ui.finish_sync(message.0.clone()));
        let ui = self.clone();
        self.app
            .on_message(move |_cx, message: &AuthEvent| ui.auth_event(message));
        let ui = self.clone();
        self.scrim.on_click(move |_cx, _event| ui.dismiss_dialog());
        let ui = self.clone();
        self.modal_band
            .on_click(move |_cx, _event| ui.review_form());
        let ui = self.clone();
        self.app.on_mouse(move |cx, event| {
            if !ui.state.borrow().modal_open {
                return;
            }
            let rect = ui.modal.rect();
            let x = f64::from(event.x);
            let y = f64::from(event.y);
            let inside = x >= rect.screen_x
                && x < rect.screen_x + f64::from(rect.width)
                && y >= rect.screen_y
                && y < rect.screen_y + f64::from(rect.height);
            if !inside {
                cx.prevent_default();
            }
        });
        self.focus(FocusTarget::Composer);
    }

    fn current_focus(&self) -> FocusTarget {
        self.state.borrow().focus
    }

    fn refresh(&self) {
        let modal_open = self.state.borrow().modal_open;
        self.overlay.visible(modal_open);
        self.apply_layout();
        self.refresh_page();
        self.refresh_footer();
    }

    fn visible_keys(&self) -> Vec<RowKey> {
        self.state
            .borrow()
            .form
            .as_ref()
            .map_or_else(Vec::new, |form| form.kind.rows().to_vec())
    }

    fn field_value(&self, key: RowKey) -> String {
        if key == RowKey::Password {
            return self.secret_value.value();
        }
        let row = &self.rows[key.index()];
        if let Some(textarea) = &row.textarea {
            textarea.text()
        } else {
            row.input.as_ref().map(Input::value).unwrap_or_default()
        }
    }

    fn set_field(&self, key: RowKey, value: &str) {
        if key == RowKey::Password {
            self.secret_value.set(value);
        } else if let Some(textarea) = &self.rows[key.index()].textarea {
            textarea.set_text(value);
        } else if let Some(input) = &self.rows[key.index()].input {
            input.set_value(value);
        }
    }

    fn open_form(&self, kind: FormKind) {
        let source = if kind.is_add() || kind.is_standalone() {
            None
        } else {
            self.selected_entry()
        };
        let original = source
            .as_ref()
            .map_or_else(OriginalValues::default, |entry| OriginalValues {
                url: entry.url.clone().unwrap_or_default(),
                username: entry.username.clone().unwrap_or_default(),
                title: entry.title.clone().unwrap_or_default(),
                notes: entry.notes.clone().unwrap_or_default(),
                totp: entry
                    .totp
                    .as_ref()
                    .map(|totp| totp.secret.clone())
                    .unwrap_or_default(),
            });
        let editing = source.as_ref().map(|entry| entry.id.clone());
        let keys = kind.rows();
        for (index, row) in self.rows.iter().enumerate() {
            let key = keys.iter().find(|key| key.index() == index).copied();
            row.view.visible(key.is_some());
            if let Some(key) = key {
                row.label.set_text(kind.label(key));
                let value = match key {
                    RowKey::Site if kind == FormKind::AddNote || kind == FormKind::EditNote => {
                        original.title.clone()
                    }
                    RowKey::Site => original.url.clone(),
                    RowKey::Username => original.username.clone(),
                    RowKey::Title => original.title.clone(),
                    RowKey::Notes => original.notes.clone(),
                    RowKey::Password | RowKey::Totp => String::new(),
                };
                self.set_field(key, &value);
                if let Some(textarea) = &row.textarea {
                    textarea.placeholder(match kind {
                        FormKind::AddNote | FormKind::EditNote => "note body",
                        _ => "optional notes",
                    });
                }
                if let Some(input) = &row.input {
                    input.placeholder(match key {
                        RowKey::Site if kind == FormKind::AddWifi => "network name",
                        RowKey::Site => "example.com",
                        RowKey::Username => "you@example.com",
                        RowKey::Title => "optional name",
                        RowKey::Totp => "otpauth URI or secret",
                        RowKey::Notes
                            if kind == FormKind::AddNote || kind == FormKind::EditNote =>
                        {
                            "note body"
                        }
                        RowKey::Notes => "optional notes",
                        RowKey::Password => "",
                    });
                }
            }
        }
        self.modal_title.set_text(kind.title());
        self.modal_body.visible(false);
        self.modal_band.visible(true);
        self.modal_error.visible(false);
        self.modal_help
            .set_text("enter next   ctrl+s review   esc cancel");
        self.modal_band.visible(true);
        self.overlay.visible(true);
        let focus_target = self.current_focus();
        {
            let mut state = self.state.borrow_mut();
            state.modal_open = true;
            state.modal_focus = focus_target;
            state.confirm = None;
            state.form = Some(FormState {
                kind,
                editing,
                focus: 0,
                error: None,
                review: None,
                prepared: None,
                original,
            });
        }
        self.apply_layout();
        self.focus_form(0);
        self.form_scroll.scroll_to(0.0, 0.0);
    }

    fn focus_form(&self, focus: usize) {
        let keys = self.visible_keys();
        if keys.is_empty() {
            return;
        }
        let focus = focus.min(keys.len() - 1);
        for (index, key) in keys.iter().enumerate() {
            let row = &self.rows[key.index()];
            row.label.fg(if index == focus {
                self.tokens.info
            } else {
                self.tokens.muted
            });
            if index == focus {
                if row.secret {
                    self.secret.focus();
                } else if let Some(textarea) = &row.textarea {
                    textarea.focus();
                } else if let Some(input) = &row.input {
                    input.focus();
                    input.perform(EditorAction::SelectAll);
                }
                self.form_scroll.scroll_into_view(&row.view);
            }
        }
        if let Some(form) = self.state.borrow_mut().form.as_mut() {
            form.focus = focus;
        }
    }

    fn form_dirty(&self) -> bool {
        let state = self.state.borrow();
        let Some(form) = state.form.as_ref() else {
            return false;
        };
        let password = self.secret_value.value();
        if form.kind.is_standalone() {
            return !self.field_value(RowKey::Site).trim().is_empty();
        }
        if form.kind.is_add() {
            return !password.is_empty()
                || self.visible_keys().iter().any(|key| {
                    *key != RowKey::Password && !self.field_value(*key).trim().is_empty()
                });
        }
        let keys = form.kind.rows();
        let mut dirty = false;
        if keys.contains(&RowKey::Title) {
            dirty |= self.field_value(RowKey::Title) != form.original.title;
        }
        if keys.contains(&RowKey::Notes) {
            dirty |= self.field_value(RowKey::Notes) != form.original.notes;
        }
        if keys.contains(&RowKey::Password) {
            dirty |= !password.is_empty();
        }
        if keys.contains(&RowKey::Totp) {
            dirty |= !self.field_value(RowKey::Totp).trim().is_empty();
        }
        dirty
    }

    fn modal_key(&self, cx: &mut Cx<'_>, key: &KeyEvent) {
        if self.palette_nav(key) {
            cx.stop_propagation();
            return;
        }
        if !self.state.borrow().modal_open {
            return;
        }
        if key.matches("ctrl+c") {
            cx.quit();
            cx.stop_propagation();
            return;
        }
        let picker_open = self.state.borrow().picker.is_some();
        if picker_open {
            if key.matches("escape") {
                self.close_modal();
            } else if key.matches("down") {
                self.picker_move(1);
            } else if key.matches("up") {
                self.picker_move(-1);
            } else if key.matches("enter") {
                self.picker_choose();
            }
            cx.stop_propagation();
            return;
        }
        let auth_open = self.state.borrow().auth.is_some();
        if auth_open {
            if key.matches("escape") {
                let join_confirm = self
                    .state
                    .borrow()
                    .auth
                    .as_ref()
                    .is_some_and(|auth| auth.step == AuthStep::JoinConfirm);
                self.close_modal();
                if join_confirm {
                    self.start_sync(false);
                }
                cx.stop_propagation();
            } else if key.matches("enter") {
                let busy = self
                    .state
                    .borrow()
                    .auth
                    .as_ref()
                    .is_some_and(|auth| auth.busy);
                if !busy {
                    self.auth_submit();
                }
                cx.stop_propagation();
            } else if key.matches("tab") || key.matches("backtab") {
                cx.stop_propagation();
            }
            // Every other key belongs to the focused field. Do not swallow it.
            return;
        }
        let confirm_open = self.state.borrow().confirm.is_some();
        if confirm_open {
            let discard = self
                .state
                .borrow()
                .confirm
                .as_ref()
                .is_some_and(|confirm| matches!(confirm.action, PendingAction::DiscardForm));
            if key.matches("escape") {
                if discard {
                    self.back_to_form();
                } else {
                    self.close_modal();
                }
            } else if key.matches("right") || key.matches("y") {
                let armed = {
                    let mut state = self.state.borrow_mut();
                    let Some(confirm) = state.confirm.as_mut() else {
                        return;
                    };
                    confirm.armed = true;
                    true
                };
                self.refresh_confirm(armed);
            } else if key.matches("left") || key.matches("n") {
                let armed = {
                    let mut state = self.state.borrow_mut();
                    let Some(confirm) = state.confirm.as_mut() else {
                        return;
                    };
                    confirm.armed = false;
                    false
                };
                self.refresh_confirm(armed);
            } else if key.matches("enter") {
                let action = {
                    let state = self.state.borrow();
                    state.confirm.as_ref().map(|confirm| confirm.action.clone())
                };
                let armed = self
                    .state
                    .borrow()
                    .confirm
                    .as_ref()
                    .is_some_and(|confirm| confirm.armed);
                if armed {
                    if let Some(action) = action {
                        self.execute_action(action);
                    }
                } else if discard {
                    self.back_to_form();
                } else {
                    self.close_modal();
                }
            }
            cx.stop_propagation();
            return;
        }

        let reviewing = self
            .state
            .borrow()
            .form
            .as_ref()
            .is_some_and(|form| form.review.is_some());
        if reviewing {
            if key.matches("escape") {
                self.back_to_form();
                cx.stop_propagation();
            } else if key.matches("enter") {
                self.commit_prepared();
                cx.stop_propagation();
            }
            return;
        }

        if key.matches("escape") {
            if self.form_dirty() {
                self.show_confirm(
                    "DISCARD CHANGES?",
                    "The values you entered will be lost.",
                    PendingAction::DiscardForm,
                );
            } else {
                self.close_modal();
            }
            cx.stop_propagation();
            return;
        }
        if key.matches("tab") || key.matches("backtab") {
            let (focus, count) = {
                let state = self.state.borrow();
                (
                    state.form.as_ref().map_or(0, |form| form.focus),
                    self.visible_keys().len(),
                )
            };
            let next = if key.matches("tab") {
                (focus + 1) % count.max(1)
            } else {
                (focus + count.saturating_sub(1)) % count.max(1)
            };
            self.focus_form(next);
            cx.stop_propagation();
            return;
        }
        if key.matches("ctrl+g") {
            let keys = self.visible_keys();
            if keys.contains(&RowKey::Password) {
                self.secret_value
                    .set(&crate::commands::write::generate_password());
                self.modal_help
                    .set_text("generated password   enter next   ctrl+s review   esc cancel");
                cx.stop_propagation();
            }
            return;
        }
        if key.matches("ctrl+s") {
            self.review_form();
            cx.stop_propagation();
            return;
        }
        if key.matches("enter") {
            let (focus, count, notes_focused) = {
                let state = self.state.borrow();
                let (focus, notes) = state.form.as_ref().map_or((0, false), |form| {
                    (
                        form.focus,
                        form.kind.rows().get(form.focus) == Some(&RowKey::Notes),
                    )
                });
                (focus, self.visible_keys().len(), notes)
            };
            if notes_focused {
                // The textarea keeps Return for a new line.
                return;
            }
            if focus + 1 < count {
                self.focus_form(focus + 1);
            } else {
                self.review_form();
            }
            cx.stop_propagation();
        }
    }

    fn back_to_form(&self) {
        if let Some(form) = self.state.borrow_mut().form.as_mut() {
            form.review = None;
            form.prepared = None;
            form.error = None;
        }
        self.modal_body.visible(false);
        self.modal_band.visible(true);
        self.modal_error.visible(false);
        self.modal_help
            .set_text("enter next   ctrl+s review   esc cancel");
        for key in self.visible_keys() {
            self.rows[key.index()].view.visible(true);
        }
        let focus = self
            .state
            .borrow()
            .form
            .as_ref()
            .map_or(0, |form| form.focus);
        self.focus_form(focus);
    }

    fn review_form(&self) {
        let Some(kind) = self.state.borrow().form.as_ref().map(|form| form.kind) else {
            return;
        };
        let password = self.field_value(RowKey::Password);
        let result = if kind == FormKind::PasskeyImport {
            self.prepare_passkey_import()
        } else if kind == FormKind::PasskeyExport {
            self.prepare_passkey_export()
        } else if kind.is_add() {
            self.prepare_add(kind, &password)
        } else {
            self.prepare_edit_values(kind, &password)
        };
        match result {
            Ok((prepared, lines)) => {
                for row in &self.rows {
                    row.view.visible(false);
                }
                self.modal_body.set_text(lines.join("\n"));
                self.modal_body.visible(true);
                self.modal_band.visible(false);
                self.modal_error.visible(false);
                self.modal_help.set_text("enter save   esc back");
                if let Some(form) = self.state.borrow_mut().form.as_mut() {
                    form.review = Some(lines);
                    form.prepared = Some(prepared);
                    form.error = None;
                }
            }
            Err(error) => {
                self.modal_error.set_text(error);
                self.modal_error.visible(true);
            }
        }
    }

    fn prepare_passkey_import(&self) -> std::result::Result<(PreparedForm, Vec<String>), String> {
        let path = std::path::PathBuf::from(self.field_value(RowKey::Site).trim());
        if path.as_os_str().is_empty() {
            return Err("A credential export file is required.".into());
        }
        let paths = self.state.borrow().view.paths.clone();
        let mut config = self.state.borrow().view.config.clone();
        let report = crate::commands::passkey::import_file(&paths, &mut config, &path, true)
            .map_err(|error| error.message().to_string())?;
        let mut lines = vec![
            "Import passkeys".to_string(),
            format!("File     {}", path.display()),
            format!("New      {}", report.imported.len()),
            format!("Skipped  {}", report.skipped.len()),
        ];
        for row in report.skipped.iter().take(4) {
            lines.push(format!("  {} {}", row.rp_id, row.reason));
        }
        Ok((PreparedForm::PasskeyImport(path), lines))
    }

    fn prepare_passkey_export(&self) -> std::result::Result<(PreparedForm, Vec<String>), String> {
        let path = std::path::PathBuf::from(self.field_value(RowKey::Site).trim());
        if path.as_os_str().is_empty() {
            return Err("A destination file is required.".into());
        }
        let mut lines = vec![
            "Export passkeys".to_string(),
            format!("File     {}", path.display()),
        ];
        if path.exists() {
            lines.push("This file exists and will be overwritten.".into());
        }
        Ok((PreparedForm::PasskeyExport(path), lines))
    }

    fn prepare_add(
        &self,
        kind: FormKind,
        password: &str,
    ) -> std::result::Result<(PreparedForm, Vec<String>), String> {
        match kind {
            FormKind::AddLogin => {
                if password.is_empty() {
                    return Err("A password is required.".into());
                }
                let totp = self.field_value(RowKey::Totp);
                let spec = if totp.trim().is_empty() {
                    None
                } else {
                    Some(
                        crate::totp::parse_spec(&totp)
                            .map_err(|error| error.message().to_string())?,
                    )
                };
                let title = self.field_value(RowKey::Title);
                let notes = self.field_value(RowKey::Notes);
                let add = crate::commands::write::prepare_login(
                    &self.field_value(RowKey::Site),
                    &self.field_value(RowKey::Username),
                    (!title.trim().is_empty()).then_some(title.trim()),
                    (!notes.trim().is_empty()).then_some(notes.trim()),
                    spec.as_ref(),
                    password,
                )
                .map_err(|error| error.message().to_string())?;
                let lines = vec![
                    "Create a login".to_string(),
                    format!("Name      {}", add.entry.display_name()),
                    format!("Site      {}", self.field_value(RowKey::Site)),
                    format!("Username  {}", self.field_value(RowKey::Username)),
                    format!("Password  {} characters", password.chars().count()),
                    if spec.is_some() {
                        "One-time code  set".to_string()
                    } else {
                        "One-time code  none".to_string()
                    },
                ];
                Ok((PreparedForm::Add(Box::new(add)), lines))
            }
            FormKind::AddWifi => {
                if password.is_empty() {
                    return Err("A password is required.".into());
                }
                let add =
                    crate::commands::write::prepare_wifi(&self.field_value(RowKey::Site), password)
                        .map_err(|error| error.message().to_string())?;
                let lines = vec![
                    "Create a Wi-Fi network".to_string(),
                    format!("Network   {}", add.entry.display_name()),
                    format!("Password  {} characters", password.chars().count()),
                ];
                Ok((PreparedForm::Add(Box::new(add)), lines))
            }
            FormKind::AddNote => {
                let add = crate::commands::write::prepare_note(
                    &self.field_value(RowKey::Title),
                    &self.field_value(RowKey::Notes),
                )
                .map_err(|error| error.message().to_string())?;
                let lines = vec![
                    "Create a note".to_string(),
                    format!("Title  {}", add.entry.display_name()),
                    format!(
                        "Body   {} characters",
                        self.field_value(RowKey::Notes).chars().count()
                    ),
                ];
                Ok((PreparedForm::Add(Box::new(add)), lines))
            }
            _ => Err("This form cannot create an item.".into()),
        }
    }

    fn prepare_edit_values(
        &self,
        kind: FormKind,
        password: &str,
    ) -> std::result::Result<(PreparedForm, Vec<String>), String> {
        let (entry_id, original, totp_input, title, notes) = {
            let state = self.state.borrow();
            let form = state
                .form
                .as_ref()
                .ok_or_else(|| "No edit is open.".to_string())?;
            let entry_id = form
                .editing
                .clone()
                .ok_or_else(|| "No item is selected.".to_string())?;
            (
                entry_id,
                (
                    form.original.title.clone(),
                    form.original.notes.clone(),
                    form.original.totp.clone(),
                ),
                self.field_value(RowKey::Totp),
                self.field_value(RowKey::Title),
                self.field_value(RowKey::Notes),
            )
        };
        let mut request = crate::commands::write::EditRequest::default();
        let keys = kind.rows();
        let mut lines = vec![kind.title().to_lowercase()];
        if keys.contains(&RowKey::Title) && title != original.0 {
            request.title = Some((!title.trim().is_empty()).then_some(title.clone()));
            lines.push(format!("Title  {title}"));
        }
        if keys.contains(&RowKey::Notes) && notes != original.1 {
            request.notes = Some((!notes.is_empty()).then_some(notes.clone()));
            lines.push(format!("Body   {} characters", notes.chars().count()));
        }
        if keys.contains(&RowKey::Password) && !password.is_empty() {
            request.password = Some(password.to_string());
            lines.push(format!("Password  {} characters", password.chars().count()));
        }
        if keys.contains(&RowKey::Totp) && !totp_input.trim().is_empty() {
            let spec = crate::totp::parse_spec(&totp_input)
                .map_err(|error| error.message().to_string())?;
            request.totp = Some(Some(spec));
            lines.push("One-time code  set".to_string());
        }
        if lines.len() == 1 {
            return Err("Nothing changed.".into());
        }
        let paths = self.state.borrow().view.paths.clone();
        let mut config = self.state.borrow().view.config.clone();
        let prepared = crate::commands::write::prepare_edit(
            &paths,
            &mut config,
            None,
            Some(&entry_id),
            &request,
        )
        .map_err(|error| error.message().to_string())?
        .ok_or_else(|| "Nothing changed.".to_string())?;
        Ok((PreparedForm::Edit(Box::new(prepared)), lines))
    }

    fn commit_prepared(&self) {
        let prepared = self
            .state
            .borrow_mut()
            .form
            .as_mut()
            .and_then(|form| form.prepared.take());
        let Some(prepared) = prepared else {
            return;
        };
        let paths = self.state.borrow().view.paths.clone();
        let mut config = self.state.borrow().view.config.clone();
        let _lock = crate::config::lock_snapshot(&paths);
        let result = match prepared {
            PreparedForm::Add(add) => crate::commands::write::commit_add(&paths, &mut config, *add)
                .map(|added| format!("added {}", added.name)),
            PreparedForm::Edit(edit) => {
                crate::commands::write::commit_edit(&paths, &mut config, *edit)
                    .map(|edited| format!("edited {}", edited.name))
            }
            PreparedForm::PasskeyImport(path) => {
                crate::commands::passkey::import_file(&paths, &mut config, &path, false).map(
                    |report| {
                        format!(
                            "imported {} passkeys ({} skipped)",
                            report.imported.len(),
                            report.skipped.len()
                        )
                    },
                )
            }
            PreparedForm::PasskeyExport(path) => {
                crate::commands::passkey::export_file(&paths, &mut config, &path, true).map(
                    |report| {
                        format!(
                            "exported {} passkeys to {}",
                            report.exported,
                            report.file.display()
                        )
                    },
                )
            }
        };
        match result {
            Ok(message) => {
                self.close_modal();
                let reload = self.state.borrow_mut().view.reload();
                self.refresh();
                match reload {
                    Ok(()) => self.set_notice(Some(message), false),
                    Err(error) => self.set_notice(
                        Some(format!("saved, but reload failed: {}", error.message())),
                        true,
                    ),
                }
            }
            Err(error) => {
                for key in self.visible_keys() {
                    self.rows[key.index()].view.visible(true);
                }
                self.modal_body.visible(false);
                self.modal_error.set_text(error.message());
                self.modal_error.visible(true);
                self.modal_help
                    .set_text("enter next   ctrl+s review   esc cancel");
                let focus = {
                    let mut state = self.state.borrow_mut();
                    state.form.as_mut().map(|form| {
                        form.review = None;
                        form.focus
                    })
                };
                if let Some(focus) = focus {
                    self.focus_form(focus);
                }
            }
        }
    }

    fn dismiss_dialog(&self) {
        let (modal_open, confirm, reviewing) = {
            let state = self.state.borrow();
            (
                state.modal_open,
                state
                    .confirm
                    .as_ref()
                    .map(|confirm| matches!(confirm.action, PendingAction::DiscardForm)),
                state
                    .form
                    .as_ref()
                    .is_some_and(|form| form.review.is_some()),
            )
        };
        if !modal_open {
            return;
        }
        if let Some(discard) = confirm {
            if discard {
                self.back_to_form();
            } else {
                self.close_modal();
            }
            return;
        }
        if reviewing {
            self.back_to_form();
            return;
        }
        if self.form_dirty() {
            self.show_confirm(
                "DISCARD CHANGES?",
                "The values you entered will be lost.",
                PendingAction::DiscardForm,
            );
        } else {
            self.close_modal();
        }
    }

    fn close_modal(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.modal_open = false;
            state.form = None;
            state.picker = None;
            state.confirm = None;
            state.auth = None;
        }
        self.overlay.visible(false);
        self.modal_body.visible(false);
        self.modal_band.visible(false);
        self.modal_error.visible(false);
        for row in &self.rows {
            row.view.visible(false);
        }
        let (screen, compact, detail_open) = {
            let state = self.state.borrow();
            (state.screen, state.size.0 < 60, state.detail_open)
        };
        let target = match self.state.borrow().modal_focus {
            FocusTarget::Detail if screen != Screen::Browser => FocusTarget::Composer,
            FocusTarget::List if screen != Screen::Browser => FocusTarget::Composer,
            FocusTarget::List if compact && detail_open => FocusTarget::Detail,
            other => other,
        };
        self.focus(target);
        self.apply_layout();
    }

    fn show_confirm(&self, title: &str, body: &str, action: PendingAction) {
        let discard = matches!(action, PendingAction::DiscardForm);
        let focus_target = self.current_focus();
        {
            let mut state = self.state.borrow_mut();
            state.modal_open = true;
            if state.form.is_none() && state.auth.is_none() {
                state.modal_focus = focus_target;
            }
            state.confirm = Some(ConfirmState {
                action,
                armed: false,
            });
        }
        self.modal_title.set_text(title);
        self.modal_body.set_text(body);
        self.modal_body.visible(true);
        self.modal_band.visible(false);
        self.modal_error.visible(false);
        self.modal_help.set_text(if discard {
            "enter keep editing   right discard   esc keep"
        } else {
            "enter cancel   right choose   esc cancel"
        });
        for row in &self.rows {
            row.view.visible(false);
        }
        self.overlay.visible(true);
        self.apply_layout();
    }

    fn refresh_confirm(&self, armed: bool) {
        let discard = self
            .state
            .borrow()
            .confirm
            .as_ref()
            .is_some_and(|confirm| matches!(confirm.action, PendingAction::DiscardForm));
        self.modal_help.set_text(match (discard, armed) {
            (true, true) => "enter discard   left keep   esc keep",
            (true, false) => "enter keep editing   right discard   esc keep",
            (false, true) => "enter confirm   left back   esc cancel",
            (false, false) => "enter cancel   right choose   esc cancel",
        });
    }

    fn execute_action(&self, action: PendingAction) {
        let paths = self.state.borrow().view.paths.clone();
        let mut config = self.state.borrow().view.config.clone();
        let _lock = crate::config::lock_snapshot(&paths);
        let result: std::result::Result<String, String> = match action {
            PendingAction::DiscardForm => {
                self.close_modal();
                return;
            }
            PendingAction::Trash { id, name } => {
                let outcome =
                    crate::commands::write::prepare_rm(&paths, &mut config, None, Some(&id))
                        .and_then(|remove| {
                            crate::commands::write::commit_rm(&paths, &mut config, remove)
                        });
                match outcome {
                    Ok(removed) => {
                        self.state.borrow_mut().last_trash =
                            Some((removed.id.clone(), removed.name.clone()));
                        Ok(format!("moved {} to Recently Deleted. u undo", name))
                    }
                    Err(error) => Err(error.message().to_string()),
                }
            }
            PendingAction::Restore { id, name } => {
                crate::commands::write::restore_data(&paths, &mut config, None, Some(&id))
                    .map(|_| format!("restored {name}"))
                    .map_err(|error| error.message().to_string())
            }
            PendingAction::Resolve { id, local, label } => {
                crate::commands::write::resolve_pending(&paths, &mut config, &id, local)
                    .map(|_| {
                        if local {
                            format!("kept the local change to {label}")
                        } else {
                            format!("took the remote version of {label}")
                        }
                    })
                    .map_err(|error| error.message().to_string())
            }
            PendingAction::GroupRemove { zone, record, name } => {
                crate::commands::group::remove_item(&paths, &mut config, &zone, &record)
                    .map(|_| format!("removed {name} from the group"))
                    .map_err(|error| error.message().to_string())
            }
        };
        self.close_modal();
        let reload = self.state.borrow_mut().view.reload();
        self.refresh();
        match (result, reload) {
            (Ok(message), Ok(())) => self.set_notice(Some(message), false),
            (Ok(message), Err(error)) => self.set_notice(
                Some(format!("{message}; reload failed: {}", error.message())),
                true,
            ),
            (Err(error), _) => self.set_notice(Some(error), true),
        }
    }

    fn start_refresh(&self) {
        let (paths, config, session, account) = {
            let state = self.state.borrow();
            let Some(session) = state.view.vault.session.clone() else {
                drop(state);
                self.set_notice(Some("sign in before refreshing services".into()), true);
                return;
            };
            (
                state.view.paths.clone(),
                state.view.config.clone(),
                session,
                state.view.vault.account.clone().unwrap_or_default(),
            )
        };
        let proxy = self.app.proxy();
        std::thread::spawn(move || {
            let result = crate::auth::refresh_services(&config, &paths, &session)
                .map(|session| (account, session))
                .map_err(|error| error.message().to_string());
            let _ = proxy.send(AuthEvent::Refreshed(result));
        });
    }

    fn open_auth(&self, join_only: bool) {
        let (anisette, account, has_session, peer, failures) = {
            let state = self.state.borrow();
            (
                state.view.config.anisette_url().unwrap_or_default(),
                state
                    .view
                    .config
                    .account
                    .clone()
                    .or_else(|| state.view.vault.account.clone())
                    .unwrap_or_default(),
                state.view.vault.session.is_some(),
                state.view.vault.peer.is_some(),
                state.view.state.failures,
            )
        };
        if join_only && !has_session {
            self.set_notice(Some("sign in before joining the trust".into()), true);
            return;
        }
        let step = if join_only {
            AuthStep::Escrow
        } else {
            AuthStep::Anisette
        };
        let focus_target = self.current_focus();
        {
            let mut state = self.state.borrow_mut();
            state.modal_open = true;
            state.modal_focus = focus_target;
            state.auth_attempt = state.auth_attempt.wrapping_add(1);
            state.form = None;
            state.confirm = None;
            state.auth = Some(AuthState {
                step,
                anisette,
                account,
                password: String::new(),
                code: String::new(),
                escrow: String::new(),
                flow: None,
                busy: false,
                error: None,
                join_only,
            });
        }
        self.modal_title.set_text("APPLE SIGN IN");
        self.overlay.visible(true);
        let _ = (peer, failures);
        self.render_auth();
    }

    fn render_auth(&self) {
        for row in &self.rows {
            row.view.visible(false);
        }
        self.apply_layout();
        self.modal_body.visible(false);
        self.modal_error.visible(false);
        let (step, busy, error, anisette, account, password, code, escrow, join_only) = {
            let state = self.state.borrow();
            let Some(auth) = state.auth.as_ref() else {
                return;
            };
            (
                auth.step,
                auth.busy,
                auth.error.clone(),
                auth.anisette.clone(),
                auth.account.clone(),
                auth.password.clone(),
                auth.code.clone(),
                auth.escrow.clone(),
                auth.join_only,
            )
        };
        if let Some(error) = error {
            self.modal_error.set_text(error);
            self.modal_error.visible(true);
        }
        if busy {
            self.modal_title.set_text("CONTACTING APPLE");
            self.modal_body
                .set_text("Signing in. This can take a few seconds.\n\nEsc cancels the display; the request may still finish.");
            self.modal_body.visible(true);
            self.modal_help.set_text("esc cancel");
            return;
        }
        self.modal_title.set_text("APPLE SIGN IN");
        let (key, label, value, secret) = match step {
            AuthStep::Anisette => (RowKey::Site, "Anisette URL (optional)", anisette, false),
            AuthStep::Account => (RowKey::Site, "Apple ID", account, false),
            AuthStep::Password => (RowKey::Password, "Password", password, true),
            AuthStep::TwoFactor => (RowKey::Site, "Two-factor code", code, false),
            AuthStep::Escrow => (RowKey::Password, "Escrow passcode", escrow, true),
            AuthStep::JoinConfirm => (RowKey::Site, "", String::new(), false),
        };
        if step == AuthStep::JoinConfirm {
            self.modal_title.set_text("JOIN THE TRUST?");
            self.modal_body.set_text(
                "Joining spends one of your escrow attempts. The keychain becomes readable once the trust is joined.",
            );
            self.modal_body.visible(true);
            self.modal_help.set_text("enter join   esc skip");
            return;
        }
        let row = &self.rows[key.index()];
        row.view.visible(true);
        row.label.set_text(label);
        if secret {
            self.secret_value.set(&value);
            self.secret.focus();
        } else if let Some(input) = &row.input {
            input.set_value(&value);
            // Select the prefilled account or URL so the first keystroke
            // replaces it instead of appending to it.
            input.perform(EditorAction::SelectAll);
            input.placeholder(match step {
                AuthStep::Anisette => "leave blank for native ADI",
                AuthStep::Account => "you@example.com",
                AuthStep::TwoFactor => "6-digit code",
                _ => "",
            });
            input.focus();
        }
        self.modal_help.set_text("enter continue   esc cancel");
        self.modal_body.set_text(match step {
            AuthStep::Escrow if !join_only => {
                "After sign-in, joining the trust spends one of your escrow attempts. Press Esc to skip."
            }
            AuthStep::Escrow => {
                "This spends one of your escrow attempts. Check the passcode before continuing."
            }
            _ => "",
        });
        self.modal_body.visible(matches!(step, AuthStep::Escrow));
    }

    fn auth_submit(&self) {
        let step = {
            let state = self.state.borrow();
            let Some(auth) = state.auth.as_ref() else {
                return;
            };
            auth.step
        };
        match step {
            AuthStep::Anisette => {
                let value = self.field_value(RowKey::Site).trim().to_string();
                let paths = {
                    let mut state = self.state.borrow_mut();
                    let Some(auth) = state.auth.as_mut() else {
                        return;
                    };
                    auth.anisette = value.clone();
                    state.view.paths.clone()
                };
                match crate::config::Config::update(&paths, |config| {
                    config.anisette_url = (!value.is_empty()).then(|| value.clone());
                }) {
                    Ok(config) => {
                        let mut state = self.state.borrow_mut();
                        state.view.config = config;
                        if let Some(auth) = state.auth.as_mut() {
                            auth.step = AuthStep::Account;
                        }
                        drop(state);
                        self.render_auth();
                    }
                    Err(error) => self.auth_error(&error.message().to_string()),
                }
            }
            AuthStep::Account => {
                let value = self.field_value(RowKey::Site).trim().to_string();
                if value.is_empty() {
                    self.auth_error("An Apple ID is required.");
                    return;
                }
                let paths = {
                    let mut state = self.state.borrow_mut();
                    let Some(auth) = state.auth.as_mut() else {
                        return;
                    };
                    auth.account = value.clone();
                    state.view.paths.clone()
                };
                match crate::config::Config::update(&paths, |config| {
                    config.account = Some(value);
                }) {
                    Ok(config) => {
                        let mut state = self.state.borrow_mut();
                        state.view.config = config;
                        if let Some(auth) = state.auth.as_mut() {
                            auth.step = AuthStep::Password;
                        }
                        drop(state);
                        self.render_auth();
                    }
                    Err(error) => self.auth_error(&error.message().to_string()),
                }
            }
            AuthStep::Password => {
                let password = self.secret_value.value();
                if password.is_empty() {
                    self.auth_error("A password is required.");
                    return;
                }
                let (account, config, paths) = {
                    let mut state = self.state.borrow_mut();
                    let Some(auth) = state.auth.as_mut() else {
                        return;
                    };
                    auth.password = password.clone();
                    auth.code.clear();
                    auth.busy = true;
                    auth.error = None;
                    (
                        auth.account.clone(),
                        state.view.config.clone(),
                        state.view.paths.clone(),
                    )
                };
                self.render_auth();
                let proxy = self.app.proxy();
                let attempt = self.state.borrow().auth_attempt;
                std::thread::spawn(move || {
                    let result = crate::auth::login_start(&config, &paths, &account, &password)
                        .map_err(|error| error.message().to_string());
                    let _ = proxy.send(AuthEvent::Started {
                        attempt,
                        account,
                        result,
                    });
                });
            }
            AuthStep::TwoFactor => {
                let code = self.field_value(RowKey::Site).trim().to_string();
                if code.is_empty() {
                    self.auth_error("Enter the code Apple sent.");
                    return;
                }
                let (flow, account) = {
                    let mut state = self.state.borrow_mut();
                    let Some(auth) = state.auth.as_mut() else {
                        return;
                    };
                    auth.code = code.clone();
                    auth.busy = true;
                    auth.error = None;
                    (auth.flow.clone(), auth.account.clone())
                };
                let Some(flow) = flow else {
                    self.auth_error("The sign-in session expired. Start again.");
                    return;
                };
                self.render_auth();
                let proxy = self.app.proxy();
                let attempt = self.state.borrow().auth_attempt;
                std::thread::spawn(move || {
                    let result = crate::auth::submit_two_factor(flow, &code)
                        .map_err(|error| error.message().to_string());
                    let _ = proxy.send(AuthEvent::Started {
                        attempt,
                        account,
                        result,
                    });
                });
            }
            AuthStep::Escrow => {
                let escrow = self.secret_value.value();
                if escrow.is_empty() {
                    self.auth_error("An escrow passcode is required to join.");
                    return;
                }
                {
                    let mut state = self.state.borrow_mut();
                    let Some(auth) = state.auth.as_mut() else {
                        return;
                    };
                    auth.escrow = escrow;
                    auth.step = AuthStep::JoinConfirm;
                    auth.error = None;
                }
                self.render_auth();
            }
            AuthStep::JoinConfirm => self.start_join(),
        }
    }

    fn auth_error(&self, message: &str) {
        if let Some(auth) = self.state.borrow_mut().auth.as_mut() {
            auth.busy = false;
            auth.error = Some(message.to_string());
        }
        self.render_auth();
    }

    fn auth_event(&self, event: &AuthEvent) {
        if let AuthEvent::Refreshed(result) = event {
            match result {
                Ok((account, session)) => match self.store_session(account, session) {
                    Ok(()) => {
                        self.refresh();
                        self.set_notice(Some("service URLs refreshed".into()), false);
                    }
                    Err(error) => self.set_notice(Some(error.message().to_string()), true),
                },
                Err(error) => self.set_notice(Some(error.clone()), true),
            }
            return;
        }
        let Some(attempt) = event.attempt() else {
            return;
        };
        if attempt != self.state.borrow().auth_attempt {
            return;
        }
        if self.state.borrow().auth.is_none() {
            // The dialog was closed while work was in flight. A finished join or
            // sign-in still changed the account, so report it instead of losing
            // the escrow attempt or session.
            match event {
                AuthEvent::Started {
                    account,
                    result: Ok(crate::auth::LoginStart::Done(session)),
                    ..
                } => match self.store_session(account, session) {
                    Ok(()) => {
                        self.refresh();
                        self.start_sync(false);
                        self.set_notice(Some(format!("signed in as {account}")), false);
                    }
                    Err(error) => {
                        self.set_notice(Some(error.message().to_string()), true);
                    }
                },
                AuthEvent::Joined {
                    result: Ok(peer), ..
                } => {
                    self.start_sync(false);
                    self.set_notice(Some(format!("joined the trust as {peer}")), false);
                }
                AuthEvent::Joined {
                    result: Err(error), ..
                } => {
                    self.set_notice(Some(error.clone()), true);
                }
                _ => {}
            }
            return;
        }
        match event {
            AuthEvent::Started {
                result: Err(error), ..
            } => self.auth_error(error),
            AuthEvent::Started {
                result: Ok(crate::auth::LoginStart::Done(session)),
                ..
            } => {
                let account = self
                    .state
                    .borrow()
                    .auth
                    .as_ref()
                    .map(|auth| auth.account.clone())
                    .unwrap_or_default();
                self.complete_login(account, (**session).clone());
            }
            AuthEvent::Started {
                result: Ok(crate::auth::LoginStart::NeedCode(flow)),
                ..
            } => {
                {
                    let mut state = self.state.borrow_mut();
                    let Some(auth) = state.auth.as_mut() else {
                        return;
                    };
                    auth.busy = false;
                    auth.flow = Some((**flow).clone());
                    auth.step = AuthStep::TwoFactor;
                    auth.error = None;
                }
                self.render_auth();
            }
            AuthEvent::Joined {
                result: Err(error), ..
            } => self.auth_error(error),
            AuthEvent::Joined {
                result: Ok(peer), ..
            } => {
                self.close_modal();
                self.start_sync(false);
                self.set_notice(Some(format!("joined the trust as {peer}")), false);
            }
            AuthEvent::Refreshed(_) => {}
        }
    }

    fn complete_login(&self, account: String, session: crate::model::Session) {
        if let Err(error) = self.store_session(&account, &session) {
            self.auth_error(&error.message().to_string());
            return;
        }
        let (needs_join, join_only) = {
            let state = self.state.borrow();
            let needs_join = state.view.vault.peer.is_none() && state.view.state.failures == 0;
            (
                needs_join,
                state.auth.as_ref().is_some_and(|auth| auth.join_only),
            )
        };
        if needs_join || join_only {
            {
                let mut state = self.state.borrow_mut();
                let Some(auth) = state.auth.as_mut() else {
                    return;
                };
                auth.busy = false;
                auth.step = AuthStep::Escrow;
                auth.error = None;
            }
            self.render_auth();
            return;
        }
        self.close_modal();
        self.start_sync(false);
        self.set_notice(Some(format!("signed in as {account}")), false);
    }

    fn store_session(
        &self,
        account: &str,
        session: &crate::model::Session,
    ) -> std::result::Result<(), Error> {
        let paths = self.state.borrow().view.paths.clone();
        let mut config = self.state.borrow().view.config.clone();
        let _lock = crate::config::lock_snapshot(&paths)?;
        let mut snapshot = if paths.snapshot_file.exists() {
            crate::vault::load(&paths, &mut config)?
        } else {
            crate::model::Vault::default()
        };
        let previous = snapshot.session.clone();
        let mut session = session.clone();
        if let Some(previous) = previous {
            if session.escrow_proxy_url.is_none() {
                session.escrow_proxy_url = previous.escrow_proxy_url;
            }
            if session.ckdatabasews_url.is_none() {
                session.ckdatabasews_url = previous.ckdatabasews_url;
            }
        }
        snapshot.account = Some(account.to_string());
        snapshot.session = Some(session);
        crate::vault::save(&paths, &mut config, &snapshot)?;
        let mut state = crate::config::load_state(&paths)?;
        state.account = Some(account.to_string());
        state.source = Some("icloud".into());
        state.entries = snapshot.login_count() as u32;
        state.passkeys = snapshot.passkey_count() as u32;
        state.groups = snapshot.groups.len() as u32;
        state.last_status = Some("logged-in".into());
        crate::config::save_state(&paths, &state)?;
        self.state.borrow_mut().view.reload()?;
        self.refresh();
        Ok(())
    }

    fn start_join(&self) {
        let (paths, config, escrow) = {
            let state = self.state.borrow();
            let Some(auth) = state.auth.as_ref() else {
                return;
            };
            (
                state.view.paths.clone(),
                state.view.config.clone(),
                auth.escrow.clone(),
            )
        };
        {
            let mut state = self.state.borrow_mut();
            if let Some(auth) = state.auth.as_mut() {
                auth.busy = true;
                auth.error = None;
            }
        }
        self.render_auth();
        let proxy = self.app.proxy();
        let attempt = self.state.borrow().auth_attempt;
        std::thread::spawn(move || {
            let mut config = config;
            let result = crate::commands::join::perform_with_passcode(&paths, &mut config, &escrow)
                .map(|joined| joined.peer)
                .map_err(|error| error.message().to_string());
            let _ = proxy.send(AuthEvent::Joined { attempt, result });
        });
    }

    fn start_edit(&self) {
        let Some(entry) = self.selected_entry() else {
            self.set_notice(Some("select an item to edit".into()), true);
            return;
        };
        if entry.group.is_some() {
            self.set_notice(Some("shared entries cannot be edited here".into()), true);
            return;
        }
        let kind = match entry.kind {
            crate::model::EntryKind::Login => FormKind::EditLogin,
            crate::model::EntryKind::Note => FormKind::EditNote,
            crate::model::EntryKind::Wifi => FormKind::EditWifi,
            _ => {
                self.set_notice(Some("this item cannot be edited here".into()), true);
                return;
            }
        };
        self.open_form(kind);
    }

    fn start_remove(&self) {
        let Some(entry) = self.selected_entry() else {
            self.set_notice(Some("select an item to delete".into()), true);
            return;
        };
        if entry.group.is_some() {
            self.set_notice(Some("shared entries cannot be deleted here".into()), true);
            return;
        }
        self.show_confirm(
            "MOVE TO RECENTLY DELETED?",
            &format!(
                "{}\n\nIt stays recoverable on every device for 30 days.",
                entry.display_name()
            ),
            PendingAction::Trash {
                id: entry.id.clone(),
                name: entry.display_name(),
            },
        );
    }

    fn start_group(&self) {
        let Some(entry) = self.selected_entry() else {
            self.set_notice(Some("select a login first".into()), true);
            return;
        };
        if let Some(group) = entry.group.clone() {
            self.show_confirm(
                "REMOVE FROM THE GROUP?",
                &format!(
                    "{} leaves its shared group. You can add it back later from this screen.",
                    entry.display_name()
                ),
                PendingAction::GroupRemove {
                    zone: format!("group-{group}"),
                    record: entry.id.clone(),
                    name: entry.display_name(),
                },
            );
            return;
        }
        let groups = self.state.borrow().view.vault.groups.clone();
        if groups.is_empty() {
            self.set_notice(
                Some("no groups yet; create one on an Apple device".into()),
                true,
            );
            return;
        }
        let items = groups
            .iter()
            .map(|group| PickerItem {
                label: group.name.clone().unwrap_or_else(|| group.id.clone()),
                detail: format!("group-{}", group.id),
                zone: format!("group-{}", group.id),
            })
            .collect::<Vec<_>>();
        let focus_target = self.current_focus();
        {
            let mut state = self.state.borrow_mut();
            state.modal_open = true;
            state.modal_focus = focus_target;
            state.form = None;
            state.confirm = None;
            state.auth = None;
            state.picker = Some(PickerState { items, selected: 0 });
        }
        self.overlay.visible(true);
        self.render_picker();
        self.apply_layout();
    }

    fn render_picker(&self) {
        for row in &self.rows {
            row.view.visible(false);
        }
        let (items, selected) = {
            let state = self.state.borrow();
            let Some(picker) = state.picker.as_ref() else {
                return;
            };
            (
                picker
                    .items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        format!(
                            "{} {}\n  {}",
                            if picker.selected == index { "▶" } else { " " },
                            item.label,
                            item.detail
                        )
                    })
                    .collect::<Vec<_>>(),
                picker.selected,
            )
        };
        let _ = selected;
        self.modal_body.set_text(items.join("\n"));
        self.modal_body.visible(true);
        self.modal_error.visible(false);
        self.modal_title.set_text("ADD TO GROUP");
        self.modal_help
            .set_text("up / down   enter add   esc cancel");
    }

    fn picker_move(&self, step: isize) {
        let count = self
            .state
            .borrow()
            .picker
            .as_ref()
            .map_or(0, |p| p.items.len());
        if count == 0 {
            return;
        }
        let current = self
            .state
            .borrow()
            .picker
            .as_ref()
            .map_or(0, |picker| picker.selected) as isize;
        let next = (current + step).rem_euclid(count as isize) as usize;
        if let Some(picker) = self.state.borrow_mut().picker.as_mut() {
            picker.selected = next;
        }
        self.render_picker();
    }

    fn picker_choose(&self) {
        let (zone, label, entry) = {
            let state = self.state.borrow();
            let Some(picker) = state.picker.as_ref() else {
                return;
            };
            let Some(item) = picker.items.get(picker.selected) else {
                return;
            };
            let entry = match &state.rows.get(state.selected).map(|row| &row.source) {
                Some(RowSource::Entry(entry)) => (**entry).clone(),
                _ => return,
            };
            (item.zone.clone(), item.label.clone(), entry)
        };
        let paths = self.state.borrow().view.paths.clone();
        let mut config = self.state.borrow().view.config.clone();
        let result = crate::commands::group::add_item(&paths, &mut config, &zone, &entry)
            .map(|_| format!("added {} to {label}", entry.display_name()))
            .map_err(|error| error.message().to_string());
        self.close_modal();
        let reload = self.state.borrow_mut().view.reload();
        self.refresh();
        match (result, reload) {
            (Ok(message), Ok(())) => self.set_notice(Some(message), false),
            (Ok(message), Err(error)) => self.set_notice(
                Some(format!("{message}; reload failed: {}", error.message())),
                true,
            ),
            (Err(error), _) => self.set_notice(Some(error), true),
        }
    }

    fn start_restore(&self) {
        let id = {
            let state = self.state.borrow();
            match &state.rows.get(state.selected).map(|row| &row.source) {
                Some(RowSource::Trash(trash)) => Some(trash.entry.id.clone()),
                _ => None,
            }
        };
        let Some(id) = id else {
            self.set_notice(Some("select a trashed item to restore".into()), true);
            return;
        };
        let name = self
            .state
            .borrow()
            .rows
            .get(self.state.borrow().selected)
            .map(|row| row.title.clone())
            .unwrap_or_default();
        self.execute_action(PendingAction::Restore { id, name });
    }

    fn start_resolve(&self, local: bool) {
        let pending = {
            let state = self.state.borrow();
            match &state.rows.get(state.selected).map(|row| &row.source) {
                Some(RowSource::Pending(op)) => Some((**op).clone()),
                _ => None,
            }
        };
        let Some(op) = pending else {
            self.set_notice(Some("select a pending change first".into()), true);
            return;
        };
        let title = if local {
            "KEEP THE LOCAL CHANGE?"
        } else {
            "TAKE THE REMOTE VERSION?"
        };
        let body = if local {
            format!(
                "{}\n\nThis op will be pushed on the next sync, overriding the server copy.",
                op.label
            )
        } else {
            format!(
                "{}\n\nThis pending change will be discarded and the server copy kept.",
                op.label
            )
        };
        self.show_confirm(
            title,
            &body,
            PendingAction::Resolve {
                id: op.id,
                local,
                label: op.label,
            },
        );
    }

    fn undo_trash(&self) {
        let last = self.state.borrow().last_trash.clone();
        let Some((id, name)) = last else {
            return;
        };
        let paths = self.state.borrow().view.paths.clone();
        let mut config = self.state.borrow().view.config.clone();
        let _lock = crate::config::lock_snapshot(&paths);
        match crate::commands::write::restore_data(&paths, &mut config, None, Some(&id)) {
            Ok(_) => {
                self.state.borrow_mut().last_trash = None;
                let reload = self.state.borrow_mut().view.reload();
                self.refresh();
                match reload {
                    Ok(()) => self.set_notice(Some(format!("restored {name}")), false),
                    Err(error) => self.set_notice(
                        Some(format!("restored, but reload failed: {}", error.message())),
                        true,
                    ),
                }
            }
            Err(error) => self.set_notice(Some(error.message().to_string()), true),
        }
    }

    fn home_model(&self) -> Home {
        let state = self.state.borrow();
        let dashboard = state.view.dashboard(Utc::now());
        let account = dashboard.account.as_deref().unwrap_or("not signed in");
        let phase = match dashboard.phase {
            DashboardPhase::NoSnapshot => "no vault yet",
            DashboardPhase::SignedOut => "signed out",
            DashboardPhase::Empty => "empty vault",
            DashboardPhase::Ready => "signed in",
        };
        let status = format!("{account} · {phase}");
        let counts = count_lines(&dashboard.counts, (state.size.0.saturating_sub(4)).max(20));
        let needle = state.query.to_lowercase();
        let recents = dashboard
            .recents
            .iter()
            .filter(|row| {
                needle.is_empty()
                    || row.title.to_lowercase().contains(&needle)
                    || row.subtitle.to_lowercase().contains(&needle)
            })
            .map(|row| {
                Line::item(row.title.clone(), row.subtitle.clone()).with_right(row.trailing.clone())
            })
            .collect::<Vec<_>>();
        let selected = if state.focus == FocusTarget::List && !recents.is_empty() {
            Some(state.recent_selected.min(recents.len() - 1))
        } else {
            None
        };
        Home {
            wordmark: wordmark_lines(state.size),
            status,
            counts: counts.lines().map(str::to_string).collect(),
            warnings: dashboard.warnings,
            recents,
            selected,
            empty: "No items yet · press / to add one".into(),
        }
    }

    fn browser_model(&self) -> Browser {
        let state = self.state.borrow();
        let items = state
            .rows
            .iter()
            .map(|row| {
                Line::item(row.title.clone(), row.subtitle.clone()).with_right(row.trailing.clone())
            })
            .collect::<Vec<_>>();
        let current = if state.detail_open {
            Some(state.selected)
        } else {
            None
        };
        let detail = state
            .rows
            .get(state.selected)
            .map(|row| {
                row.detail_rows(Utc::now(), state.revealed)
                    .into_iter()
                    .map(|(label, value)| (short_label(&label), value))
                    .collect()
            })
            .unwrap_or_default();
        let title = state
            .rows
            .get(state.selected)
            .map(|row| row.title.clone())
            .unwrap_or_default();
        Browser {
            tabs: CATEGORIES
                .iter()
                .map(|category| format!("{} {}", category.label(), category.count(&state.view)))
                .collect(),
            active_tab: state.category.index(),
            items,
            selected: state.selected,
            current,
            empty: format!("No {} yet", state.category.label().to_lowercase()),
            detail,
            detail_title: title,
            detail_scroll: state.detail_scroll,
        }
    }

    fn palette_model(&self) -> Palette {
        let state = self.state.borrow();
        let selected = state
            .palette_selected
            .min(state.palette_commands.len().saturating_sub(1));
        let mut rows = Vec::new();
        let mut selected_row = 0;
        let mut group: Option<String> = None;
        for (index, command) in state.palette_commands.iter().enumerate() {
            let category = command
                .category()
                .map(|category| category.label().to_string())
                .unwrap_or_else(|| "Commands".into());
            if group.as_deref() != Some(category.as_str()) {
                if !rows.is_empty() {
                    rows.push(Line::Blank);
                }
                rows.push(Line::Heading(category.clone()));
                group = Some(category.clone());
            }
            if index == selected {
                selected_row = rows.len();
            }
            rows.push(Line::item(command.name(), command.description()));
        }
        Palette {
            rows,
            selected: selected_row,
            empty: if state.query.trim().is_empty() {
                "No items available".into()
            } else {
                "No results found".into()
            },
        }
    }

    fn refresh_page(&self) {
        let (screen, palette_open) = {
            let state = self.state.borrow();
            (state.screen, state.palette_open)
        };
        let mut model = PageModel {
            page: Some(match screen {
                Screen::Dashboard => Page::Dashboard,
                Screen::Browser => Page::Browser,
                Screen::Help => Page::Help,
            }),
            ..PageModel::default()
        };
        match screen {
            Screen::Dashboard => model.home = self.home_model(),
            Screen::Browser => {
                {
                    let mut state = self.state.borrow_mut();
                    let rows = state.category.rows(&state.view, &state.query);
                    state.selected = state.selected.min(rows.len().saturating_sub(1));
                    state.rows = rows;
                }
                model.browser = self.browser_model();
            }
            Screen::Help => {
                model.help = Some(Help {
                    groups: help_groups(),
                    scroll: self.state.borrow().help_scroll,
                })
            }
        }
        if palette_open {
            model.palette = Some(self.palette_model());
        }
        self.page.set(model);
    }

    fn refresh_footer(&self) {
        let state = self.state.borrow();
        let width = usize::from(state.size.0);
        let location = match state.screen {
            Screen::Dashboard => "apw".to_string(),
            Screen::Help => "help".to_string(),
            Screen::Browser => {
                let mut text = format!("vault / {}", state.category.label());
                if !state.query.is_empty() && !state.palette_open {
                    text.push_str(" / ");
                    text.push_str(&state.query);
                }
                text
            }
        };
        let wide = width >= 60;
        let mut groups: Vec<&str> = match state.screen {
            Screen::Dashboard if wide => vec!["type to search", "ctrl+p commands", "tab focus"],
            Screen::Dashboard => vec!["type search", "ctrl+p commands", "tab focus"],
            Screen::Browser => vec!["↑↓ move", "enter open", "/ commands", "esc back"],
            Screen::Help => vec!["↑↓ scroll", "enter close", "esc back"],
        };
        if state.syncing {
            groups.push("syncing");
        }
        let location = truncate(&location, (width / 2).min(28));
        let available = width
            .saturating_sub(4)
            .saturating_sub(location.chars().count() + 2);
        let mut hints = String::new();
        for group in groups {
            let candidate = if hints.is_empty() {
                group.to_string()
            } else {
                format!("{hints} · {group}")
            };
            if candidate.chars().count() <= available {
                hints = candidate;
            } else {
                if hints.is_empty() {
                    hints = truncate(group, available);
                }
                break;
            }
        }
        drop(state);
        self.location.set_text(location);
        self.hints.set_text(hint_content(&hints, &self.tokens));
    }

    fn set_query(&self, query: String) {
        let palette_open = self.state.borrow().palette_open;
        if palette_open {
            {
                let mut state = self.state.borrow_mut();
                state.query = query;
                state.palette_selected = 0;
            }
            self.refresh_palette();
            self.refresh_page();
            self.refresh_footer();
            return;
        }
        if let Some(rest) = query.strip_prefix('/') {
            {
                let mut state = self.state.borrow_mut();
                state.palette_open = true;
                state.query = rest.to_string();
                state.palette_selected = 0;
            }
            self.prompt.set_value(rest);
            self.refresh_palette();
            self.refresh_page();
            self.apply_layout();
            self.refresh_footer();
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            state.query = query;
            state.selected = 0;
        }
        self.refresh_page();
        self.refresh_footer();
    }

    fn refresh_palette(&self) {
        let term = {
            let state = self.state.borrow();
            state.query.trim_start_matches('/').trim().to_lowercase()
        };
        let mut ranked = COMMANDS
            .iter()
            .copied()
            .filter(|command| {
                command.name().contains(&term)
                    || command.description().to_lowercase().contains(&term)
                    || command
                        .category()
                        .is_some_and(|category| category.label().to_lowercase().contains(&term))
            })
            .map(|command| {
                let name = command.name();
                let rank = if name == term {
                    0
                } else if name.starts_with(&term) {
                    1
                } else if name.contains(&term) {
                    2
                } else {
                    3
                };
                (rank, command)
            })
            .collect::<Vec<_>>();
        ranked.sort_by_key(|(rank, _)| *rank);
        let commands = ranked
            .into_iter()
            .map(|(_, command)| command)
            .collect::<Vec<_>>();
        let count = commands.len();
        {
            let mut state = self.state.borrow_mut();
            state.palette_commands = commands;
            state.palette_selected = state.palette_selected.min(count.saturating_sub(1));
            state.palette_open = true;
        }
        self.refresh_page();
        self.apply_layout();
        self.prompt.focus();
    }

    fn palette_nav(&self, key: &KeyEvent) -> bool {
        let (open, page) = {
            let state = self.state.borrow();
            (state.palette_open, state.palette_commands.len())
        };
        if !open {
            return false;
        }
        if key.matches("alt+down") || key.matches("alt+up") {
            self.jump_palette_group(if key.matches("alt+down") { 1 } else { -1 });
            return true;
        }
        let step = if key.matches("down") {
            Some(1)
        } else if key.matches("up") {
            Some(-1)
        } else if key.matches("pagedown") {
            Some(10)
        } else if key.matches("pageup") {
            Some(-10)
        } else {
            None
        };
        if let Some(step) = step {
            if page > 0 {
                let mut state = self.state.borrow_mut();
                state.palette_selected =
                    (state.palette_selected as isize + step).rem_euclid(page as isize) as usize;
            }
            self.refresh_page();
            return true;
        }
        if key.matches("home") {
            self.state.borrow_mut().palette_selected = 0;
            self.refresh_page();
            return true;
        }
        if key.matches("end") {
            self.state.borrow_mut().palette_selected = page.saturating_sub(1);
            self.refresh_page();
            return true;
        }
        false
    }

    fn close_palette(&self) {
        self.state.borrow_mut().palette_open = false;
        self.prompt.set_value("");
        self.set_query(String::new());
        self.apply_layout();
        self.refresh_page();
        self.refresh_footer();
        self.prompt.focus();
    }

    fn jump_palette_group(&self, step: isize) {
        let (commands, selected) = {
            let state = self.state.borrow();
            (state.palette_commands.clone(), state.palette_selected)
        };
        if commands.is_empty() {
            return;
        }
        let group = |command: &Command| {
            command
                .category()
                .map(|category| category.label())
                .unwrap_or("Commands")
        };
        let current = group(&commands[selected]);
        let target = if step > 0 {
            commands
                .iter()
                .enumerate()
                .skip(selected + 1)
                .find(|(_, command)| group(command) != current)
                .map(|(index, _)| index)
        } else {
            let start = commands[..=selected]
                .iter()
                .rposition(|command| group(command) == current)
                .unwrap_or(selected);
            let Some(previous) = commands[..start]
                .iter()
                .rposition(|command| group(command) != current)
            else {
                return;
            };
            Some(
                commands[..=previous]
                    .iter()
                    .rposition(|command| group(command) == group(&commands[previous]))
                    .unwrap_or(previous),
            )
        };
        if let Some(target) = target {
            self.state.borrow_mut().palette_selected = target;
            self.refresh_page();
        }
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
        self.close_palette();
        self.set_notice(None, false);
        match command {
            Command::Sync => self.start_sync(false),
            Command::SyncForce => self.start_sync(true),
            Command::Otp => {
                if self.copy_otp() {
                    self.set_notice(Some("copied the one-time code".into()), false);
                } else {
                    self.set_notice(Some("the selected item has no one-time code".into()), true);
                }
            }
            Command::Group => self.start_group(),
            Command::AddLogin => self.open_form(FormKind::AddLogin),
            Command::AddWifi => self.open_form(FormKind::AddWifi),
            Command::AddNote => self.open_form(FormKind::AddNote),
            Command::PasskeyImport => self.open_form(FormKind::PasskeyImport),
            Command::PasskeyExport => self.open_form(FormKind::PasskeyExport),
            Command::Edit => self.start_edit(),
            Command::Remove => self.start_remove(),
            Command::Restore => self.start_restore(),
            Command::ResolveLocal => self.start_resolve(true),
            Command::ResolveRemote => self.start_resolve(false),
            Command::Login => self.open_auth(false),
            Command::LoginRefresh => self.start_refresh(),
            Command::Join => self.open_auth(true),
            Command::Help => {
                {
                    let mut state = self.state.borrow_mut();
                    state.help_return = state.screen;
                    state.screen = Screen::Help;
                }
                self.refresh();
                self.focus(FocusTarget::Composer);
            }
            Command::Status => {
                self.state.borrow_mut().screen = Screen::Dashboard;
                self.refresh();
                self.focus(FocusTarget::Composer);
            }
            Command::Get => {
                self.state.borrow_mut().screen = Screen::Browser;
                self.refresh();
                let index = self.state.borrow().selected;
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
                    self.save_category(category);
                    self.refresh();
                    self.focus(FocusTarget::List);
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
        self.save_category(category);
        self.refresh_page();
        self.refresh_footer();
    }

    fn save_category(&self, category: Category) {
        let paths = self.state.borrow().view.paths.clone();
        if self.state.borrow().view.config.tui.last_category.as_deref() == Some(category.key()) {
            return;
        }
        let saved = crate::config::Config::update(&paths, |config| {
            config.tui.last_category = Some(category.key().to_string());
        });
        match saved {
            Ok(config) => self.state.borrow_mut().view.config = config,
            Err(error) => {
                self.set_notice(
                    Some(format!("category not saved: {}", error.message())),
                    true,
                );
            }
        }
        self.state.borrow_mut().view.config.tui.last_category = Some(category.key().to_string());
    }

    fn select_row(&self, index: usize) {
        {
            let mut state = self.state.borrow_mut();
            if state.selected != index {
                state.revealed = false;
            }
            state.selected = index;
        }
        self.refresh_page();
    }

    fn activate_row(&self, index: usize) {
        self.select_row(index);
        self.state.borrow_mut().detail_open = true;
        self.apply_layout();
        self.focus(FocusTarget::Detail);
    }

    fn selected_entry(&self) -> Option<crate::model::Entry> {
        let state = self.state.borrow();
        match &state.rows.get(state.selected)?.source {
            RowSource::Entry(entry) => Some((**entry).clone()),
            RowSource::Trash(trash) => Some(trash.entry.clone()),
            _ => None,
        }
    }

    fn copy_password(&self) -> bool {
        let Some(entry) = self.selected_entry() else {
            return false;
        };
        if let Some(password) = entry.password.as_deref().filter(|value| !value.is_empty()) {
            self.app.copy_to_clipboard(password);
            return true;
        }
        false
    }

    fn copy_otp(&self) -> bool {
        let Some(entry) = self.selected_entry() else {
            return false;
        };
        let Some(totp) = entry.totp.as_ref() else {
            return false;
        };
        if let Ok(code) = crate::totp::generate(totp, SystemTime::now()) {
            self.app.copy_to_clipboard(&code);
            return true;
        }
        false
    }

    fn reveal_password(&self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        if entry.password.is_none() {
            return;
        }
        self.state.borrow_mut().revealed = true;
        self.refresh_page();
        let ui = self.clone();
        self.app.set_timeout(Duration::from_secs(20), move |_cx| {
            ui.state.borrow_mut().revealed = false;
            ui.refresh_page();
        });
    }

    fn start_sync(&self, force: bool) {
        if self.state.borrow().syncing {
            return;
        }
        let (paths, config) = {
            let state = self.state.borrow();
            (state.view.paths.clone(), state.view.config.clone())
        };
        self.state.borrow_mut().syncing = true;
        self.refresh_footer();
        let proxy = self.app.proxy();
        std::thread::spawn(move || {
            let mut config = config;
            let result = crate::commands::sync::run_quiet(&paths, &mut config, force, None)
                .map_err(|error| error.message().to_string());
            let _ = proxy.send(SyncFinished(result));
        });
    }

    fn reload_if_changed(&self) {
        let (path, seen, busy) = {
            let state = self.state.borrow();
            (
                state.view.paths.snapshot_file.clone(),
                state.snapshot_mtime,
                state.modal_open || state.syncing,
            )
        };
        if busy {
            return;
        }
        let current = std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok();
        if current.is_some() && current != seen {
            let reload = self.state.borrow_mut().view.reload();
            self.state.borrow_mut().snapshot_mtime = current;
            if reload.is_ok() {
                self.refresh();
            }
        }
    }

    fn finish_sync(&self, result: std::result::Result<crate::commands::sync::SyncOutcome, String>) {
        self.state.borrow_mut().syncing = false;
        match result {
            Ok(outcome) => {
                let reload = self.state.borrow_mut().view.reload();
                self.refresh();
                match reload {
                    Ok(()) => self.set_notice(
                        Some(format!(
                            "synced {} logins ({})",
                            outcome.logins, outcome.note
                        )),
                        false,
                    ),
                    Err(error) => self.set_notice(
                        Some(format!("synced, but reload failed: {}", error.message())),
                        true,
                    ),
                }
            }
            Err(error) => {
                self.refresh_footer();
                self.set_notice(Some(error), true);
            }
        }
    }

    fn set_notice(&self, text: Option<String>, error: bool) {
        match text {
            Some(text) => {
                self.toast_text.set_text(text).fg(if error {
                    self.tokens.error
                } else {
                    self.tokens.text
                });
                self.toast_more.set_text("");
                self.toast_start.fg(if error {
                    self.tokens.error
                } else {
                    self.tokens.info
                });
                self.toast_end.fg(if error {
                    self.tokens.error
                } else {
                    self.tokens.info
                });
                self.toast.visible(true);
                let ui = self.clone();
                self.app.set_timeout(Duration::from_secs(5), move |_cx| {
                    ui.toast.visible(false);
                });
            }
            None => {
                self.toast.visible(false);
            }
        }
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
        self.prompt.set_value(row.title.clone());
        self.refresh();
        if self.state.borrow().detail_open {
            self.focus(FocusTarget::Detail);
        } else {
            self.focus(FocusTarget::List);
        }
    }

    fn submit(&self, cx: &mut Cx<'_>) {
        if self.state.borrow().palette_open {
            let index = self.state.borrow().palette_selected;
            self.run_palette(cx, index);
            return;
        }
        let screen = self.state.borrow().screen;
        match screen {
            Screen::Dashboard => {
                self.state.borrow_mut().screen = Screen::Browser;
                self.refresh();
                self.focus(FocusTarget::List);
            }
            Screen::Browser => {
                self.focus(FocusTarget::List);
            }
            Screen::Help => {
                let return_to = self.state.borrow().help_return;
                self.state.borrow_mut().screen = return_to;
                self.refresh();
                self.focus(FocusTarget::Composer);
            }
        }
    }

    fn open_palette(&self) {
        self.prompt.set_value("/");
        self.set_query("/".into());
        self.focus(FocusTarget::Composer);
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
        if detail_open {
            let focus = self.state.borrow().focus;
            if compact {
                self.state.borrow_mut().detail_open = false;
                self.apply_layout();
            }
            if focus == FocusTarget::Detail {
                self.focus(FocusTarget::List);
                self.refresh_page();
                return;
            }
        }
        match screen {
            Screen::Help => {
                let return_to = self.state.borrow().help_return;
                self.state.borrow_mut().screen = return_to;
                self.refresh();
                self.focus(FocusTarget::Composer);
            }
            Screen::Browser => {
                if !self.state.borrow().query.is_empty() {
                    self.prompt.set_value("");
                    self.set_query(String::new());
                    self.focus(FocusTarget::Composer);
                } else {
                    self.state.borrow_mut().screen = Screen::Dashboard;
                    self.refresh();
                    self.focus(FocusTarget::Composer);
                }
            }
            Screen::Dashboard => {
                if !self.state.borrow().query.is_empty() {
                    self.prompt.set_value("");
                    self.set_query(String::new());
                }
            }
        }
    }

    fn key(&self, cx: &mut Cx<'_>, key: &KeyEvent) {
        if self.state.borrow().modal_open {
            return;
        }
        if key.matches("ctrl+c") && self.state.borrow().palette_open {
            self.close_palette();
            cx.stop_propagation();
            return;
        }
        if key.matches("ctrl+c") {
            cx.quit();
            return;
        }
        if key.matches("ctrl+z") {
            self.app.suspend();
            return;
        }
        if key.matches("escape") {
            if self.state.borrow().palette_open {
                self.close_palette();
            } else {
                self.back();
            }
            cx.stop_propagation();
            return;
        }
        let (screen, palette_open, focus) = {
            let state = self.state.borrow();
            (state.screen, state.palette_open, state.focus)
        };
        if palette_open {
            let page = self.state.borrow().palette_commands.len();
            if key.matches("enter") {
                let index = self.state.borrow().palette_selected;
                self.run_palette(cx, index);
                cx.stop_propagation();
                return;
            }
            if key.matches("alt+down") || key.matches("alt+up") {
                self.jump_palette_group(if key.matches("alt+down") { 1 } else { -1 });
                cx.stop_propagation();
                return;
            }
            let step = if key.matches("down") {
                Some(1)
            } else if key.matches("up") {
                Some(-1)
            } else if key.matches("pagedown") {
                Some(10)
            } else if key.matches("pageup") {
                Some(-10)
            } else {
                None
            };
            if let Some(step) = step {
                if page > 0 {
                    let mut state = self.state.borrow_mut();
                    state.palette_selected =
                        (state.palette_selected as isize + step).rem_euclid(page as isize) as usize;
                }
                self.refresh_page();
                cx.stop_propagation();
                return;
            }
            if key.matches("home") {
                self.state.borrow_mut().palette_selected = 0;
                self.refresh_page();
                cx.stop_propagation();
                return;
            }
            if key.matches("end") {
                let last = page.saturating_sub(1);
                self.state.borrow_mut().palette_selected = last;
                self.refresh_page();
                cx.stop_propagation();
                return;
            }
            return;
        }
        if key.matches("ctrl+p") {
            self.open_palette();
            cx.stop_propagation();
            return;
        }
        if key.matches("tab") {
            let next = match (screen, focus) {
                (Screen::Dashboard, FocusTarget::Composer) => FocusTarget::List,
                (Screen::Dashboard, _) => FocusTarget::Composer,
                (Screen::Browser, FocusTarget::Composer) => FocusTarget::List,
                (Screen::Browser, FocusTarget::List) => FocusTarget::Detail,
                (Screen::Browser, _) => FocusTarget::Composer,
                (Screen::Help, _) => FocusTarget::Composer,
            };
            self.focus(next);
            self.refresh_page();
            cx.stop_propagation();
            return;
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
        if screen == Screen::Help {
            if key.matches("enter") || key.matches("escape") {
                self.back();
                cx.stop_propagation();
                return;
            }
            let step = if key.matches("pagedown") || key.matches("pageup") {
                10
            } else {
                1
            };
            if key.matches("down") || key.matches("pagedown") {
                let limit = help_scroll_limit(self.state.borrow().size);
                let mut state = self.state.borrow_mut();
                state.help_scroll = (state.help_scroll + step).min(limit);
                drop(state);
                self.refresh_page();
            } else if key.matches("up") || key.matches("pageup") {
                let mut state = self.state.borrow_mut();
                state.help_scroll = state.help_scroll.saturating_sub(step);
                drop(state);
                self.refresh_page();
            } else if key.matches("home") {
                self.state.borrow_mut().help_scroll = 0;
                self.refresh_page();
            } else if key.matches("end") {
                let limit = help_scroll_limit(self.state.borrow().size);
                self.state.borrow_mut().help_scroll = limit;
                self.refresh_page();
            }
            return;
        }
        if focus == FocusTarget::List {
            if let KeyCode::Char(character) = key.code {
                if !key.modifiers.contains(Modifiers::CTRL)
                    && !key.modifiers.contains(Modifiers::ALT)
                    && character != '/'
                    && character != 'q'
                {
                    self.focus(FocusTarget::Composer);
                    self.prompt.insert(character.to_string());
                    cx.stop_propagation();
                    return;
                }
            }
        }
        let mut moved = false;
        if key.matches("down") {
            moved = self.move_selection(1);
        } else if key.matches("up") {
            moved = self.move_selection(-1);
        } else if key.matches("pagedown") {
            moved = self.move_selection(10);
        } else if key.matches("pageup") {
            moved = self.move_selection(-10);
        } else if key.matches("home") {
            moved = self.move_selection(isize::MIN / 2);
        } else if key.matches("end") {
            moved = self.move_selection(isize::MAX / 2);
        }
        if moved {
            cx.stop_propagation();
            return;
        }
        if key.matches("enter") {
            match screen {
                Screen::Dashboard if focus == FocusTarget::List => {
                    let index = self.state.borrow().recent_selected;
                    self.open_recent(index);
                }
                Screen::Browser if focus == FocusTarget::List => {
                    let index = self.state.borrow().selected;
                    self.activate_row(index);
                    self.focus(FocusTarget::Detail);
                    self.refresh_page();
                }
                _ => {}
            }
            cx.stop_propagation();
            return;
        }
        if screen == Screen::Browser && focus == FocusTarget::Detail {
            let action = if key.matches("y") {
                Some("copy")
            } else if key.matches("o") {
                Some("otp")
            } else if key.matches("r") {
                Some("reveal")
            } else if key.matches("e") {
                Some("edit")
            } else if key.matches("a") {
                Some("add")
            } else if key.matches("g") {
                Some("group")
            } else if key.matches("t") {
                Some("remove")
            } else if key.matches("s") {
                Some("restore")
            } else if key.matches("u") {
                Some("undo")
            } else if key.matches("l") {
                Some("local")
            } else if key.matches("v") {
                Some("remote")
            } else {
                None
            };
            match action {
                Some("copy") => {
                    if self.copy_password() {
                        self.set_notice(Some("copied the password".into()), false);
                    } else {
                        self.set_notice(Some("the selected item has no password".into()), true);
                    }
                }
                Some("otp") => {
                    if self.copy_otp() {
                        self.set_notice(Some("copied the one-time code".into()), false);
                    } else {
                        self.set_notice(
                            Some("the selected item has no one-time code".into()),
                            true,
                        );
                    }
                }
                Some("reveal") => self.reveal_password(),
                Some("edit") => self.start_edit(),
                Some("add") => self.open_form(FormKind::AddLogin),
                Some("group") => self.start_group(),
                Some("remove") => self.start_remove(),
                Some("restore") => self.start_restore(),
                Some("undo") => self.undo_trash(),
                Some("local") => self.start_resolve(true),
                Some("remote") => self.start_resolve(false),
                _ => {}
            }
            if action.is_some() {
                cx.stop_propagation();
                return;
            }
        }
        if key.matches("/") && focus != FocusTarget::Composer {
            self.open_palette();
            cx.stop_propagation();
            return;
        }
        if key.matches("q") && focus != FocusTarget::Composer {
            cx.quit();
        }
    }

    fn move_selection(&self, step: isize) -> bool {
        let (screen, focus) = {
            let state = self.state.borrow();
            (state.screen, state.focus)
        };
        if focus == FocusTarget::Composer {
            return false;
        }
        match screen {
            Screen::Dashboard => {
                let count = self.state.borrow().recents.len();
                if count == 0 {
                    return false;
                }
                let mut state = self.state.borrow_mut();
                let next = if step == isize::MIN / 2 {
                    0
                } else if step == isize::MAX / 2 {
                    count - 1
                } else {
                    (state.recent_selected as isize + step).rem_euclid(count as isize) as usize
                };
                state.recent_selected = next;
                drop(state);
                self.refresh_page();
                true
            }
            Screen::Browser => {
                let count = self.state.borrow().rows.len();
                if count == 0 {
                    return false;
                }
                let mut state = self.state.borrow_mut();
                let next = if step == isize::MIN / 2 {
                    0
                } else if step == isize::MAX / 2 {
                    count - 1
                } else {
                    (state.selected as isize + step).rem_euclid(count as isize) as usize
                };
                state.selected = next;
                state.revealed = false;
                state.detail_scroll = 0;
                drop(state);
                self.refresh_page();
                true
            }
            Screen::Help => false,
        }
    }

    fn cycle_category(&self, step: isize) {
        let index = self.state.borrow().category.index() as isize;
        let next = (index + step).rem_euclid(CATEGORIES.len() as isize) as usize;
        self.set_category(next);
    }
}

fn hint_content(text: &str, tokens: &Tokens) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (index, group) in text.split(" · ").enumerate() {
        if index > 0 {
            spans.push(Span::raw(" · ").fg(tokens.faint));
        }
        let mut parts = group.splitn(2, ' ');
        let key = parts.next().unwrap_or_default();
        let label = parts.next().unwrap_or_default();
        spans.push(Span::raw(key.to_string()).fg(tokens.text));
        if !label.is_empty() {
            spans.push(Span::raw(format!(" {label}")).fg(tokens.muted));
        }
    }
    spans
}

fn short_label(label: &str) -> String {
    match label {
        "One-time code" => "Code".into(),
        "Created" => "Created".into(),
        "Last modified" => "Modified".into(),
        other => other.to_string(),
    }
}

fn wordmark_lines(size: (u16, u16)) -> Vec<String> {
    let (width, height) = size;
    if height < 12 {
        return Vec::new();
    }
    if width < 44 {
        return vec![WORDMARK_COMPACT.to_string()];
    }
    WORDMARK.lines().map(str::to_string).collect()
}

fn help_scroll_limit(size: (u16, u16)) -> usize {
    let (_, height) = size;
    let dialog_height = u32::from(height)
        .saturating_sub(1)
        .saturating_sub(2)
        .min(28);
    let visible = dialog_height.saturating_sub(3) as usize;
    let rows = help_groups()
        .iter()
        .enumerate()
        .map(|(index, (_, rows))| rows.len() + 1 + usize::from(index > 0))
        .sum::<usize>();
    rows.saturating_sub(visible)
}

fn help_groups() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        (
            "Vault",
            vec![
                ("y", "copy the password"),
                ("o", "copy the one-time code"),
                ("r", "reveal for 20 seconds"),
                ("e", "edit the item"),
                ("t", "move to Recently Deleted"),
                ("s", "restore an item"),
                ("g", "change the group"),
                ("a", "add a login"),
                ("u", "undo the last delete"),
                ("l / v", "keep local or remote"),
            ],
        ),
        (
            "Navigation",
            vec![
                ("↑ ↓", "move"),
                ("enter", "open"),
                ("tab", "switch focus"),
                ("ctrl+tab", "next category"),
                ("esc", "back"),
                ("ctrl+p", "commands"),
                ("/", "commands"),
                ("ctrl+c", "quit"),
            ],
        ),
        (
            "Sync",
            vec![
                ("/sync", "sync now"),
                ("/login", "sign in again"),
                ("/join", "join the trust circle"),
            ],
        ),
    ]
}

fn count_lines(counts: &[(&str, usize)], width: u16) -> String {
    let mut lines = Vec::new();
    let mut line = String::new();
    for (label, count) in counts {
        let item = format!("{count} {label}");
        let next = line.chars().count() + 3 + item.chars().count();
        if !line.is_empty() && next > usize::from(width) {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push_str("   ");
        }
        line.push_str(&item);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, State};
    use crate::model::{Entry, EntryKind, Vault};
    use opentui::testing::TestApp;

    fn test_paths() -> crate::config::Paths {
        let root = tempfile::tempdir().unwrap().keep();
        crate::config::Paths {
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            snapshot_file: root.join("data/snapshot.bin"),
            state_dir: root.join("state"),
            state_file: root.join("state/state.json"),
        }
    }

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
            paths: test_paths(),
            has_snapshot: true,
        }
    }

    fn ui(app: &TestApp) -> Ui {
        let ui = Ui::build((**app).clone(), view(), Tokens::fallback());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();
        ui
    }

    fn ui_sized(app: &TestApp, width: u16, height: u16) -> Ui {
        let ui = Ui::build((**app).clone(), view(), Tokens::fallback());
        ui.wire();
        ui.resize(width, height);
        ui.refresh();
        ui
    }

    fn temp_view() -> (tempfile::TempDir, VaultView) {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths {
            config_dir: dir.path().join("config"),
            config_file: dir.path().join("config/config.toml"),
            data_dir: dir.path().join("data"),
            snapshot_file: dir.path().join("data/snapshot.bin"),
            state_dir: dir.path().join("state"),
            state_file: dir.path().join("state/state.json"),
        };
        paths.ensure().unwrap();
        let key = crate::store::key::SnapshotKey {
            key: [7u8; 32],
            source: crate::store::key::KeySource::Passphrase,
        };
        crate::store::key::remember_session(&paths, &key);
        let vault = Vault {
            entries: vec![Entry {
                id: "one".into(),
                kind: EntryKind::Login,
                title: Some("Example".into()),
                username: Some("alice".into()),
                password: Some("hunter2".into()),
                sites: vec!["example.com".into()],
                updated_at: Some(Utc::now()),
                ..Entry::default()
            }],
            ..Vault::default()
        };
        let bytes = crate::store::seal(&vault, &key.key).unwrap();
        std::fs::write(&paths.snapshot_file, bytes).unwrap();
        let view = VaultView::load(&paths).unwrap();
        (dir, view)
    }

    #[test]
    fn dashboard_renders_counts_and_recents() {
        let app = TestApp::new(100, 30);
        let _ui = ui(&app);
        let text = app.render().text();
        assert!(text.contains("Recent"), "{text}");
        assert!(text.contains("2 logins"), "{text}");
    }

    #[test]
    fn typing_filters_the_list() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.state.borrow_mut().screen = Screen::Browser;
        ui.set_query("exam".into());
        assert_eq!(ui.state.borrow().rows.len(), 1);
        ui.set_query("nobody".into());
        assert_eq!(ui.state.borrow().rows.len(), 0);
    }

    #[test]
    fn slash_opens_and_filters_the_command_palette() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.set_query("/".into());
        assert!(ui.state.borrow().palette_open);
        assert_eq!(ui.state.borrow().palette_commands.len(), COMMANDS.len());
        ui.set_query("/qui".into());
        assert_eq!(ui.state.borrow().palette_commands.len(), 1);
        ui.set_query("/not".into());
        assert_eq!(ui.state.borrow().palette_commands.len(), 2);
        ui.back();
        assert!(!ui.state.borrow().palette_open);
        assert!(ui.state.borrow().query.is_empty());
    }

    #[test]
    fn palette_arrows_move_the_selection() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.set_query("/".into());
        app.press("down");
        assert_eq!(ui.state.borrow().palette_selected, 1);
        app.press("end");
        assert_eq!(
            ui.state.borrow().palette_selected,
            COMMANDS.len().saturating_sub(1)
        );
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
        assert_eq!(ui.state.borrow().screen, Screen::Browser);
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
    fn the_add_login_form_renders_and_reviews_before_saving() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.open_form(FormKind::AddLogin);
        let text = app.render().text();
        assert!(text.contains("NEW LOGIN"), "{text}");
        assert!(text.contains("Site"), "{text}");
        assert!(text.contains("Password"), "{text}");

        ui.set_field(RowKey::Site, "example.com");
        ui.set_field(RowKey::Username, "alice");
        ui.set_field(RowKey::Password, "hunter2");
        ui.review_form();
        let text = app.render().text();
        assert!(text.contains("Create a login"), "{text}");
        assert!(text.contains("7 characters"), "{text}");
        assert!(ui.state.borrow().form.as_ref().unwrap().review.is_some());

        app.press("escape");
        assert!(ui.state.borrow().form.as_ref().unwrap().review.is_none());
        app.press("escape");
        assert!(ui.state.borrow().confirm.is_some());
        app.press("right");
        app.press("enter");
        assert!(!ui.state.borrow().modal_open);
    }

    #[test]
    fn a_narrow_dashboard_keeps_recents_and_all_counts() {
        let app = TestApp::new(53, 34);
        let _ui = ui_sized(&app, 53, 34);
        let frame = app.render();
        let text = frame.text();
        for needle in ["apw", "Recent", "0 pending", "0 passkeys"] {
            assert!(text.contains(needle), "53x34 lost {needle:?}\n{text}");
        }
        for y in 0..34u32 {
            let row = frame.row(y);
            assert!(!row.trim_start().starts_with("trash"), "row {y}: {row}");
        }
    }

    #[test]
    fn the_hard_minimum_keeps_status_counts_and_actions() {
        let app = TestApp::new(40, 16);
        let _ui = ui_sized(&app, 40, 16);
        let text = app.render().text();
        for needle in ["apw", "0 pending", "0 passkeys", "ctrl+p"] {
            assert!(text.contains(needle), "40x16 lost {needle:?}\n{text}");
        }
    }

    #[test]
    fn enter_in_the_composer_opens_the_browser() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.prompt.set_value("exam");
        ui.set_query("exam".into());
        ui.focus(FocusTarget::Composer);
        app.press("enter");
        assert_eq!(ui.state.borrow().screen, Screen::Browser);
        assert_eq!(ui.state.borrow().query, "exam");
    }

    #[test]
    fn typing_returns_focus_to_the_composer() {
        let app = TestApp::new(53, 34);
        let ui = ui_sized(&app, 53, 34);
        ui.focus(FocusTarget::List);
        app.type_text("abc");
        assert_eq!(ui.state.borrow().query, "abc");
    }

    #[test]
    fn a_tap_inside_a_modal_focuses_its_field() {
        let app = TestApp::new(53, 34);
        let ui = ui_sized(&app, 53, 34);
        ui.open_form(FormKind::AddLogin);
        app.render();
        let target = ui.rows[RowKey::Username.index()]
            .input
            .as_ref()
            .unwrap()
            .rect();
        app.click(target.screen_x as u16 + 2, target.screen_y as u16);
        app.type_text("bob");
        assert_eq!(ui.field_value(RowKey::Username), "bob");
    }

    #[test]
    fn the_modal_action_tap_reviews_the_form() {
        let app = TestApp::new(53, 34);
        let ui = ui_sized(&app, 53, 34);
        ui.open_form(FormKind::AddLogin);
        ui.set_field(RowKey::Site, "example.com");
        ui.set_field(RowKey::Password, "hunter2");
        app.render();
        let rect = ui.modal_band.rect();
        app.click(rect.screen_x as u16 + 2, rect.screen_y as u16);
        assert!(ui
            .state
            .borrow()
            .form
            .as_ref()
            .is_some_and(|form| form.review.is_some()));
    }

    #[test]
    fn enter_moves_to_the_next_form_field() {
        let app = TestApp::new(53, 34);
        let ui = ui_sized(&app, 53, 34);
        ui.open_form(FormKind::AddLogin);
        app.type_text("example.com");
        app.press("enter");
        app.type_text("bob");
        assert_eq!(ui.field_value(RowKey::Username), "bob");
        assert_eq!(ui.state.borrow().form.as_ref().unwrap().focus, 1);
    }

    #[test]
    fn a_failed_save_keeps_the_form_focused() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.open_form(FormKind::AddLogin);
        ui.set_field(RowKey::Site, "example.com");
        ui.set_field(RowKey::Password, "hunter2");
        ui.focus_form(0);
        ui.review_form();
        ui.commit_prepared();
        assert!(ui.state.borrow().form.is_some());
        assert!(app.focused().is_some());
        app.type_text("x");
        assert_eq!(ui.field_value(RowKey::Site), "x");
    }

    #[test]
    fn escaping_the_discard_prompt_returns_to_the_form() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.open_form(FormKind::AddLogin);
        ui.set_field(RowKey::Site, "example.com");
        app.press("escape");
        assert!(ui.state.borrow().confirm.is_some());
        app.press("escape");
        assert!(ui.state.borrow().form.is_some());
        assert_eq!(ui.field_value(RowKey::Site), "example.com");
    }

    #[test]
    fn tab_does_not_arm_a_destructive_confirmation() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.show_confirm(
            "MOVE TO RECENTLY DELETED?",
            "Example",
            PendingAction::Trash {
                id: "one".into(),
                name: "Example".into(),
            },
        );
        app.press("tab");
        assert!(!ui.state.borrow().confirm.as_ref().unwrap().armed);
        app.press("enter");
        assert!(!ui.state.borrow().modal_open);
    }

    #[test]
    fn editing_a_note_keeps_its_body() {
        let (_dir, mut view) = temp_view();
        view.vault.entries.push(Entry {
            id: "n1".into(),
            kind: EntryKind::Note,
            title: Some("Groceries".into()),
            notes: Some("milk\neggs\nbread".into()),
            ..Entry::default()
        });
        let app = TestApp::new(100, 30);
        let ui = Ui::build((*app).clone(), view, Tokens::fallback());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();
        {
            let mut state = ui.state.borrow_mut();
            state.screen = Screen::Browser;
            state.category = Category::Notes;
            state.selected = 0;
        }
        ui.refresh();
        ui.open_form(FormKind::EditNote);
        assert_eq!(ui.field_value(RowKey::Notes), "milk\neggs\nbread");
        assert!(!ui.form_dirty());
    }

    #[test]
    fn a_confirmation_defaults_to_cancel() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.show_confirm(
            "MOVE TO RECENTLY DELETED?",
            "Example",
            PendingAction::Trash {
                id: "missing".into(),
                name: "Example".into(),
            },
        );
        app.press("enter");
        assert!(!ui.state.borrow().modal_open);
    }

    #[test]
    fn adding_and_trashing_an_entry_persists_to_the_snapshot() {
        let (_dir, view) = temp_view();
        let app = TestApp::new(100, 30);
        let ui = Ui::build((*app).clone(), view, Tokens::fallback());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();

        ui.open_form(FormKind::AddLogin);
        ui.set_field(RowKey::Site, "new.example");
        ui.set_field(RowKey::Username, "bob");
        ui.set_field(RowKey::Password, "secret");
        ui.review_form();
        ui.commit_prepared();
        assert!(!ui.state.borrow().modal_open);

        let paths = ui.state.borrow().view.paths.clone();
        let mut config = crate::config::Config::default();
        let loaded = crate::vault::load(&paths, &mut config).unwrap();
        assert_eq!(loaded.entries.len(), 2);
        assert!(loaded
            .entries
            .iter()
            .any(|entry| entry.url.as_deref() == Some("https://new.example")));

        {
            let mut state = ui.state.borrow_mut();
            state.screen = Screen::Browser;
            state.category = Category::Logins;
            state.query = "new.example".into();
            state.selected = 0;
        }
        ui.refresh();
        ui.start_remove();
        assert!(ui.state.borrow().confirm.is_some());
        app.press("right");
        app.press("enter");
        assert!(!ui.state.borrow().modal_open);

        let loaded = crate::vault::load(&paths, &mut config).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded
            .pending
            .iter()
            .any(|op| op.kind == crate::model::OpKind::Delete));
        assert!(ui.state.borrow().last_trash.is_some());
    }

    #[test]
    fn changing_category_keeps_the_kdf_salt() {
        let (_dir, mut view) = temp_view();
        view.config.kdf_salt = Some("c2FsdA==".into());
        view.config.account = Some("me@example.com".into());
        view.config.anisette_url = Some("http://127.0.0.1:6969".into());
        view.config.sync.min_interval_seconds = 123;
        view.config.tui.split = Some(true);
        view.config.save(&view.paths).unwrap();
        let app = TestApp::new(100, 30);
        let ui = Ui::build((*app).clone(), view, Tokens::fallback());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();
        ui.set_category(Category::Notes.index());
        let config = crate::config::Config::load(&ui.state.borrow().view.paths).unwrap();
        assert_eq!(config.kdf_salt.as_deref(), Some("c2FsdA=="));
        assert_eq!(config.account.as_deref(), Some("me@example.com"));
        assert_eq!(
            config.anisette_url.as_deref(),
            Some("http://127.0.0.1:6969")
        );
        assert_eq!(config.sync.min_interval_seconds, 123);
        assert_eq!(config.tui.split, Some(true));
        assert_eq!(config.tui.last_category.as_deref(), Some("notes"));
    }

    #[test]
    fn a_broken_config_is_not_replaced_by_a_category_change() {
        let (_dir, view) = temp_view();
        std::fs::write(&view.paths.config_file, "kdf_salt = 5\n").unwrap();
        let before = std::fs::read(&view.paths.config_file).unwrap();
        let app = TestApp::new(100, 30);
        let ui = Ui::build((*app).clone(), view, Tokens::fallback());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();
        ui.set_category(Category::Notes.index());
        assert_eq!(
            std::fs::read(&ui.state.borrow().view.paths.config_file).unwrap(),
            before
        );
        assert!(ui.state.borrow().view.config.tui.last_category.is_some());
    }

    #[test]
    fn the_login_wizard_keeps_a_salt_written_after_launch() {
        let (_dir, mut view) = temp_view();
        let disk = crate::config::Config {
            kdf_salt: Some("c2FsdA==".into()),
            ..crate::config::Config::default()
        };
        disk.save(&view.paths).unwrap();
        view.config = crate::config::Config::default();
        let app = TestApp::new(100, 30);
        let ui = Ui::build((*app).clone(), view, Tokens::fallback());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();
        ui.open_auth(false);
        ui.set_field(RowKey::Site, "http://127.0.0.1:6969");
        app.press("enter");
        let config = crate::config::Config::load(&ui.state.borrow().view.paths).unwrap();
        assert_eq!(config.kdf_salt.as_deref(), Some("c2FsdA=="));
        assert_eq!(
            config.anisette_url.as_deref(),
            Some("http://127.0.0.1:6969")
        );
    }

    #[test]
    fn the_group_picker_lists_snapshot_groups() {
        let app = TestApp::new(100, 30);
        let mut view = view();
        view.vault.groups = vec![crate::model::Group {
            id: "family".into(),
            name: Some("Family".into()),
            shared: true,
        }];
        let ui = Ui::build(app.clone(), view, Tokens::fallback());
        ui.wire();
        ui.resize(100, 30);
        ui.refresh();
        {
            let mut state = ui.state.borrow_mut();
            state.screen = Screen::Browser;
            state.query.clear();
        }
        ui.refresh();
        ui.start_group();
        assert_eq!(ui.state.borrow().picker.as_ref().unwrap().items.len(), 1);
        let text = app.render().text();
        assert!(text.contains("Family"), "{text}");
    }

    #[test]
    fn the_login_command_opens_the_wizard() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.set_query("/login".into());
        assert!(ui.state.borrow().palette_commands.len() >= 3);
        assert_eq!(
            ui.state.borrow().palette_commands.first().map(|c| c.name()),
            Some("login")
        );
        app.press("enter");
        assert!(ui.state.borrow().auth.is_some());
        assert!(ui.state.borrow().modal_open);
    }

    #[test]
    fn the_login_wizard_advances_to_the_masked_password() {
        let app = TestApp::new(100, 30);
        let ui = ui(&app);
        ui.open_auth(false);
        let text = app.render().text();
        assert!(text.contains("APPLE SIGN IN"), "{text}");
        assert!(text.contains("Anisette URL"), "{text}");

        ui.set_field(RowKey::Site, "http://127.0.0.1:6969");
        app.press("enter");
        assert_eq!(
            ui.state.borrow().auth.as_ref().unwrap().step,
            AuthStep::Account
        );
        ui.set_field(RowKey::Site, "me@example.com");
        app.press("enter");
        assert_eq!(
            ui.state.borrow().auth.as_ref().unwrap().step,
            AuthStep::Password
        );
        let text = app.render().text();
        assert!(text.contains("Password"), "{text}");
        assert!(text.contains("type a value"), "{text}");

        app.press("escape");
        assert!(!ui.state.borrow().modal_open);
    }

    #[test]
    #[ignore]
    fn dump_form() {
        for (width, height) in [
            (100, 30),
            (80, 24),
            (70, 24),
            (64, 24),
            (53, 34),
            (53, 14),
            (40, 16),
        ] {
            let app = TestApp::new(width, height);
            let ui = ui_sized(&app, width, height);
            ui.open_form(FormKind::AddLogin);
            ui.set_field(RowKey::Site, "example.com");
            ui.set_field(RowKey::Username, "alice");
            let frame = app.render();
            println!("--- form {width}x{height} ---");
            for y in 0..height as u32 {
                println!("{y:02}|{}|", frame.row(y));
            }
        }
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
        for (width, height) in [
            (100, 30),
            (80, 24),
            (70, 24),
            (64, 24),
            (53, 34),
            (53, 14),
            (40, 16),
        ] {
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
        for (width, height) in [
            (100, 30),
            (80, 24),
            (70, 24),
            (64, 24),
            (53, 34),
            (53, 14),
            (40, 16),
        ] {
            let app = TestApp::new(width, height);
            let _ui = ui_sized(&app, width, height);
            let frame = app.render();
            println!("--- {width}x{height} ---");
            println!("page {:?}", _ui.page_view.rect());
            for y in 0..height as u32 {
                println!("{y:02}|{}|", frame.row(y));
            }
        }
    }
}
