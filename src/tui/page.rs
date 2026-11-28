//! The page painter: dashboard, browser, palette, and help drawn cell by cell.
//!
//! opencode's chrome needs a rail beside filled rows, a 12-cell label column,
//! and ellipsis truncation. OpenTUI's list widgets cannot draw that, so the
//! body is painted from a model and only text entry uses a widget.

use opentui::prelude::{App, ColorMatrix, Component, Custom, Painter, Style};

use crate::tui::theme::Tokens;
use crate::tui::view::{truncate, Line};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    Browser,
    Help,
}

#[derive(Clone, Default)]
pub struct Home {
    pub wordmark: Vec<String>,
    pub status: String,
    pub counts: Vec<String>,
    pub warnings: Vec<String>,
    pub recents: Vec<Line>,
    pub selected: Option<usize>,
    pub empty: String,
}

#[derive(Clone, Default)]
pub struct Browser {
    pub tabs: Vec<String>,
    pub active_tab: usize,
    pub items: Vec<Line>,
    pub selected: usize,
    pub current: Option<usize>,
    pub empty: String,
    pub detail: Vec<(String, String)>,
    pub detail_title: String,
    pub detail_scroll: usize,
}

#[derive(Clone, Default)]
pub struct Palette {
    pub rows: Vec<Line>,
    pub selected: usize,
    pub empty: String,
}

#[derive(Clone, Default)]
pub struct Help {
    pub groups: Vec<(&'static str, Vec<(&'static str, &'static str)>)>,
    pub scroll: usize,
}

#[derive(Clone, Default)]
pub struct PageModel {
    pub page: Option<Page>,
    pub home: Home,
    pub browser: Browser,
    pub palette: Option<Palette>,
    pub help: Option<Help>,
}

pub struct PageView {
    model: PageModel,
    tokens: Tokens,
}

#[derive(Clone, Copy, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Default)]
pub struct HomeLayout {
    pub top: u32,
    pub wordmark: u32,
    pub prompt: Rect,
    pub recents: Rect,
}

impl PageView {
    pub fn new(app: &App, tokens: &Tokens) -> (Custom<Self>, PageHandle) {
        let custom = Custom::new(
            app,
            Self {
                model: PageModel::default(),
                tokens: *tokens,
            },
        );
        let handle = PageHandle(custom.clone());
        (custom, handle)
    }
}

#[derive(Clone)]
pub struct PageHandle(Custom<PageView>);

impl PageHandle {
    pub fn set(&self, model: PageModel) {
        self.0.update(|page| page.model = model);
    }

    pub fn page(&self) -> Option<Page> {
        self.0.with(|page| page.model.page)
    }
}

pub fn home_layout(width: u32, height: u32, home: &Home) -> HomeLayout {
    let pad = if width < 44 { 1 } else { 2 };
    let column = width.saturating_sub(pad * 2).min(75);
    let x = width.saturating_sub(column) / 2;
    let warnings = home.warnings.len() as u32;
    let counts = home.counts.len() as u32;
    let recents = home.recents.len().min(6) as u32;
    let wordmark = if height >= 12 { 6 } else { 0 };
    let content = wordmark + 1 + 1 + warnings + counts + 2 + 3 + 1 + recents;
    let top = height.saturating_sub(content) / 2;
    let prompt_y = top + wordmark + 1 + 1 + warnings + counts + 1;
    let recents_y = prompt_y + 3 + 1 + 1;
    HomeLayout {
        top,
        wordmark: top,
        prompt: Rect {
            x,
            y: prompt_y.min(height.saturating_sub(3)),
            width: column,
            height: 3,
        },
        recents: Rect {
            x,
            y: recents_y.min(height),
            width: column,
            height: recents,
        },
    }
}

pub fn palette_rect(terminal_width: u32, terminal_height: u32) -> Rect {
    let width = terminal_width.saturating_sub(2).min(60);
    let height = (terminal_height / 2)
        .saturating_sub(6)
        .clamp(6, terminal_height.saturating_sub(1).max(6));
    Rect {
        x: (terminal_width.saturating_sub(width)) / 2,
        y: terminal_height / 4,
        width,
        height,
    }
}

impl Component for PageView {
    fn paint(&self, painter: &mut Painter<'_>) {
        let (width, height) = painter.size();
        match self.model.page {
            None => {}
            Some(Page::Dashboard) => {
                draw_home(painter, &self.tokens, width, height, &self.model.home)
            }
            Some(Page::Browser) => {
                draw_browser(painter, &self.tokens, width, height, &self.model.browser)
            }
            Some(Page::Help) => draw_help(
                painter,
                &self.tokens,
                width,
                height,
                self.model.help.as_ref(),
            ),
        }
        if let (Some(palette), Some(_page)) = (&self.model.palette, self.model.page) {
            painter.color_matrix(0, 0, width, height, &ColorMatrix::gain(0.45));
            draw_palette(painter, &self.tokens, width, height, palette);
        }
    }
}

fn draw_home(painter: &mut Painter<'_>, tokens: &Tokens, width: u32, height: u32, home: &Home) {
    let layout = home_layout(width, height, home);
    let pad = if width < 44 { 1 } else { 2 };
    let column = width.saturating_sub(pad * 2).min(75);
    let x = width.saturating_sub(column) / 2;
    let mut y = layout.top;
    if height >= 12 && !home.wordmark.is_empty() {
        let widest = home
            .wordmark
            .iter()
            .map(|line| line.chars().count())
            .max()
            .unwrap_or(0) as u32;
        let word_x = width.saturating_sub(widest) / 2;
        if let Some(last) = home.wordmark.last() {
            let row = y + home.wordmark.len() as u32;
            if row < height {
                painter.text(word_x as i32, row as i32, last, Style::new().fg(tokens.shadow));
            }
        }
        for (index, line) in home.wordmark.iter().enumerate() {
            painter.text(
                word_x as i32,
                (y + index as u32) as i32,
                line,
                Style::new().fg(tokens.text).bold(),
            );
        }
        y += home.wordmark.len() as u32 + 1;
    }
    if !home.status.is_empty() {
        let text = truncate(&home.status, column as usize);
        let start = x + (column.saturating_sub(text.chars().count() as u32)) / 2;
        painter.text(start as i32, y as i32, &text, Style::new().fg(tokens.muted));
        y += 1;
    }
    for warning in &home.warnings {
        let text = truncate(warning, column as usize);
        let start = x + (column.saturating_sub(text.chars().count() as u32)) / 2;
        painter.text(
            start as i32,
            y as i32,
            &text,
            Style::new().fg(tokens.warning),
        );
        y += 1;
    }
    for counts in &home.counts {
        let text = truncate(counts, column as usize);
        let start = x + (column.saturating_sub(text.chars().count() as u32)) / 2;
        painter.text(start as i32, y as i32, &text, Style::new().fg(tokens.muted));
        y += 1;
    }
    let recent_y = layout.recents.y;
    let mut row = recent_y;
    {
        painter.text(
            (layout.recents.x + 2) as i32,
            row as i32,
            "Recent",
            Style::new().fg(tokens.text).bold(),
        );
        row += 1;
    }
    if !home.recents.is_empty() {
        for (index, line) in home.recents.iter().enumerate() {
            if row >= height {
                break;
            }
            draw_line(
                painter,
                tokens,
                layout.recents.x,
                row,
                layout.recents.width,
                line,
                home.selected == Some(index),
                false,
            );
            row += 1;
        }
    } else if !home.empty.is_empty() && row < height {
        painter.text(
            (layout.recents.x + 2) as i32,
            row as i32,
            &truncate(&home.empty, layout.recents.width.saturating_sub(2) as usize),
            Style::new().fg(tokens.muted),
        );
    }
}

fn draw_browser(
    painter: &mut Painter<'_>,
    tokens: &Tokens,
    width: u32,
    height: u32,
    browser: &Browser,
) {
    let pad = if width < 44 { 1 } else { 2 };
    let mut x = pad;
    let mut remaining = browser.tabs.len();
    for (index, label) in browser.tabs.iter().enumerate() {
        remaining -= 1;
        let reserve = if remaining > 0 { 4 } else { 0 };
        let text = format!(" {label} ");
        let room = width.saturating_sub(x + reserve) as usize;
        if room < 6 {
            let overflow = format!("‹{}", remaining + 1);
            painter.text(x as i32, 0, &overflow, Style::new().fg(tokens.muted));
            break;
        }
        let fitted = truncate(&text, room);
        let active = index == browser.active_tab;
        let style = if active {
            Style::new().fg(tokens.text).bg(tokens.hover).bold()
        } else {
            Style::new().fg(tokens.muted)
        };
        painter.text(x as i32, 0, &fitted, style);
        x += fitted.chars().count() as u32;
    }
    let body_top = 2;
    let body_height = height.saturating_sub(body_top + 4);
    let _ = pad;
    if width >= 96 {
        let list_width = (width * 42 / 100).max(20);
        let split_x = list_width;
        for (index, line) in browser.items.iter().enumerate() {
            let row = body_top + index as u32;
            if row >= body_top + body_height {
                break;
            }
            draw_line(
                painter,
                tokens,
                pad,
                row,
                split_x.saturating_sub(pad * 2),
                line,
                index == browser.selected,
                browser.current == Some(index),
            );
        }
        if browser.items.is_empty() && !browser.empty.is_empty() {
            painter.text(
                (pad + 2) as i32,
                body_top as i32,
                &truncate(&browser.empty, split_x.saturating_sub(pad * 2 + 2) as usize),
                Style::new().fg(tokens.muted),
            );
        }
        draw_detail(
            painter,
            tokens,
            split_x + pad,
            body_top,
            width.saturating_sub(split_x + pad * 2),
            body_height,
            browser,
        );
    } else if browser.current.is_some() {
        draw_detail(
            painter,
            tokens,
            pad,
            body_top,
            width.saturating_sub(pad * 2),
            body_height,
            browser,
        );
    } else {
        for (index, line) in browser.items.iter().enumerate() {
            let row = body_top + index as u32;
            if row >= body_top + body_height {
                break;
            }
            draw_line(
                painter,
                tokens,
                pad,
                row,
                width.saturating_sub(pad * 2),
                line,
                index == browser.selected,
                browser.current == Some(index),
            );
        }
    }
}

fn draw_detail(
    painter: &mut Painter<'_>,
    tokens: &Tokens,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    browser: &Browser,
) {
    if width <= 14 || browser.detail.is_empty() {
        return;
    }
    let mut row = y;
    let value_width = width.saturating_sub(14);
    painter.text(
        x as i32,
        row as i32,
        &truncate(&browser.detail_title, width as usize),
        Style::new().fg(tokens.text).bold(),
    );
    row += 1;
    let mut remaining = height.saturating_sub(1) as usize;
    let mut skip = browser.detail_scroll;
    for (label, value) in &browser.detail {
        let wrapped = wrap(value, value_width as usize);
        if skip > 0 {
            skip -= 1;
            continue;
        }
        if remaining <= 1 {
            break;
        }
        painter.text(
            x as i32,
            row as i32,
            &truncate(label, 12),
            Style::new().fg(tokens.muted),
        );
        for (index, line) in wrapped.iter().enumerate() {
            if index > 0 {
                row += 1;
                remaining = remaining.saturating_sub(1);
                if remaining <= 1 {
                    break;
                }
            }
            painter.text(
                (x + 14) as i32,
                row as i32,
                &truncate(line, value_width as usize),
                Style::new().fg(tokens.text),
            );
        }
        row += 1;
        remaining = remaining.saturating_sub(1);
    }
}

fn draw_help(
    painter: &mut Painter<'_>,
    tokens: &Tokens,
    width: u32,
    height: u32,
    help: Option<&Help>,
) {
    let Some(help) = help else { return };
    let dialog_width = width.saturating_sub(2).min(60);
    let dialog_height = height.saturating_sub(2).min(28);
    let x = (width.saturating_sub(dialog_width)) / 2;
    let y = (height.saturating_sub(dialog_height)) / 2;
    painter.fill(
        x as i32,
        y as i32,
        dialog_width,
        dialog_height,
        tokens.dialog,
    );
    painter.text(
        (x + 3) as i32,
        (y + 1) as i32,
        "Help",
        Style::new().fg(tokens.text).bold(),
    );
    painter.text(
        (x + dialog_width - 5) as i32,
        (y + 1) as i32,
        "esc",
        Style::new().fg(tokens.muted),
    );
    let mut row = y + 3;
    let mut skip = help.scroll;
    let mut first = true;
    for (group, rows) in &help.groups {
        if !first && row + 2 < y + dialog_height {
            row += 1;
        }
        first = false;
        if skip > 0 {
            skip -= 1;
        } else {
            if row + 1 >= y + dialog_height {
                break;
            }
            painter.text(
                (x + 3) as i32,
                row as i32,
                group,
                Style::new().fg(tokens.muted).bold(),
            );
            row += 1;
        }
        for (keys, description) in rows {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if row + 1 >= y + dialog_height {
                break;
            }
            painter.text(
                (x + 3) as i32,
                row as i32,
                &truncate(keys, 17),
                Style::new().fg(tokens.text),
            );
            painter.text(
                (x + 3 + 17) as i32,
                row as i32,
                &truncate(description, dialog_width.saturating_sub(23) as usize),
                Style::new().fg(tokens.muted),
            );
            row += 1;
        }
    }
    let footer = "ok enter";
    painter.text(
        (x + dialog_width).saturating_sub(footer.len() as u32 + 3) as i32,
        (y + dialog_height).saturating_sub(2) as i32,
        footer,
        Style::new().fg(tokens.muted),
    );
}

fn draw_palette(
    painter: &mut Painter<'_>,
    tokens: &Tokens,
    width: u32,
    height: u32,
    palette: &Palette,
) {
    let rect = palette_rect(width, height);
    painter.fill(
        rect.x as i32,
        rect.y as i32,
        rect.width,
        rect.height,
        tokens.dialog,
    );
    painter.text(
        (rect.x + rect.width - 4) as i32,
        (rect.y + 1) as i32,
        "esc",
        Style::new().fg(tokens.muted),
    );
    for (index, line) in palette.rows.iter().enumerate() {
        let row = rect.y + 3 + index as u32;
        if row + 1 >= rect.y + rect.height {
            break;
        }
        draw_line(
            painter,
            tokens,
            rect.x + 3,
            row,
            rect.width.saturating_sub(6),
            line,
            index == palette.selected,
            false,
        );
    }
    if palette.rows.is_empty() {
        painter.text(
            (rect.x + 3) as i32,
            (rect.y + 3) as i32,
            &truncate(&palette.empty, rect.width.saturating_sub(6) as usize),
            Style::new().fg(tokens.muted),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_line(
    painter: &mut Painter<'_>,
    tokens: &Tokens,
    x: u32,
    y: u32,
    width: u32,
    line: &Line,
    selected: bool,
    current: bool,
) {
    match line {
        Line::Blank => {}
        Line::Heading(text) => painter.text(
            (x + 2) as i32,
            y as i32,
            &truncate(text, width.saturating_sub(2) as usize),
            Style::new().fg(tokens.muted).bold(),
        ),
        Line::Item {
            title,
            description,
            right,
            ..
        } => {
            if selected {
                painter.fill(
                    (x + 1) as i32,
                    y as i32,
                    width.saturating_sub(1),
                    1,
                    tokens.selected,
                );
            }
            let rail = if selected {
                ("┃", tokens.selected_text)
            } else if current {
                ("▪", tokens.muted)
            } else {
                (" ", tokens.muted)
            };
            painter.text(x as i32, y as i32, rail.0, Style::new().fg(rail.1));
            let (title_style, meta_style) = if selected {
                (
                    Style::new().fg(tokens.selected_text),
                    Style::new().fg(tokens.selected_meta),
                )
            } else {
                (Style::new().fg(tokens.text), Style::new().fg(tokens.muted))
            };
            let right_width = right.chars().count() as u32;
            let right_start = width.saturating_sub(right_width + 1);
            let available = right_start.saturating_sub(2) as usize;
            let title_text = truncate(title, available);
            painter.text((x + 2) as i32, y as i32, &title_text, title_style);
            if !description.is_empty() {
                let used = title_text.chars().count() as u32;
                let remaining = available.saturating_sub(used as usize + 3);
                if remaining > 0 {
                    painter.text(
                        (x + 2 + used) as i32,
                        y as i32,
                        " · ",
                        Style::new().fg(tokens.faint),
                    );
                    painter.text(
                        (x + 5 + used) as i32,
                        y as i32,
                        &truncate(description, remaining),
                        meta_style,
                    );
                }
            }
            if right_width > 0 {
                painter.text(
                    (x + right_start) as i32,
                    y as i32,
                    right,
                    Style::new().fg(if selected {
                        tokens.selected_meta
                    } else {
                        tokens.muted
                    }),
                );
            }
        }
    }
}

/// Word wrap for detail values and messages.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        for word in paragraph.split(' ') {
            if word.is_empty() {
                continue;
            }
            let needed = if line.is_empty() {
                word.chars().count()
            } else {
                line.chars().count() + 1 + word.chars().count()
            };
            if needed <= width {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
            } else if line.is_empty() {
                lines.push(truncate(word, width));
            } else {
                lines.push(std::mem::take(&mut line));
                lines.push(truncate(word, width));
            }
        }
        if !line.is_empty() {
            lines.push(line);
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_splits_long_words_and_keeps_short_ones() {
        assert_eq!(wrap("one two", 10), vec!["one two".to_string()]);
        assert_eq!(
            wrap("one two", 4),
            vec!["one".to_string(), "two".to_string()]
        );
        assert_eq!(wrap("abcdef", 3), vec!["ab…".to_string()]);
    }

    #[test]
    fn the_prompt_stays_inside_a_narrow_page() {
        let home = Home::default();
        let layout = home_layout(40, 16, &home);
        assert!(layout.prompt.x + layout.prompt.width <= 40);
        assert!(layout.prompt.width <= 75);
    }
}
