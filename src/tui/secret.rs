//! A masked single-line field for passwords and recovery codes.

use std::cell::RefCell;
use std::rc::Rc;

use opentui::prelude::*;

#[derive(Default)]
struct SecretState {
    value: String,
    cursor: usize,
    focused: bool,
}

/// Shared text, so the modal can read and clear a field the component edits.
#[derive(Clone, Default)]
pub struct SecretValue(Rc<RefCell<SecretState>>);

impl SecretValue {
    pub fn new(value: &str) -> Self {
        Self(Rc::new(RefCell::new(SecretState {
            value: value.to_string(),
            cursor: value.chars().count(),
            focused: false,
        })))
    }

    pub fn value(&self) -> String {
        self.0.borrow().value.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.0.borrow().value.is_empty()
    }

    pub fn clear(&self) {
        let mut state = self.0.borrow_mut();
        state.value.clear();
        state.cursor = 0;
    }

    pub fn set(&self, value: &str) {
        let mut state = self.0.borrow_mut();
        state.value = value.to_string();
        state.cursor = state.value.chars().count();
    }
}

/// The widget: paints one row of bullets and edits in place while focused.
pub struct SecretField {
    value: SecretValue,
}

impl SecretField {
    pub fn new(value: SecretValue) -> Self {
        Self { value }
    }
}

impl Component for SecretField {
    fn paint(&self, painter: &mut Painter<'_>) {
        let state = self.value.0.borrow();
        let width = painter.width() as usize;
        if width == 0 {
            return;
        }
        let style = if state.focused {
            Style::new().fg(Color::BRIGHT_WHITE)
        } else {
            Style::new().fg(Color::DEFAULT_FOREGROUND)
        };
        if state.value.is_empty() {
            let hint = if state.focused {
                "type a value"
            } else {
                "empty"
            };
            painter.text(0, 0, hint, Style::new().fg(Color::BRIGHT_BLACK));
            return;
        }
        let bullets = "•".repeat(state.value.chars().count().min(width));
        painter.text(0, 0, &bullets, style);
        if state.focused && state.cursor < width {
            painter.cell(state.cursor as i32, 0, ' ', style.inverse());
        }
    }

    fn key(&mut self, _cx: &mut Cx<'_>, key: &KeyEvent) -> bool {
        let mut state = self.value.0.borrow_mut();
        match key.code {
            KeyCode::Char(character)
                if !key.modifiers.contains(Modifiers::CTRL)
                    && !key.modifiers.contains(Modifiers::ALT) =>
            {
                let byte = char_byte(&state.value, state.cursor);
                state.value.insert(byte, character);
                state.cursor += 1;
                true
            }
            KeyCode::Backspace => {
                if state.cursor > 0 {
                    let byte = char_byte(&state.value, state.cursor - 1);
                    state.value.remove(byte);
                    state.cursor -= 1;
                }
                true
            }
            KeyCode::Delete => {
                if state.cursor < state.value.chars().count() {
                    let byte = char_byte(&state.value, state.cursor);
                    state.value.remove(byte);
                }
                true
            }
            KeyCode::Left => {
                state.cursor = state.cursor.saturating_sub(1);
                true
            }
            KeyCode::Right => {
                state.cursor = (state.cursor + 1).min(state.value.chars().count());
                true
            }
            KeyCode::Home => {
                state.cursor = 0;
                true
            }
            KeyCode::End => {
                state.cursor = state.value.chars().count();
                true
            }
            KeyCode::Char('u') if key.modifiers.contains(Modifiers::CTRL) => {
                state.value.clear();
                state.cursor = 0;
                true
            }
            _ => false,
        }
    }

    fn paste(&mut self, _cx: &mut Cx<'_>, text: &str) -> bool {
        let mut state = self.value.0.borrow_mut();
        let text = text.replace(['\n', '\r'], "");
        let byte = char_byte(&state.value, state.cursor);
        state.value.insert_str(byte, &text);
        state.cursor += text.chars().count();
        true
    }

    fn focus_changed(&mut self, _cx: &mut Cx<'_>, focused: bool) {
        self.value.0.borrow_mut().focused = focused;
    }
}

fn char_byte(text: &str, index: usize) -> usize {
    text.char_indices()
        .nth(index)
        .map_or(text.len(), |(byte, _)| byte)
}
