use serde_json::{json, Value};

use crate::error::Error;
use crate::model::Status;

/// Output options shared by the query commands.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub json: bool,
    /// True when `--json` was passed, as opposed to inferred from a pipe.
    pub explicit_json: bool,
    pub wide: bool,
    pub no_header: bool,
}

impl Style {
    /// `--json`, or a pipe. A terminal gets tables unless `--json` is given.
    pub fn new(json: bool, wide: bool, no_header: bool) -> Self {
        Self {
            json: json || (!is_tty() && !no_header && !wide),
            explicit_json: json,
            wide,
            no_header,
        }
    }
}

pub fn success(data: Value) -> Value {
    json!({ "status": Status::Success as i32, "data": data })
}

pub fn failure(error: &Error) -> Value {
    json!({
        "status": error.status(),
        "error": { "code": error.code(), "message": error.message() },
    })
}

pub fn print_json(value: &Value) {
    println!("{}", serde_json::to_string(value).unwrap_or_default());
}

pub fn print_json_err(value: &Value) {
    eprintln!("{}", serde_json::to_string(value).unwrap_or_default());
}

pub fn use_json(flag: bool) -> bool {
    flag || !is_tty()
}

/// A label and value block, used by `get`.
pub fn print_block(rows: &[(&str, String)]) {
    let width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);
    for (label, value) in rows {
        println!("{label:<width$}  {value}");
    }
}

/// A key and value block, used by `status`.
pub fn print_kv(rows: &[(&str, String)]) {
    print_block(rows);
}

pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    print_table_opts(headers, rows, false, false);
}

pub fn print_table_opts(headers: &[&str], rows: &[Vec<String>], no_header: bool, wide: bool) {
    let columns = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate().take(columns) {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }

    if !wide {
        shrink(&mut widths, terminal_width());
    }

    let line = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .take(columns)
            .map(|(index, cell)| pad(cell, widths[index]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };

    if !no_header {
        println!(
            "{}",
            line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>())
        );
        println!(
            "{}",
            widths
                .iter()
                .map(|width| "-".repeat(*width))
                .collect::<Vec<_>>()
                .join("  ")
        );
    }
    for row in rows {
        println!("{}", line(row));
    }
}

/// Shrink the widest columns until the table fits, keeping at least eight
/// characters per column.
fn shrink(widths: &mut [usize], width: usize) {
    let gaps = widths.len().saturating_sub(1) * 2;
    let mut total = widths.iter().sum::<usize>() + gaps;
    while total > width {
        let Some((index, _)) = widths
            .iter()
            .enumerate()
            .filter(|(_, value)| **value > 8)
            .max_by_key(|(_, value)| **value)
        else {
            break;
        };
        widths[index] -= 1;
        total -= 1;
    }
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|width| *width >= 40)
        .unwrap_or(100)
}

fn pad(value: &str, width: usize) -> String {
    let value = truncate(value, width);
    let length = value.chars().count();
    if length >= width {
        value
    } else {
        format!("{value}{}", " ".repeat(width - length))
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out: String = value.chars().take(width - 1).collect();
    out.push('…');
    out
}

pub fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}
