use serde_json::{json, Value};

use crate::error::Error;
use crate::model::Status;

pub fn success(results: Value) -> Value {
    json!({ "results": results, "status": Status::Success as i32 })
}

pub fn failure(error: &Error) -> Value {
    json!({
        "error": error.message(),
        "status": error.status(),
        "results": [],
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

pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index < widths.len() {
                widths[index] = widths[index].max(cell.chars().count());
            }
        }
    }

    let line = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| pad(cell, widths.get(index).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };

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
    for row in rows {
        println!("{}", line(row));
    }
}

fn pad(value: &str, width: usize) -> String {
    let length = value.chars().count();
    if length >= width {
        value.to_string()
    } else {
        format!("{value}{}", " ".repeat(width - length))
    }
}

pub fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}
