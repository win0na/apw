//! Row data and text fitting for the page painter.

/// Fits `text` into `width` cells, ending with an ellipsis when it is cut.
pub fn truncate(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    while out.ends_with(' ') {
        out.pop();
    }
    out.push('…');
    out
}

/// One row painted by the page.
#[derive(Clone)]
pub enum Line {
    /// A spacer row.
    Blank,
    /// A group heading, bold and muted.
    Heading(String),
    /// A list item: rail, title, inline description, right metadata.
    Item {
        title: String,
        description: String,
        right: String,
    },
}

impl Line {
    pub fn item(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self::Item {
            title: title.into(),
            description: description.into(),
            right: String::new(),
        }
    }

    pub fn with_right(mut self, right: impl Into<String>) -> Self {
        if let Self::Item { right: slot, .. } = &mut self {
            *slot = right.into();
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncation_fits_and_marks_the_cut() {
        assert_eq!(truncate("alpha", 8), "alpha");
        assert_eq!(truncate("alphabet", 6), "alpha…");
        assert_eq!(truncate("alphabet", 1), "…");
        assert_eq!(truncate("alphabet", 0), "");
        assert_eq!(truncate("ab ", 2), "a…");
    }
}
