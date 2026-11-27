//! The System palette: opencode's terminal-derived theme, ported from
//! `packages/tui/src/theme/system.ts` and
//! `packages/theme/src/tui/v1-migrate-new-designs.ts`.
//!
//! The terminal's sixteen colors are seeds. The page is the terminal
//! background, the neutral ramp is built from it, and each accent is laid out
//! on the same OKLCH step profile. Values are not hand-picked; they are
//! recomputed for whatever palette the terminal reports.

use opentui::prelude::Color;
use opentui::term::TerminalPalette;

use super::oklch::Oklch;
use super::oklch::{contrast, mix, oklch_to_rgba, tint, to_oklch, Rgba};

/// Dark or light, from the background.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Dark,
    Light,
}

/// The colors the interface uses, by role.
#[derive(Clone, Copy, Debug)]
pub struct Tokens {
    pub mode: Mode,
    /// The terminal background; transparent so the terminal shows through.
    pub page: Color,
    /// Panels, the prompt surface, and toasts.
    pub panel: Color,
    /// Hover fills and the dialog footer band.
    pub hover: Color,
    /// The highest surface step.
    pub max: Color,
    /// A selected row, and the rail while focused.
    pub selected: Color,
    pub selected_text: Color,
    /// The secondary column of a selected row.
    pub selected_meta: Color,
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    /// The structural left rail and rules.
    pub rail: Color,
    pub scrollbar: Color,
    pub formfield: Color,
    pub error: Color,
    pub warning: Color,
    pub success: Color,
    pub info: Color,
    pub destructive: Color,
    /// The flat dialog surface.
    pub dialog: Color,
    /// The wordmark shadow.
    pub shadow: Color,
}

const STEPS: [usize; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];

struct Profile {
    surface: [f64; 10],
    text: [f64; 10],
    hue_lightness: [f64; 10],
    hue_chroma: [f64; 10],
    hue_mid: f64,
    readable: [f64; 10],
    readable_hue: [f64; 10],
}

const DARK: Profile = Profile {
    surface: [0.0, 0.0, 0.0, 0.0, 0.253, 0.175, 0.11, 0.057, 0.039, 0.0],
    text: [0.0, 0.0, 0.719, 0.538, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    hue_lightness: [
        0.0, -0.035, -0.023, -0.003, 0.0, 0.0, 0.095, 0.071, 0.024, 0.012,
    ],
    hue_chroma: [0.0, 0.1, 0.24, 0.22, 0.0, 0.64, 0.2, 0.14, 0.09, 0.07],
    hue_mid: 0.55,
    readable: [0.0, 0.0, 0.0, 0.0, 0.0, 0.66, 0.81, 0.92, 0.95, 0.99],
    readable_hue: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7, 0.82, 0.92, 0.99],
};

const LIGHT: Profile = Profile {
    surface: [
        0.0, 0.0, 0.0, 0.0, -0.227, -0.145, -0.102, -0.039, -0.015, 0.0,
    ],
    text: [0.0, 0.0, 0.688, 0.484, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    hue_lightness: [
        0.0, 0.083, 0.13, 0.116, 0.0, 0.0, 0.021, -0.002, -0.004, -0.008,
    ],
    hue_chroma: [0.0, 0.19, 0.12, 0.16, 0.0, 0.38, 0.17, 0.1, 0.05, 0.02],
    hue_mid: 0.65,
    readable: [0.0, 0.0, 0.0, 0.0, 0.0, 0.64, 0.74, 0.89, 0.96, 0.97],
    readable_hue: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.78, 0.88, 0.93, 0.97],
};

/// The xterm colors `ansiToRgba` falls back to when the terminal does not
/// report a slot.
const ANSI: [Rgba; 16] = [
    Rgba::rgb(0x00, 0x00, 0x00),
    Rgba::rgb(0x80, 0x00, 0x00),
    Rgba::rgb(0x00, 0x80, 0x00),
    Rgba::rgb(0x80, 0x80, 0x00),
    Rgba::rgb(0x00, 0x00, 0x80),
    Rgba::rgb(0x80, 0x00, 0x80),
    Rgba::rgb(0x00, 0x80, 0x80),
    Rgba::rgb(0xc0, 0xc0, 0xc0),
    Rgba::rgb(0x80, 0x80, 0x80),
    Rgba::rgb(0xff, 0x00, 0x00),
    Rgba::rgb(0x00, 0xff, 0x00),
    Rgba::rgb(0xff, 0xff, 0x00),
    Rgba::rgb(0x00, 0x00, 0xff),
    Rgba::rgb(0xff, 0x00, 0xff),
    Rgba::rgb(0x00, 0xff, 0xff),
    Rgba::rgb(0xff, 0xff, 0xff),
];

struct Seeds {
    mode: Mode,
    /// The terminal background, opaque, for the ramps.
    page: Rgba,
    /// The legacy background seed. Transparent, so the terminal shows through.
    background: Rgba,
    text: Rgba,
    panel: Rgba,
    element: Rgba,
    border: Rgba,
    border_active: Rgba,
    red: Rgba,
    green: Rgba,
    yellow: Rgba,
    cyan: Rgba,
}

impl Seeds {
    fn read(palette: Option<&TerminalPalette>) -> Self {
        let slot = |index: usize| {
            palette
                .and_then(|palette| palette.colors.get(index).copied().flatten())
                .map_or(ANSI[index], |color| {
                    Rgba::new(color.r, color.g, color.b, 255)
                })
        };
        let background = palette
            .and_then(|palette| palette.background)
            .map_or(ANSI[0], |color| Rgba::new(color.r, color.g, color.b, 255));
        let text = palette
            .and_then(|palette| palette.foreground)
            .map_or(ANSI[7], |color| Rgba::new(color.r, color.g, color.b, 255));
        let mode = if luminance(background) > 0.5 {
            Mode::Light
        } else {
            Mode::Dark
        };
        let grays = gray_ramp(background, mode);
        Self {
            mode,
            page: background,
            background: Rgba::new(background.r, background.g, background.b, 0),
            text,
            panel: grays[2],
            element: grays[3],
            border: grays[7],
            border_active: grays[8],
            red: slot(1),
            green: slot(2),
            yellow: slot(3),
            cyan: slot(6),
        }
    }
}

fn luminance(color: Rgba) -> f64 {
    let [r, g, b] = color.floats();
    0.299 * r + 0.587 * g + 0.114 * b
}

fn gray_ramp(background: Rgba, mode: Mode) -> [Rgba; 13] {
    let mut grays = [background; 13];
    let [r, g, b] = background.floats();
    let light = luminance(background) * 255.0;
    for (index, gray) in grays.iter_mut().enumerate().skip(1) {
        let factor = index as f64 / 12.0;
        if mode == Mode::Dark && light < 10.0 {
            let value = (factor * 0.4 * 255.0).floor();
            *gray = Rgba::rgb(value as u8, value as u8, value as u8);
            continue;
        }
        if mode == Mode::Light && light > 245.0 {
            let value = (255.0 - factor * 0.4 * 255.0).floor();
            *gray = Rgba::rgb(value as u8, value as u8, value as u8);
            continue;
        }
        let next = if mode == Mode::Dark {
            light + (255.0 - light) * factor * 0.4
        } else {
            light * (1.0 - factor * 0.4)
        };
        let ratio = next / light;
        let channel = |value: f64| (value * ratio).clamp(0.0, 255.0).floor() as u8;
        *gray = Rgba::rgb(channel(r * 255.0), channel(g * 255.0), channel(b * 255.0));
    }
    grays
}

fn muted_text(background: Rgba, mode: Mode) -> Rgba {
    let light = luminance(background) * 255.0;
    let gray = if mode == Mode::Dark {
        if light < 10.0 {
            180.0
        } else {
            (160.0 + light * 0.3).floor().min(200.0)
        }
    } else if light > 245.0 {
        75.0
    } else {
        (100.0 - (255.0 - light) * 0.2).floor().max(60.0)
    };
    let gray = gray as u8;
    Rgba::rgb(gray, gray, gray)
}

struct Neutral {
    scale: [Rgba; 10],
    lightness: [f64; 10],
    page: Oklch,
    text: Rgba,
    page_contrast: f64,
}

fn first_opaque(colors: &[Rgba]) -> Option<Rgba> {
    colors.iter().copied().find(|color| color.opaque())
}

fn first_oklch(colors: &[Rgba]) -> Option<Oklch> {
    first_opaque(colors).map(to_oklch)
}

fn readable(neutral: &Neutral, color: Oklch, share: f64) -> Oklch {
    let target = (neutral.page_contrast * share).max(4.5_f64.min(neutral.page_contrast * 0.95));
    let passes = |amount: f64| {
        contrast(
            neutral.text,
            oklch_to_rgba(mix(color, neutral.page, amount)),
        ) >= target
    };
    if passes(0.0) {
        return color;
    }
    if !passes(0.6) {
        return mix(color, neutral.page, 0.6);
    }
    let (mut low, mut high) = (0.0, 0.6);
    for _ in 0..12 {
        let amount = (low + high) / 2.0;
        if passes(amount) {
            high = amount;
        } else {
            low = amount;
        }
    }
    mix(color, neutral.page, high)
}

impl Neutral {
    fn build(seeds: &Seeds, profile: &Profile) -> Self {
        let page_source = [(9, seeds.background), (7, seeds.panel), (6, seeds.element)];
        let reference = page_source.iter().find(|(_, color)| color.opaque());
        let page = reference.map_or_else(
            || to_oklch(Rgba::rgb(0, 0, 0)),
            |(_, color)| to_oklch(*color),
        );
        let page_lightness = page.l - reference.map_or(0.0, |(step, _)| profile.surface[*step]);

        let surface_900 = first_oklch(&[seeds.background, seeds.panel, seeds.element]);
        let surface_700 = first_oklch(&[seeds.panel, seeds.background, seeds.element]);
        let surface_600 = first_oklch(&[seeds.element, seeds.panel, seeds.background]);
        let fallback = page;
        let tints = [
            surface_900.unwrap_or(fallback),
            surface_700.unwrap_or(fallback),
            surface_600.unwrap_or(fallback),
        ];
        let text = to_oklch(seeds.text);
        let page_color = Oklch {
            l: page_lightness,
            ..tints[0]
        };
        let page_contrast = contrast(seeds.text, oklch_to_rgba(page_color));

        let mut scale = [seeds.background; 10];
        let mut lightness = [0.0; 10];
        let mut planned = [0.0; 10];
        let mut partial = Neutral {
            scale,
            lightness,
            page: page_color,
            text: seeds.text,
            page_contrast,
        };

        for step in [8, 7, 6, 5, 4] {
            let tint = match step {
                8 | 7 => tints[1],
                _ => tints[2],
            };
            let generated = Oklch {
                l: page_lightness + profile.surface[step],
                ..tint
            };
            let color = if step == 4 {
                generated
            } else {
                readable(&partial, generated, profile.readable[step])
            };
            planned[step] = generated.l;
            lightness[step] = color.l;
            scale[step] = oklch_to_rgba(color);
        }
        lightness[9] = page_lightness;
        scale[9] = seeds.background;
        if !seeds.panel.opaque() {
            scale[8] = seeds.panel;
            scale[7] = seeds.panel;
        }
        if !seeds.element.opaque() {
            scale[6] = seeds.element;
        }
        lightness[1] = text.l;
        scale[1] = seeds.text;
        for step in [2, 3] {
            let generated = mix(page_color, text, profile.text[step]);
            lightness[step] = generated.l;
            scale[step] = oklch_to_rgba(generated);
        }
        let muted = to_oklch(muted_text(seeds.page, seeds.mode));
        let muted_step = if (muted.l - lightness[2]).abs() <= (muted.l - lightness[3]).abs() {
            2
        } else {
            3
        };
        lightness[muted_step] = muted.l;
        scale[muted_step] = muted_text(seeds.page, seeds.mode);
        for step in [4, 5, 6, 7, 8] {
            lightness[step] = planned[step];
        }
        partial.scale = scale;
        partial.lightness = lightness;
        partial
    }
}

fn hue_scale(seed: Rgba, profile: &Profile, neutral: &Neutral) -> [Rgba; 10] {
    let anchor = to_oklch(seed);
    let mut scale = [seed; 10];
    let lightness = |step: usize| neutral.lightness[step] + profile.hue_lightness[step];
    for step in STEPS {
        if step == 4 {
            scale[step] = seed;
            continue;
        }
        let generated = Oklch {
            l: if step == 5 {
                anchor.l + (lightness(6) - anchor.l) * profile.hue_mid
            } else {
                lightness(step)
            },
            c: anchor.c * profile.hue_chroma[step],
            h: anchor.h,
        };
        let color = if (6..=9).contains(&step) {
            readable(neutral, generated, profile.readable_hue[step])
        } else {
            generated
        };
        scale[step] = oklch_to_rgba(color);
    }
    scale
}

fn color(value: Rgba) -> Color {
    Color::rgba(value.r, value.g, value.b, value.a)
}

impl Tokens {
    /// The System palette for a terminal, or the ANSI fallback when the
    /// terminal reported nothing usable.
    pub fn system(palette: Option<&TerminalPalette>) -> Self {
        let seeds = Seeds::read(palette);
        let profile = match seeds.mode {
            Mode::Dark => &DARK,
            Mode::Light => &LIGHT,
        };
        let neutral = Neutral::build(&seeds, profile);
        let interactive = hue_scale(seeds.cyan, profile, &neutral);
        let dialog = match seeds.mode {
            Mode::Dark => neutral.scale[7],
            Mode::Light => neutral.scale[8],
        };
        Self {
            mode: seeds.mode,
            page: Color::TRANSPARENT,
            panel: color(neutral.scale[7]),
            hover: color(neutral.scale[6]),
            max: color(neutral.scale[5]),
            selected: color(interactive[6]),
            selected_text: color(neutral.scale[1]),
            selected_meta: color(interactive[2]),
            text: color(neutral.scale[1]),
            muted: color(neutral.scale[2]),
            faint: color(neutral.scale[3]),
            rail: color(seeds.border),
            scrollbar: color(seeds.border_active),
            formfield: color(interactive[4]),
            error: color(seeds.red),
            warning: color(seeds.yellow),
            success: color(seeds.green),
            info: color(interactive[4]),
            destructive: color(seeds.red),
            dialog: color(dialog),
            shadow: color(tint(seeds.background, seeds.text, 0.25)),
        }
    }

    /// The ANSI fallback when no terminal palette is available.
    pub fn fallback() -> Self {
        Self::system(None)
    }
}

impl Default for Tokens {
    fn default() -> Self {
        Self::fallback()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentui::term::TerminalPalette;

    fn rgb(hex: &str) -> Rgba {
        Rgba::rgb(
            u8::from_str_radix(&hex[0..2], 16).unwrap(),
            u8::from_str_radix(&hex[2..4], 16).unwrap(),
            u8::from_str_radix(&hex[4..6], 16).unwrap(),
        )
    }

    fn expected(hex: &str) -> Color {
        let value = rgb(hex);
        Color::rgb(value.r, value.g, value.b)
    }

    /// Catppuccin Mocha on a `#2e2d47` page, the palette the reference
    /// screenshots came from.
    fn catppuccin() -> TerminalPalette {
        let colors = [
            "2e2d47", "f38ba8", "a6e3a1", "f9e2af", "89b4fa", "f5c2e7", "94e2d5", "cdd6f4",
            "585b70", "f38ba8", "a6e3a1", "f9e2af", "89b4fa", "f5c2e7", "94e2d5", "a6adc8",
        ];
        TerminalPalette {
            colors: colors
                .iter()
                .map(|hex| {
                    let color = rgb(hex);
                    Some(Color::rgb(color.r, color.g, color.b))
                })
                .collect(),
            foreground: Some(Color::rgb(0xcd, 0xd6, 0xf4)),
            background: Some(Color::rgb(0x2e, 0x2d, 0x47)),
            cursor: None,
        }
    }

    fn tokens(palette: &TerminalPalette) -> Tokens {
        Tokens::system(Some(palette))
    }

    #[test]
    fn dark_neutral_ramp_matches_opencode() {
        let tokens = tokens(&catppuccin());
        assert_eq!(tokens.mode, Mode::Dark);
        assert_eq!(tokens.panel, expected("323051"));
        assert_eq!(tokens.hover, expected("3a385c"));
        assert_eq!(tokens.max, expected("47456a"));
        assert_eq!(tokens.text, expected("cdd6f4"));
        assert_eq!(tokens.muted, expected("aeaeae"));
        assert_eq!(tokens.faint, expected("7d82a2"));
        assert_eq!(tokens.dialog, expected("323051"));
    }

    #[test]
    fn dark_accents_match_opencode() {
        let tokens = tokens(&catppuccin());
        assert_eq!(tokens.selected, expected("324759"));
        assert_eq!(tokens.selected_meta, expected("9baba8"));
        assert_eq!(tokens.formfield, expected("94e2d5"));
        assert_eq!(tokens.error, expected("f38ba8"));
        assert_eq!(tokens.warning, expected("f9e2af"));
        assert_eq!(tokens.success, expected("a6e3a1"));
        assert_eq!(tokens.rail, expected("5b598d"));
        assert_eq!(tokens.scrollbar, expected("626098"));
    }

    #[test]
    fn light_neutral_ramp_matches_opencode() {
        let mut palette = catppuccin();
        let page = rgb("ffffff");
        palette.background = Some(Color::rgb(page.r, page.g, page.b));
        let tokens = Tokens::system(Some(&palette));
        assert_eq!(tokens.mode, Mode::Light);
        assert_eq!(tokens.text, expected("cdd6f4"));
        assert_eq!(tokens.muted, expected("4b4b4b"));
        assert_eq!(tokens.faint, expected("e5e9f8"));
        assert_eq!(tokens.panel, expected("f6f6f6"));
        assert_eq!(tokens.hover, expected("ededed"));
        assert_eq!(tokens.max, expected("e8e8e8"));
        assert_eq!(tokens.selected, expected("edf2f1"));
        assert_eq!(tokens.selected_meta, expected("6a7170"));
        assert_eq!(tokens.dialog, expected("f7f7f7"));
    }

    #[test]
    fn a_missing_palette_still_yields_a_usable_theme() {
        let tokens = Tokens::fallback();
        assert_eq!(tokens.mode, Mode::Dark);
        assert_eq!(tokens.text, expected("c0c0c0"));
        assert_eq!(tokens.panel, expected("111111"));
        assert_ne!(tokens.page, tokens.panel);
    }
}
