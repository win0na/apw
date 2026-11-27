//! The color math opencode's System theme uses: sRGB, OKLCH, contrast, and
//! interpolation. Ported from `packages/theme/src/tui/color.ts` and the
//! helpers in `v1-migrate.ts`; the formulas are kept verbatim so a generated
//! palette matches opencode cell for cell.

/// An eight-bit sRGB color with alpha, the unit the theme system works in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Rgba {
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self::new(r, g, b, 255)
    }

    pub const fn opaque(self) -> bool {
        self.a > 0
    }

    /// The red, green, and blue channels as 0..1 floats.
    pub fn floats(self) -> [f64; 3] {
        [
            f64::from(self.r) / 255.0,
            f64::from(self.g) / 255.0,
            f64::from(self.b) / 255.0,
        ]
    }
}

/// A color in OKLCH: lightness 0..1, chroma, and hue in degrees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Oklch {
    pub l: f64,
    pub c: f64,
    pub h: f64,
}

fn clamp(value: f64, min: f64, max: f64) -> f64 {
    value.max(min).min(max)
}

fn hue(value: f64) -> f64 {
    value.rem_euclid(360.0)
}

fn linear_to_srgb(value: f64) -> f64 {
    if value <= 0.003_130_8 {
        value * 12.92
    } else {
        1.055 * value.powf(1.0 / 2.4) - 0.055
    }
}

fn srgb_to_linear(value: f64) -> f64 {
    if value <= 0.040_45 {
        value / 12.92
    } else {
        ((value + 0.055) / 1.055).powf(2.4)
    }
}

pub fn rgb_to_oklch(red: f64, green: f64, blue: f64) -> Oklch {
    let lr = srgb_to_linear(red);
    let lg = srgb_to_linear(green);
    let lb = srgb_to_linear(blue);
    let l_root = (0.412_221_470_8 * lr + 0.536_332_536_3 * lg + 0.051_445_992_9 * lb).cbrt();
    let m_root = (0.211_903_498_2 * lr + 0.680_699_545_1 * lg + 0.107_396_956_6 * lb).cbrt();
    let s_root = (0.088_302_461_9 * lr + 0.281_718_837_6 * lg + 0.629_978_700_5 * lb).cbrt();
    let lightness = 0.210_454_255_3 * l_root + 0.793_617_785 * m_root - 0.004_072_046_8 * s_root;
    let a = 1.977_998_495_1 * l_root - 2.428_592_205 * m_root + 0.450_593_709_9 * s_root;
    let b = 0.025_904_037_1 * l_root + 0.782_771_766_2 * m_root - 0.808_675_766 * s_root;
    let chroma = (a * a + b * b).sqrt();
    let angle = b.atan2(a) * (180.0 / std::f64::consts::PI);
    Oklch {
        l: lightness,
        c: chroma,
        h: if angle < 0.0 { angle + 360.0 } else { angle },
    }
}

fn oklch_to_srgb(color: Oklch) -> [f64; 3] {
    let a = color.c * (color.h * std::f64::consts::PI / 180.0).cos();
    let b = color.c * (color.h * std::f64::consts::PI / 180.0).sin();
    let l_root = color.l + 0.396_337_777_4 * a + 0.215_803_757_3 * b;
    let m_root = color.l - 0.105_561_345_8 * a - 0.063_854_172_8 * b;
    let s_root = color.l - 0.089_484_177_5 * a - 1.291_485_548 * b;
    let l = l_root * l_root * l_root;
    let m = m_root * m_root * m_root;
    let s = s_root * s_root * s_root;
    [
        linear_to_srgb(4.076_741_662_1 * l - 3.307_711_591_3 * m + 0.230_969_929_2 * s),
        linear_to_srgb(-1.268_438_004_6 * l + 2.609_757_401_1 * m - 0.341_319_396_5 * s),
        linear_to_srgb(-0.004_196_086_3 * l - 0.703_418_614_7 * m + 1.707_614_701 * s),
    ]
}

fn in_gamut(rgb: [f64; 3]) -> bool {
    rgb.iter().all(|channel| (0.0..=1.0).contains(channel))
}

fn fit_oklch(color: Oklch) -> Oklch {
    let base = Oklch {
        l: clamp(color.l, 0.0, 1.0),
        c: color.c.max(0.0),
        h: hue(color.h),
    };
    if in_gamut(oklch_to_srgb(base)) {
        return base;
    }
    for index in 0..24 {
        let next = Oklch {
            c: base.c * 0.9_f64.powi(index + 1),
            ..base
        };
        if in_gamut(oklch_to_srgb(next)) {
            return next;
        }
    }
    Oklch { c: 0.0, ..base }
}

/// Rounds the fitted color to eight-bit sRGB, as `oklchToHex` does.
pub fn oklch_to_rgba(color: Oklch) -> Rgba {
    let rgb = oklch_to_srgb(fit_oklch(color));
    let byte = |value: f64| (clamp(value, 0.0, 1.0) * 255.0).round() as u8;
    Rgba::rgb(byte(rgb[0]), byte(rgb[1]), byte(rgb[2]))
}

pub fn to_oklch(color: Rgba) -> Oklch {
    let [r, g, b] = color.floats();
    rgb_to_oklch(r, g, b)
}

/// Interpolates in OKLCH, taking the hue from the chromatic side.
pub fn mix(start: Oklch, end: Oklch, amount: f64) -> Oklch {
    let start_hue = if start.c > 0.002 { start.h } else { end.h };
    let end_hue = if end.c > 0.002 { end.h } else { start_hue };
    let delta = (((end_hue - start_hue) % 360.0) + 540.0) % 360.0 - 180.0;
    Oklch {
        l: start.l + (end.l - start.l) * amount,
        c: start.c + (end.c - start.c) * amount,
        h: start_hue + delta * amount,
    }
}

/// WCAG contrast of two eight-bit colors.
pub fn contrast(first: Rgba, second: Rgba) -> f64 {
    fn luminance(color: Rgba) -> f64 {
        fn channel(value: f64) -> f64 {
            if value <= 0.040_45 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * channel(f64::from(color.r) / 255.0)
            + 0.7152 * channel(f64::from(color.g) / 255.0)
            + 0.0722 * channel(f64::from(color.b) / 255.0)
    }
    let (lighter, darker) = {
        let (a, b) = (luminance(first), luminance(second));
        if a >= b {
            (a, b)
        } else {
            (b, a)
        }
    };
    (lighter + 0.05) / (darker + 0.05)
}

/// Blends `overlay` into `base` in sRGB, as `tint` does.
pub fn tint(base: Rgba, overlay: Rgba, alpha: f64) -> Rgba {
    let blend = |from: u8, to: u8| {
        let value =
            f64::from(from) / 255.0 + (f64::from(to) / 255.0 - f64::from(from) / 255.0) * alpha;
        (value * 255.0).round() as u8
    };
    Rgba::rgb(
        blend(base.r, overlay.r),
        blend(base.g, overlay.g),
        blend(base.b, overlay.b),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb(hex: &str) -> Rgba {
        Rgba::rgb(
            u8::from_str_radix(&hex[0..2], 16).unwrap(),
            u8::from_str_radix(&hex[2..4], 16).unwrap(),
            u8::from_str_radix(&hex[4..6], 16).unwrap(),
        )
    }

    #[test]
    fn oklch_round_trips_the_page_color() {
        let color = rgb("2e2d47");
        assert_eq!(oklch_to_rgba(to_oklch(color)), color);
    }

    #[test]
    fn contrast_matches_the_wcag_order() {
        assert!(contrast(rgb("ffffff"), rgb("000000")) > 20.0);
        assert!((contrast(rgb("ffffff"), rgb("ffffff")) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn tint_moves_quarter_way_to_the_overlay() {
        assert_eq!(tint(rgb("000000"), rgb("ffffff"), 0.25), rgb("404040"));
    }
}
