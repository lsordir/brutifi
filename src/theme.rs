/*!
 * Custom theme for the BrutiFi application.
 *
 * A cohesive, modern dark theme built around a cyan accent. Provides a small
 * design system: surface elevations, a cyan accent ramp, and reusable widget
 * styles (cards, buttons, badges, inputs) used across every screen.
 */

use iced::widget::{button, container, pick_list, text_input};
use iced::{Background, Border, Color, Shadow, Theme, Vector};

/// Custom color palette (modern dark "control-room" aesthetic).
pub mod colors {
    use iced::Color;

    /// Build a color from 0-255 RGB components.
    const fn rgb8(r: u8, g: u8, b: u8) -> Color {
        Color::from_rgb(r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0)
    }

    // --- Accent ramp (cyan) ---
    pub const PRIMARY: Color = rgb8(0x06, 0xB6, 0xD4); // cyan-500
    pub const PRIMARY_HOVER: Color = rgb8(0x22, 0xD3, 0xEE); // cyan-400
    pub const PRIMARY_SOFT: Color = rgb8(0x0E, 0x74, 0x90); // deep cyan (pressed)
    pub const ACCENT: Color = rgb8(0x38, 0xBD, 0xF8); // sky highlight for text

    // --- Semantic ---
    pub const SECONDARY: Color = rgb8(0x60, 0xA5, 0xFA); // blue
    pub const DANGER: Color = rgb8(0xF8, 0x71, 0x71); // red-400
    pub const DANGER_DEEP: Color = rgb8(0xDC, 0x26, 0x26); // red-600
    pub const WARNING: Color = rgb8(0xFB, 0xBF, 0x24); // amber-400
    pub const SUCCESS: Color = rgb8(0x34, 0xD3, 0x99); // emerald-400

    // --- Surfaces (low -> high elevation) ---
    pub const BACKGROUND: Color = rgb8(0x0B, 0x0F, 0x16); // app canvas
    pub const SURFACE: Color = rgb8(0x14, 0x19, 0x22); // cards
    pub const SURFACE_RAISED: Color = rgb8(0x1A, 0x20, 0x2B); // header / inputs
    pub const SURFACE_HOVER: Color = rgb8(0x22, 0x2A, 0x38); // hover

    // --- Text ---
    pub const TEXT: Color = rgb8(0xE8, 0xEC, 0xF2);
    pub const TEXT_DIM: Color = rgb8(0x8B, 0x95, 0xA7);
    pub const TEXT_FAINT: Color = rgb8(0x5B, 0x64, 0x74);

    // --- Lines ---
    pub const BORDER: Color = rgb8(0x27, 0x2E, 0x3C);
    pub const BORDER_STRONG: Color = rgb8(0x35, 0x3E, 0x4F);

    /// Same color at a given alpha.
    pub const fn with_alpha(c: Color, a: f32) -> Color {
        Color { a, ..c }
    }
}

// --- Containers ---------------------------------------------------------

/// Elevated card container with a soft shadow.
pub fn card_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::SURFACE)),
        text_color: Some(colors::TEXT),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 12.0.into(),
        },
        shadow: Shadow {
            color: colors::with_alpha(Color::BLACK, 0.35),
            offset: Vector::new(0.0, 6.0),
            blur_radius: 18.0,
        },
    }
}

/// Flat panel (no shadow) for grouping inside cards.
pub fn panel_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::with_alpha(
            colors::SURFACE_RAISED,
            0.6,
        ))),
        text_color: Some(colors::TEXT),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 10.0.into(),
        },
        ..Default::default()
    }
}

/// App header bar.
pub fn header_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::SURFACE_RAISED)),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A tinted "info / callout" box. Pass an accent color.
pub fn callout_style(accent: Color) -> impl Fn(&Theme) -> container::Style {
    move |_: &Theme| container::Style {
        background: Some(Background::Color(colors::with_alpha(accent, 0.12))),
        text_color: Some(colors::TEXT),
        border: Border {
            color: colors::with_alpha(accent, 0.55),
            width: 1.0,
            radius: 10.0.into(),
        },
        ..Default::default()
    }
}

/// Pill / badge background.
pub fn badge_style(accent: Color) -> impl Fn(&Theme) -> container::Style {
    move |_: &Theme| container::Style {
        background: Some(Background::Color(colors::with_alpha(accent, 0.16))),
        text_color: Some(accent),
        border: Border {
            color: colors::with_alpha(accent, 0.45),
            width: 1.0,
            radius: 999.0.into(),
        },
        ..Default::default()
    }
}

/// Network list item (normal).
pub fn network_item_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::SURFACE_RAISED)),
        text_color: Some(colors::TEXT),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 10.0.into(),
        },
        ..Default::default()
    }
}

/// Network list item (selected).
pub fn network_item_selected_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::with_alpha(colors::PRIMARY, 0.14))),
        text_color: Some(colors::TEXT),
        border: Border {
            color: colors::PRIMARY,
            width: 1.5,
            radius: 10.0.into(),
        },
        shadow: Shadow {
            color: colors::with_alpha(colors::PRIMARY, 0.25),
            offset: Vector::new(0.0, 0.0),
            blur_radius: 10.0,
        },
    }
}

// --- Buttons ------------------------------------------------------------

/// Primary (accent) button.
pub fn primary_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg, shadow) = match status {
        button::Status::Hovered => (
            colors::PRIMARY_HOVER,
            colors::with_alpha(colors::PRIMARY, 0.45),
        ),
        button::Status::Pressed => (colors::PRIMARY_SOFT, colors::with_alpha(Color::BLACK, 0.3)),
        button::Status::Disabled => (colors::with_alpha(colors::PRIMARY, 0.3), Color::TRANSPARENT),
        _ => (colors::PRIMARY, colors::with_alpha(colors::PRIMARY, 0.3)),
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: rgb_ink(),
        border: Border {
            radius: 9.0.into(),
            ..Default::default()
        },
        shadow: Shadow {
            color: shadow,
            offset: Vector::new(0.0, 3.0),
            blur_radius: 12.0,
        },
    }
}

/// Secondary (outlined) button.
pub fn secondary_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg, border_color, text_color) = match status {
        button::Status::Hovered => (colors::SURFACE_HOVER, colors::PRIMARY, colors::TEXT),
        button::Status::Pressed => (colors::SURFACE, colors::PRIMARY_SOFT, colors::TEXT),
        button::Status::Disabled => (colors::SURFACE, colors::BORDER, colors::TEXT_FAINT),
        _ => (colors::SURFACE_RAISED, colors::BORDER_STRONG, colors::TEXT),
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color,
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 9.0.into(),
        },
        ..Default::default()
    }
}

/// Danger button.
pub fn danger_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => colors::DANGER,
        button::Status::Pressed => colors::DANGER_DEEP,
        button::Status::Disabled => colors::with_alpha(colors::DANGER, 0.3),
        _ => colors::DANGER_DEEP,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: Color::WHITE,
        border: Border {
            radius: 9.0.into(),
            ..Default::default()
        },
        shadow: Shadow {
            color: colors::with_alpha(colors::DANGER_DEEP, 0.35),
            offset: Vector::new(0.0, 3.0),
            blur_radius: 12.0,
        },
    }
}

// --- Inputs -------------------------------------------------------------

/// Text input styling.
pub fn text_input_style(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let border_color = match status {
        text_input::Status::Focused => colors::PRIMARY,
        text_input::Status::Hovered => colors::BORDER_STRONG,
        _ => colors::BORDER,
    };
    text_input::Style {
        background: Background::Color(colors::SURFACE_RAISED),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 9.0.into(),
        },
        icon: colors::TEXT_DIM,
        placeholder: colors::TEXT_FAINT,
        value: colors::TEXT,
        selection: colors::with_alpha(colors::PRIMARY, 0.4),
    }
}

/// Pick-list (dropdown) styling.
pub fn pick_list_style(_theme: &Theme, status: pick_list::Status) -> pick_list::Style {
    let border_color = match status {
        pick_list::Status::Hovered | pick_list::Status::Opened => colors::PRIMARY,
        _ => colors::BORDER,
    };
    pick_list::Style {
        text_color: colors::TEXT,
        placeholder_color: colors::TEXT_FAINT,
        handle_color: colors::TEXT_DIM,
        background: Background::Color(colors::SURFACE_RAISED),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 9.0.into(),
        },
    }
}

/// Ink color for text on accent buttons (dark for contrast on cyan).
fn rgb_ink() -> Color {
    colors::BACKGROUND
}
