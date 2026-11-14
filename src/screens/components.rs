/*!
 * Reusable UI components.
 *
 * Small, composable building blocks shared by every screen so the look stays
 * consistent and the per-screen `view` code stays declarative. Everything here
 * is theme-driven (see [`crate::theme`]).
 */

use iced::widget::{column, container, row, scrollable, text, Column};
use iced::{Color, Element, Length};

use crate::messages::Message;
use crate::theme::{self, colors};

/// Page title + subtitle block.
pub fn page_header(title: &str, subtitle: &str) -> Element<'static, Message> {
    column![
        text(title.to_string()).size(26).color(colors::TEXT),
        text(subtitle.to_string()).size(13).color(colors::TEXT_DIM),
    ]
    .spacing(4)
    .into()
}

/// A section heading used inside cards.
pub fn section_title(title: &str) -> Element<'static, Message> {
    text(title.to_string()).size(14).color(colors::TEXT).into()
}

/// A dimmed field label paired with a form control (label stacked above).
pub fn field_label(label: &str) -> Element<'static, Message> {
    text(label.to_string()).size(13).color(colors::TEXT).into()
}

/// A rounded, colored pill/badge.
pub fn pill(label: &str, color: Color) -> Element<'static, Message> {
    container(text(label.to_string()).size(9).color(color))
        .padding([3, 8])
        .style(theme::badge_style(color))
        .into()
}

/// A `Label   value` row with a fixed-width label column for tidy alignment.
pub fn labeled_value(label: &str, value: &str, value_color: Color) -> Element<'static, Message> {
    row![
        text(label.to_string())
            .size(11)
            .color(colors::TEXT_DIM)
            .width(Length::Fixed(84.0)),
        text(value.to_string()).size(12).color(value_color),
    ]
    .spacing(8)
    .into()
}

/// A tinted callout box with an accent color, title and body lines.
pub fn callout(accent: Color, title: &str, lines: &[&str]) -> Element<'static, Message> {
    let mut col = Column::new()
        .spacing(4)
        .push(text(title.to_string()).size(12).color(accent));
    for line in lines {
        col = col.push(text(line.to_string()).size(10).color(colors::TEXT_DIM));
    }
    container(col)
        .padding(12)
        .width(Length::Fill)
        .style(theme::callout_style(accent))
        .into()
}

/// A danger-tinted error banner.
pub fn error_banner(msg: &str) -> Element<'static, Message> {
    container(text(format!("⚠  {}", msg)).size(11).color(colors::DANGER))
        .padding(12)
        .width(Length::Fill)
        .style(theme::callout_style(colors::DANGER))
        .into()
}

/// A scrollable activity-log card. Renders nothing when there are no messages.
pub fn log_panel(messages: &[String]) -> Option<Element<'static, Message>> {
    if messages.is_empty() {
        return None;
    }
    Some(
        container(
            column![
                text("Activity Log").size(12).color(colors::TEXT_DIM),
                scrollable(
                    container(text(messages.join("\n")).size(11).color(colors::TEXT_DIM),)
                        .padding(10)
                        .width(Length::Fill)
                        .style(theme::panel_style),
                )
                .height(Length::Fixed(150.0)),
            ]
            .spacing(8)
            .padding(14),
        )
        .width(Length::Fill)
        .style(theme::card_style)
        .into(),
    )
}

/// Wrap arbitrary content in a standard elevated card.
pub fn card<'a>(body: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(body)
        .padding(14)
        .width(Length::Fill)
        .style(theme::card_style)
        .into()
}
