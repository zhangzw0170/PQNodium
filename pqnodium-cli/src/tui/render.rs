use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};

// ── Color Palette ──────────────────────────────────────────────────────

pub mod palette {
    use ratatui::style::Color;

    pub const BG: Color = Color::Rgb(18, 18, 26);
    pub const BORDER: Color = Color::Rgb(60, 60, 90);
    pub const BORDER_BRIGHT: Color = Color::Rgb(100, 100, 140);

    pub const TEXT: Color = Color::Rgb(210, 210, 230);
    pub const TEXT_DIM: Color = Color::Rgb(110, 110, 140);
    pub const TEXT_MUTED: Color = Color::Rgb(75, 75, 100);

    pub const ACCENT: Color = Color::Rgb(120, 160, 255);
    pub const GREEN: Color = Color::Rgb(80, 220, 160);
    pub const YELLOW: Color = Color::Rgb(255, 200, 80);
    pub const RED: Color = Color::Rgb(255, 100, 100);
    pub const PURPLE: Color = Color::Rgb(180, 140, 255);

    pub const INPUT_BG: Color = Color::Rgb(26, 26, 38);
    pub const STATUS_BG: Color = Color::Rgb(22, 22, 34);
}

// ── Log types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum LogLevel {
    Info,
    Success,
    Warn,
    Error,
}

impl LogLevel {
    pub fn icon(&self) -> &'static str {
        match self {
            LogLevel::Info => "●",
            LogLevel::Success => "✓",
            LogLevel::Warn => "⚠",
            LogLevel::Error => "✗",
        }
    }

    pub fn icon_color(&self) -> Color {
        match self {
            LogLevel::Info => palette::ACCENT,
            LogLevel::Success => palette::GREEN,
            LogLevel::Warn => palette::YELLOW,
            LogLevel::Error => palette::RED,
        }
    }

    pub fn text_style(&self) -> Style {
        match self {
            LogLevel::Info => Style::default().fg(palette::TEXT),
            LogLevel::Success => Style::default().fg(palette::GREEN),
            LogLevel::Warn => Style::default().fg(palette::YELLOW),
            LogLevel::Error => Style::default()
                .fg(palette::RED)
                .add_modifier(Modifier::BOLD),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub text: String,
    pub level: LogLevel,
}

impl LogEntry {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            timestamp: now_timestamp(),
            text: text.into(),
            level: LogLevel::Info,
        }
    }

    pub fn success(text: impl Into<String>) -> Self {
        Self {
            timestamp: now_timestamp(),
            text: text.into(),
            level: LogLevel::Success,
        }
    }

    pub fn warn(text: impl Into<String>) -> Self {
        Self {
            timestamp: now_timestamp(),
            text: text.into(),
            level: LogLevel::Warn,
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            timestamp: now_timestamp(),
            text: text.into(),
            level: LogLevel::Error,
        }
    }

    pub fn to_line(&self) -> Line<'static> {
        Line::from(vec![
            Span::styled(
                format!(" {} ", self.timestamp),
                Style::default().fg(palette::TEXT_MUTED),
            ),
            Span::styled(
                format!("{} ", self.level.icon()),
                Style::default().fg(self.level.icon_color()),
            ),
            Span::styled(self.text.clone(), self.level.text_style()),
        ])
    }
}

fn now_timestamp() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() % 86400;
    let h = (secs / 3600) as u8;
    let m = ((secs % 3600) / 60) as u8;
    let s = (secs % 60) as u8;
    format!("{h:02}:{m:02}:{s:02}")
}

// ── Render functions ───────────────────────────────────────────────────

use super::AppState;

pub(super) fn render(frame: &mut ratatui::Frame, state: &mut AppState) {
    let [status_area, log_area, input_area] = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(1),
        ratatui::layout::Constraint::Fill(1),
        ratatui::layout::Constraint::Length(3),
    ])
    .areas(frame.area());

    render_status_bar(frame, status_area, state);
    render_log_panel(frame, log_area, state);
    render_input_panel(frame, input_area, state);
}

fn render_status_bar(frame: &mut ratatui::Frame, area: Rect, state: &AppState) {
    let nat_text = match state.nat_public {
        Some(true) => Span::styled(" NAT: Public ", Style::default().fg(palette::GREEN)),
        Some(false) => Span::styled(" NAT: Private ", Style::default().fg(palette::YELLOW)),
        None => Span::styled(" NAT: Unknown ", Style::default().fg(palette::TEXT_DIM)),
    };

    let conn_color = if state.connected_count > 0 {
        palette::GREEN
    } else {
        palette::TEXT_DIM
    };
    let conn_icon = if state.connected_count > 0 {
        "◉"
    } else {
        "○"
    };

    let title = Line::from(vec![
        Span::styled(
            " PQNodium ",
            Style::default()
                .fg(palette::PURPLE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(palette::TEXT_MUTED)),
        Span::styled(
            &state.peer_id_display,
            Style::default().fg(palette::TEXT_DIM),
        ),
        Span::styled(" │ ", Style::default().fg(palette::TEXT_MUTED)),
        Span::styled(
            format!(" {conn_icon} {} connected ", state.connected_count),
            Style::default().fg(conn_color),
        ),
        Span::styled("│", Style::default().fg(palette::TEXT_MUTED)),
        nat_text,
    ]);

    let status_bar = Paragraph::new(title).style(Style::default().bg(palette::STATUS_BG));
    frame.render_widget(status_bar, area);
}

fn render_log_panel(frame: &mut ratatui::Frame, area: Rect, state: &mut AppState) {
    let log_lines: Vec<Line<'_>> = state.logs.iter().map(|e| e.to_line()).collect();
    let log_content_height = log_lines.len() as u16;
    let visible_height = area.height.saturating_sub(2);

    let max_scroll = log_content_height.saturating_sub(visible_height);
    if state.scroll_offset >= max_scroll {
        state.scroll_offset = max_scroll;
        state.auto_scroll = true;
    }

    let log = Paragraph::new(log_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(palette::BORDER))
                .style(Style::default().bg(palette::BG)),
        )
        .wrap(Wrap { trim: false })
        .scroll((state.scroll_offset, 0));

    frame.render_widget(log, area);
}

fn render_input_panel(frame: &mut ratatui::Frame, area: Rect, state: &AppState) {
    use ratatui::layout::Position;

    let input_display = format!(" {}", state.input);
    let input = Paragraph::new(input_display)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(palette::BORDER_BRIGHT))
                .title(Line::from(vec![
                    Span::styled(
                        " > ",
                        Style::default()
                            .fg(palette::ACCENT)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "Enter command or message",
                        Style::default().fg(palette::TEXT_DIM),
                    ),
                ]))
                .style(Style::default().bg(palette::INPUT_BG)),
        )
        .style(Style::default().fg(palette::TEXT))
        .scroll((0, (state.input_cursor + 1) as u16));

    frame.render_widget(input, area);

    let cursor_x = (state.input_cursor + 2) as u16;
    let cursor_y = area.y + 1;
    frame.set_cursor_position(Position::new(
        cursor_x.min(area.x + area.width.saturating_sub(2)),
        cursor_y,
    ));
}
