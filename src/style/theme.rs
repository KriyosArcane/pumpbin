use iced::theme::{Palette, Custom};
use iced::{Color, Theme};

/// PumpBin dark theme
/// Professional cybersecurity tool aesthetic
pub fn modern_dark_theme() -> Theme {
    Theme::custom(
        "PumpBin Dark".to_string(),
        Palette {
            background: Color::from_rgb8(28, 30, 35),      // Background (#1c1e23)
            text: Color::from_rgb8(206, 206, 206),        // Text (#cecece)
            primary: Color::from_rgb8(0, 173, 239),       // PumpBin accent blue (#00ADEF)
            success: Color::from_rgb8(0, 229, 157),       // Teal/green (#00E59D)
            danger: Color::from_rgb8(255, 82, 96),        // Coral red (#FF5260)
        },
    )
}

/// Keep the old theme for backward compatibility if needed
pub fn tactical_theme() -> Theme {
    Theme::custom(
        "Industrial Brutalism".to_string(),
        Palette {
            background: Color::from_rgb8(0, 0, 0),        // Absolute Black
            text: Color::from_rgb8(255, 255, 255),        // Stark White
            primary: Color::from_rgb8(229, 255, 0),       // Acid Yellow (#E5FF00)
            success: Color::from_rgb8(255, 69, 0),        // Safety Orange (#FF4500)
            danger: Color::from_rgb8(255, 0, 0),          // Absolute Red (#FF0000)
        },
    )
}
