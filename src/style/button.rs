use iced::{
    widget::button::{Status, Style},
    Border, Color, Theme, Background,
};

const BUTTON_RADIUS: f32 = 0.0;
const CARD_RADIUS: f32 = 0.0;

pub fn primary(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border = Border {
        width: 1.0,
        color: palette.primary.base.color,
        radius: BUTTON_RADIUS.into(),
    };

    match status {
        Status::Hovered | Status::Pressed => {
            style.background = Some(Background::Color(palette.background.weak.color));
            style.text_color = palette.background.base.text;
            style.border.color = palette.primary.base.color;
        }
        Status::Disabled => {
            style.background = None;
            style.text_color = palette.background.weak.text;
        }
        _ => {
            style.background = None;
            style.text_color = palette.primary.base.color;
        }
    }
    style
}

pub fn secondary(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border = Border {
        width: 1.0,
        color: palette.secondary.base.color,
        radius: BUTTON_RADIUS.into(),
    };

    match status {
        Status::Hovered | Status::Pressed => {
            style.background = Some(Background::Color(palette.background.weak.color));
            style.text_color = palette.secondary.base.color;
            style.border.color = palette.secondary.base.color;
        }
        _ => {
            style.background = None;
            style.text_color = palette.secondary.base.color;
        }
    }
    style
}

pub fn danger(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border = Border {
        width: 1.0,
        color: palette.danger.base.color,
        radius: BUTTON_RADIUS.into(),
    };

    match status {
        Status::Hovered | Status::Pressed => {
            style.background = Some(Background::Color(palette.background.weak.color));
            style.text_color = palette.danger.base.color;
            style.border.color = palette.danger.base.color;
        }
        Status::Disabled => {
            style.background = None;
            style.text_color = palette.background.weak.text;
        }
        _ => {
            style.background = None;
            style.text_color = palette.danger.base.color;
        }
    }
    style
}

pub fn selected(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border = Border {
        width: 1.0,
        color: palette.success.base.color,
        radius: CARD_RADIUS.into(),
    };

    match status {
        Status::Hovered | Status::Pressed => {
            style.background = Some(Background::Color(palette.background.weak.color));
            style.text_color = palette.success.base.color;
        }
        _ => {
            style.background = None;
            style.text_color = palette.success.base.color;
        }
    }
    style
}

pub fn unselected(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border = Border {
        width: 1.0,
        color: palette.primary.base.color,
        radius: CARD_RADIUS.into(),
    };

    match status {
        Status::Hovered | Status::Pressed => {
            style.background = Some(Background::Color(palette.background.weak.color));
            style.text_color = palette.primary.base.color;
        }
        _ => {
            style.background = None;
            style.text_color = palette.primary.base.color;
        }
    }
    style
}

pub fn text_button(theme: &Theme, status: Status) -> Style {
    let palette = theme.extended_palette();
    let mut style = Style::default();
    style.border = Border {
        width: 0.0,
        color: Color::TRANSPARENT,
        radius: 0.0.into(),
    };

    match status {
        Status::Hovered => {
            style.background = Some(Background::Color(palette.background.weak.color));
            style.text_color = palette.primary.base.color;
        }
        _ => {
            style.background = Some(Background::Color(Color::TRANSPARENT));
            style.text_color = palette.background.weak.text;
        }
    }
    style
}
