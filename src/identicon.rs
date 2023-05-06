use std::fmt::Display;

use crypto::{hmac::Hmac, mac::Mac, sha2::Sha256};

pub enum Color {
    Red = 1,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
}

impl From<usize> for Color {
    fn from(value: usize) -> Self {
        match value {
            1 => Color::Red,
            2 => Color::Green,
            3 => Color::Yellow,
            4 => Color::Blue,
            5 => Color::Magenta,
            6 => Color::Cyan,
            7 => Color::White,
            _ => Color::White,
        }
    }
}

pub struct Identicon {
    pub left_arm: char,
    pub body: char,
    pub right_arm: char,
    pub accessory: char,
    pub color: Color,
}

impl Identicon {
    pub fn new(full_name: &str, master_password: &str) -> Identicon {
        let left_arm = vec!['╔', '╚', '╰', '═'];
        let right_arm = vec!['╗', '╝', '╯', '═'];
        let body = ['█', '░', '▒', '▓', '☺', '☻'];
        let accessory = vec![
            '◈', '◎', '◐', '◑', '◒', '◓', '☀', '☁', '☂', '☃', '☄', '★', '☆', '☎', '☏', '⎈', '⌂',
            '☘', '☢', '☣', '☕', '⌚', '⌛', '⏰', '⚡', '⛄', '⛅', '☔', '♔', '♕', '♖', '♗', '♘',
            '♙', '♚', '♛', '♜', '♝', '♞', '♟', '♨', '♩', '♪', '♫', '⚐', '⚑', '⚔', '⚖', '⚙', '⚠',
            '⌘', '⏎', '✄', '✆', '✈', '✉', '✌',
        ];
        let mut hmac = Hmac::new(Sha256::new(), master_password.as_bytes());
        hmac.input(&full_name.as_bytes());

        let seed: Vec<usize> = hmac.result().code().iter().map(|i| *i as usize).collect();

        Identicon {
            left_arm: left_arm[seed[0] % left_arm.len()],
            body: body[seed[1] % body.len()],
            right_arm: right_arm[seed[2] % right_arm.len()],
            accessory: accessory[seed[3] % accessory.len()],
            color: (seed[4] % 7 + 1).into(),
        }
    }
}

impl Display for Identicon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            self.left_arm, self.body, self.right_arm, self.accessory
        )
    }
}
