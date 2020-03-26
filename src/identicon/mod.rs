use crypto::{
    hmac::Hmac,
    mac::Mac,
    sha2::Sha256
};

pub fn generate(full_name: &str, master_password: &str) -> String {
    let left_arm = vec!['╔', '╚', '╰', '═'];
    let right_arm = vec!['╗', '╝', '╯', '═'];
    let body = ['█', '░', '▒', '▓', '☺', '☻'];
    let accessory = vec!['◈', '◎', '◐', '◑', '◒', '◓', '☀', '☁', '☂', '☃',
                         '☄', '★', '☆', '☎', '☏', '⎈', '⌂', '☘', '☢', '☣',
                         '☕', '⌚', '⌛', '⏰', '⚡', '⛄', '⛅', '☔', '♔', '♕',
                         '♖', '♗', '♘', '♙', '♚', '♛', '♜', '♝', '♞', '♟',
                         '♨', '♩', '♪', '♫', '⚐', '⚑', '⚔', '⚖', '⚙', '⚠',
                         '⌘', '⏎', '✄', '✆', '✈', '✉', '✌'];
    let mut hmac = Hmac::new(Sha256::new(), master_password.as_bytes());
    hmac.input(&full_name.as_bytes());

    let identicon_seed = hmac.result().code().to_vec();

    format!("{}{}{}{}",
            left_arm[identicon_seed[0] as usize % left_arm.len()],
            body[identicon_seed[1] as usize % body.len()],
            right_arm[identicon_seed[2] as usize % right_arm.len()],
            accessory[identicon_seed[3] as usize % accessory.len()])
}
