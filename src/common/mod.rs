pub const KEY_LENGTH: usize = 64;

pub enum Purpose {
    Authentication,
    Identification,
    Recovery,
}

#[derive(Debug)]
pub enum PasswordType {
    MaximumSecurity,
    Long,
    Medium,
    Short,
    Basic,
    PIN,
    Name,
    Phrase
}

pub fn get_scope(purpose: &Purpose) -> &'static str {
    let scope = match purpose {
        Authentication => "com.lyndir.masterpassword",
        Identification => "com.lyndir.masterpassword.login",
        Recovery => "com.lyndir.masterpassword.answer",
    };

    scope
}


#[inline(always)]
pub fn u32_to_bytes(u: u32) -> [u8; 4] {
    [((u >> 24) & 0xff) as u8, ((u >> 16) & 0xff) as u8, ((u >> 8) & 0xff) as u8, (u & 0xff) as u8]
}
