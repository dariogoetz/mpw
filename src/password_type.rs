#[derive(Debug)]
pub enum PasswordType {
    MaximumSecurity,
    Long,
    Medium,
    Short,
    Basic,
    PIN,
    Name,
    Phrase,
}

const TPL_MAXIMUM_SECURITY: [&str; 2] = ["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"];
const TPL_LONG: [&str; 21] = [
    "CvcvnoCvcvCvcv",
    "CvcvCvcvnoCvcv",
    "CvcvCvcvCvcvno",
    "CvccnoCvcvCvcv",
    "CvccCvcvnoCvcv",
    "CvccCvcvCvcvno",
    "CvcvnoCvccCvcv",
    "CvcvCvccnoCvcv",
    "CvcvCvccCvcvno",
    "CvcvnoCvcvCvcc",
    "CvcvCvcvnoCvcc",
    "CvcvCvcvCvccno",
    "CvccnoCvccCvcv",
    "CvccCvccnoCvcv",
    "CvccCvccCvcvno",
    "CvcvnoCvccCvcc",
    "CvcvCvccnoCvcc",
    "CvcvCvccCvccno",
    "CvccnoCvcvCvcc",
    "CvccCvcvnoCvcc",
    "CvccCvcvCvccno",
];
const TPL_MEDIUM: [&str; 2] = ["CvcnoCvc", "CvcCvcno"];
const TPL_SHORT: [&str; 1] = ["Cvcn"];
const TPL_BASIC: [&str; 3] = ["aaanaaan", "aannaaan", "aaannaaa"];
const TPL_PIN: [&str; 1] = ["nnnn"];
const TPL_NAME: [&str; 1] = ["cvccvcvcv"];
const TPL_PHRASE: [&str; 3] = [
    "cvcc cvc cvccvcv cvc",
    "cvc cvccvcvcv cvcv",
    "cv cvccv cvc cvcvccv",
];

fn apply_template_char(c: char, position: usize) -> char {
    let charset = match c {
        'V' => "AEIOU",
        'C' => "BCDFGHJKLMNPQRSTVWXYZ",
        'v' => "aeiou",
        'c' => "bcdfghjklmnpqrstvwxyz",
        'A' => "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
        'a' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
        'n' => "0123456789",
        'o' => "@&%?,=[]_:-+*$#!'^~;()/.",
        'x' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
        ' ' => " ",
        _ => " ",
    };

    // cycle ensures that the "nth" always return Some(_)
    charset.chars().cycle().nth(position).unwrap()
}

impl PasswordType {
    fn template(&self, position: usize) -> &'static str {
        let templates = match &self {
            PasswordType::MaximumSecurity => TPL_MAXIMUM_SECURITY.as_slice(),
            PasswordType::Long => TPL_LONG.as_slice(),
            PasswordType::Medium => TPL_MEDIUM.as_slice(),
            PasswordType::Short => TPL_SHORT.as_slice(),
            PasswordType::Basic => TPL_BASIC.as_slice(),
            PasswordType::PIN => TPL_PIN.as_slice(),
            PasswordType::Name => TPL_NAME.as_slice(),
            PasswordType::Phrase => TPL_PHRASE.as_slice(),
        };
        templates[position % templates.len()]
    }

    pub fn generate_password(&self, sitekey: &[u8]) -> String {
        // first byte in sitekey determines template
        let template = self.template(sitekey[0] as usize);

        // remaining bytes determine which character to use depending on template char
        template
            .chars()
            .zip(sitekey.iter().skip(1))
            .map(|(tpl_char, sitekey_byte)| apply_template_char(tpl_char, *sitekey_byte as usize))
            .collect()
    }
}

impl From<&str> for PasswordType {
    fn from(value: &str) -> Self {
        match value {
            "Maximum" => PasswordType::MaximumSecurity,
            "Long" => PasswordType::Long,
            "Medium" => PasswordType::Medium,
            "Short" => PasswordType::Short,
            "Basic" => PasswordType::Basic,
            "PIN" => PasswordType::PIN,
            "Name" => PasswordType::Name,
            "Phrase" => PasswordType::Phrase,
            _ => PasswordType::MaximumSecurity,
        }
    }
}
