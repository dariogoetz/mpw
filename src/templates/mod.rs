use super::common::{PasswordType, KEY_LENGTH};

pub fn get_template(sitekey_byte: u8, site_type: &PasswordType) -> &'static str {
    let templates = match site_type {
        PasswordType::MaximumSecurity => vec!["anoxxxxxxxxxxxxxxxxx",
                                          "axxxxxxxxxxxxxxxxxno"],
        PasswordType::Long => vec!["CvcvnoCvcvCvcv",
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
                               "CvccCvcvCvccno"],
        PasswordType::Medium => vec!["CvcnoCvc", "CvcCvcno"],
        PasswordType::Short => vec!["Cvcn"],
        PasswordType::Basic => vec!["aaanaaan", "aannaaan", "aaannaaa"],
        PasswordType::PIN => vec!["nnnn"],
        PasswordType::Name => vec!["cvccvcvcv"],
        PasswordType::Phrase => vec!["cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv",
                                 "cv cvccv cvc cvcvccv"]
    };
    let template = templates[(sitekey_byte as usize) % templates.len()];

    template
}

fn get_template_char(char_class: char, sitekey_byte: u8) -> Option<char> {
    let charset = match char_class {
        'V' => Some("AEIOU"),
        'C' => Some("BCDFGHJKLMNPQRSTVWXYZ"),
        'v' => Some("aeiou"),
        'c' => Some("bcdfghjklmnpqrstvwxyz"),
        'A' => Some("AEIOUBCDFGHJKLMNPQRSTVWXYZ"),
        'a' => Some("AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz"),
        'n' => Some("0123456789"),
        'o' => Some("@&%?,=[]_:-+*$#!'^~;()/."),
        'x' => Some("AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()"),
        ' ' => Some(" "),
        _ => None
    };

    match charset {
        Some(val) => val.chars().nth((sitekey_byte as usize) % val.len()),
        None => None
    }
}


pub fn get_password(sitekey: &Vec<u8>, site_type: &PasswordType) -> Option<String> {
    let template = get_template(sitekey[0], site_type);

    let mut res = Vec::new();
    let mut has_none = false;

    for (i, c) in template.chars().enumerate() {
        if let Some(tc) = get_template_char(c, sitekey[i + 1]) {
            res.push(tc);
        } else {
            has_none = true;
        }
    }

    if has_none {
        None
    } else {
        Some(res.iter().collect())
    }
}
