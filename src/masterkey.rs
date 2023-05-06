use crate::password_type::PasswordType;

use crypto::scrypt::{scrypt, ScryptParams};
use crypto::{hmac::Hmac, mac::Mac, sha2::Sha256};

pub const KEY_LENGTH: usize = 64;

#[derive(Clone, Debug)]
pub enum Purpose {
    Authentication,
    Identification,
    Recovery,
}

impl Purpose {
    pub fn scope(&self) -> &'static str {
        match self {
            Purpose::Authentication => "com.lyndir.masterpassword",
            Purpose::Identification => "com.lyndir.masterpassword.login",
            Purpose::Recovery => "com.lyndir.masterpassword.answer",
        }
    }
}

pub struct MasterKey {
    key: [u8; KEY_LENGTH],
    purpose: Purpose,
}

#[inline(always)]
fn u32_to_bytes(u: u32) -> [u8; 4] {
    [
        ((u >> 24) & 0xff) as u8,
        ((u >> 16) & 0xff) as u8,
        ((u >> 8) & 0xff) as u8,
        (u & 0xff) as u8,
    ]
}

impl MasterKey {
    pub fn new(full_name: &str, password: &str, purpose: &Purpose) -> Self {
        let params = ScryptParams::new(15, 8, 2);

        let scope = purpose.scope();

        let mut seed = Vec::new();
        seed.extend_from_slice(scope.as_bytes());
        seed.extend_from_slice(&u32_to_bytes(full_name.len() as u32));
        seed.extend_from_slice(full_name.as_bytes());

        let mut key = [0u8; KEY_LENGTH];
        scrypt(password.as_bytes(), &seed, &params, &mut key);

        MasterKey {
            key,
            purpose: purpose.clone(),
        }
    }

    pub fn new_auth(full_name: &str, password: &str) -> Self {
        Self::new(full_name, password, &Purpose::Authentication)
    }

    pub fn generate_password(
        &self,
        site_name: &str,
        password_type: &PasswordType,
        counter: i32,
    ) -> String {
        let sitekey = self.gen_sitekey(site_name, counter);
        password_type.generate_password(&sitekey)
    }

    fn gen_sitekey(&self, site_name: &str, counter: i32) -> Vec<u8> {
        let scope = self.purpose.scope();

        let mut seed = Vec::new();
        seed.extend_from_slice(scope.as_bytes());
        seed.extend_from_slice(&u32_to_bytes(site_name.len() as u32));
        seed.extend_from_slice(site_name.as_bytes());
        seed.extend_from_slice(&u32_to_bytes(counter as u32));

        let mut hmac = Hmac::new(Sha256::new(), &self.key);
        hmac.input(&seed);

        hmac.result().code().to_vec()
    }
}
