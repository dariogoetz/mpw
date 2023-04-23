use super::common;
use crypto::{hmac::Hmac, mac::Mac, sha2::Sha256};

fn get_seed(site_name: &str, scope: &str, counter: i32) -> Vec<u8> {
    let mut seed = Vec::new();
    seed.extend_from_slice(scope.as_bytes());
    seed.extend_from_slice(&common::u32_to_bytes(site_name.len() as u32));
    seed.extend_from_slice(site_name.as_bytes());
    seed.extend_from_slice(&common::u32_to_bytes(counter as u32));

    seed
}

pub fn gen_sitekey(
    masterkey: &[u8; common::KEY_LENGTH],
    site_name: &str,
    purpose: &common::Purpose,
    counter: i32,
) -> Vec<u8> {
    let scope = common::get_scope(purpose);
    let seed = get_seed(site_name, scope, counter);

    let mut hmac = Hmac::new(Sha256::new(), masterkey);
    hmac.input(&seed);

    hmac.result().code().to_vec()
}
