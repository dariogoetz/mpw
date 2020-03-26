use super::common;

use crypto::scrypt::{scrypt, scrypt_check, scrypt_simple, ScryptParams};
use log::*;

fn get_scrypt_params() -> ScryptParams {
    return ScryptParams::new(15, 8, 2);
}

fn get_seed(full_name: &str, scope: &str) -> Vec<u8> {
    let mut seed = Vec::new();
    seed.extend_from_slice(scope.as_bytes());
    seed.extend_from_slice(&common::u32_to_bytes(full_name.len() as u32));
    seed.extend_from_slice(full_name.as_bytes());

    seed
}

pub fn gen_masterkey(password: &str, full_name: &str, purpose: &common::Purpose) -> [u8; common::KEY_LENGTH] {
    let params = get_scrypt_params();
    let scope = common::get_scope(purpose);
    let seed = get_seed(full_name, scope);
    let mut masterkey = [0u8; common::KEY_LENGTH];
    scrypt(password.as_bytes(), &seed, &params, &mut masterkey);

    masterkey
}

