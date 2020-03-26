
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_scrypt() {
        let params = get_scrypt_params();
        let hashed_pw = scrypt_simple("test_string", &params).expect("Scrypt generation failed.");
        let check_passed = scrypt_check("test_string", &hashed_pw).expect("Scrypt check failed.");
        assert!(check_passed);
    }
}
