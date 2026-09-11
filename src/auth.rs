// Authentication module for ReMgr web console.
//
// Passwords are stored only as Argon2id PHC strings. The console is protected
// by a session cookie issued on login.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash a plaintext password into an Argon2id PHC string. Returns "" on failure.
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    match Argon2::default().hash_password(password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => String::new(),
    }
}

/// Verify a plaintext password against a stored Argon2id PHC string.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Generate a random, URL/cookie-safe password of `len` alphanumeric chars.
pub fn generate_random_password(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..ALPHABET.len());
            ALPHABET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify() {
        let h = hash_password("correct horse battery staple");
        assert!(!h.is_empty());
        assert!(h.starts_with("$argon2"));
        assert!(verify_password("correct horse battery staple", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn random_password_length_and_uniqueness() {
        let a = generate_random_password(16);
        let b = generate_random_password(16);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
    }
}