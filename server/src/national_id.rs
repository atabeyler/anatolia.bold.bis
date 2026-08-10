//! Encryption-at-rest for national ID numbers (madde 20 in the hardening
//! instructions). Two derived values are stored instead of the plaintext:
//!
//! - `national_id_encrypted`: AES-256-GCM ciphertext (random 96-bit nonce
//!   prefixed, then base64-encoded) — recoverable only with
//!   `NATIONAL_ID_ENCRYPTION_KEY`, used when the full value must be
//!   decrypted server-side (currently: only to mask it for display, see
//!   `admin::mask_national_id`).
//! - `national_id_lookup_hash`: HMAC-SHA256(key, national_id), hex-encoded
//!   — deterministic, so it can carry the `UNIQUE` constraint that used to
//!   sit on the plaintext column (duplicate national ID detection) without
//!   the database ever holding a value an operator could read directly.
//!
//! Both are derived from the same key so a single compromised secret is
//! the actual boundary — there is no separate, weaker "lookup" secret to
//! attack instead.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

const NONCE_LEN: usize = 12;

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
}

/// Encrypts `plaintext` and returns `(national_id_encrypted, national_id_lookup_hash)`.
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> (String, String) {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher(key)
        .encrypt(&nonce, plaintext.as_bytes())
        .expect("AES-256-GCM encryption of a short, well-formed plaintext cannot fail");
    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    (BASE64.encode(combined), lookup_hash(key, plaintext))
}

/// Decrypts a value produced by `encrypt`. Returns `None` on any failure
/// (malformed base64, wrong key, tampered ciphertext) rather than
/// panicking — a decryption failure must never crash a request.
pub fn decrypt(key: &[u8; 32], encrypted: &str) -> Option<String> {
    let combined = BASE64.decode(encrypted).ok()?;
    if combined.len() < NONCE_LEN {
        return None;
    }
    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
    let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes.try_into().ok()?;
    let nonce = Nonce::from(nonce_bytes);
    let plaintext = cipher(key).decrypt(&nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Deterministic HMAC-SHA256 of `value` under `key`, hex-encoded — used
/// for exact-match duplicate lookups without storing (or comparing
/// against) the plaintext.
pub fn lookup_hash(key: &[u8; 32], value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length, including a fixed 32-byte one");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = test_key();
        let (encrypted, _hash) = encrypt(&key, "12345678901");
        assert_eq!(decrypt(&key, &encrypted).as_deref(), Some("12345678901"));
    }

    #[test]
    fn two_encryptions_of_the_same_value_differ() {
        let key = test_key();
        let (a, hash_a) = encrypt(&key, "12345678901");
        let (b, hash_b) = encrypt(&key, "12345678901");
        assert_ne!(a, b, "random nonce must make ciphertext non-deterministic");
        assert_eq!(hash_a, hash_b, "lookup hash must stay deterministic");
    }

    #[test]
    fn decrypt_with_wrong_key_fails_closed() {
        let (encrypted, _) = encrypt(&test_key(), "12345678901");
        assert_eq!(decrypt(&[9u8; 32], &encrypted), None);
    }

    #[test]
    fn decrypt_rejects_garbage_input() {
        assert_eq!(decrypt(&test_key(), "not-base64!!"), None);
        assert_eq!(decrypt(&test_key(), "dG9vc2hvcnQ="), None);
    }

    #[test]
    fn lookup_hash_is_stable_and_value_dependent() {
        let key = test_key();
        assert_eq!(lookup_hash(&key, "111"), lookup_hash(&key, "111"));
        assert_ne!(lookup_hash(&key, "111"), lookup_hash(&key, "222"));
    }
}
