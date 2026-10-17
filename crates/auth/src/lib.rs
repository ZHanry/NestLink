//! Password, encrypted TURN credentials and opaque token primitives. Secrets never derive Debug.
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid password or credential")]
    Invalid,
    #[error("cryptographic operation failed")]
    Crypto,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);
impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn from_text(text: String) -> Self {
        Self(text)
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

pub fn random_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
}
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
pub fn token() -> Secret {
    Secret(URL_SAFE_NO_PAD.encode(random_bytes::<32>()))
}
pub fn token_hash(purpose: &str, value: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"NestLink/v15/token\0");
    hash.update((purpose.len() as u64).to_be_bytes());
    hash.update(purpose.as_bytes());
    hash.update(value.as_bytes());
    hash.finalize().into()
}
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(AuthError::Invalid);
    }
    let params = Params::new(19_456, 2, 1, None).map_err(|_| AuthError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|_| AuthError::Crypto)
}
pub fn verify_password(password: &str, encoded: &str) -> Result<(), AuthError> {
    if password.len() > 1024 {
        return Err(AuthError::Invalid);
    }
    let hash = PasswordHash::new(encoded).map_err(|_| AuthError::Invalid)?;
    // Stored parameters are bounded before invoking the expensive implementation.
    if hash.algorithm.as_str() != "argon2id"
        || hash.params.get_decimal("m").is_none_or(|m| m > 65_536)
        || hash.params.get_decimal("t").is_none_or(|t| t > 4)
        || hash.params.get_decimal("p").is_none_or(|p| p > 4)
    {
        return Err(AuthError::Invalid);
    }
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .map_err(|_| AuthError::Invalid)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);
impl VaultKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn encrypt_turn(
        &self,
        allocation_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        self.encrypt_bound(
            &format!("NestLink/v15/turn-credential/{allocation_id}"),
            plaintext,
        )
    }
    fn encrypt_bound(&self, aad: &str, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        if plaintext.len() > 984 {
            return Err(AuthError::Invalid);
        }
        let nonce = random_bytes::<24>();
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| AuthError::Crypto)?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&encrypted);
        Ok(result)
    }
    pub fn decrypt_turn(
        &self,
        allocation_id: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        self.decrypt_bound(
            &format!("NestLink/v15/turn-credential/{allocation_id}"),
            ciphertext,
        )
    }
    fn decrypt_bound(&self, aad: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        if ciphertext.len() < 40 || ciphertext.len() > 1024 {
            return Err(AuthError::Invalid);
        }
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(
                XNonce::from_slice(&ciphertext[..24]),
                Payload {
                    msg: &ciphertext[24..],
                    aad: aad.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| AuthError::Crypto)
    }
}

/// RFC 5389 MESSAGE-INTEGRITY uses this mandated long-term credential digest.
/// It is not a password storage hash or an endpoint identity signature.
pub fn turn_auth_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut digest = Md5::new();
    digest.update(username.as_bytes());
    digest.update(b":");
    digest.update(realm.as_bytes());
    digest.update(b":");
    digest.update(password.as_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn password_hash_is_salted_and_rejects_wrong_password() {
        let a = hash_password("test-only-password").unwrap();
        let b = hash_password("test-only-password").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("test-only-password", &a).is_ok());
        assert!(verify_password("wrong-password", &a).is_err());
        assert!(hash_password("short").is_err());
        assert_eq!(format!("{:?}", token()), "Secret([redacted])");
    }
    #[test]
    fn token_domains_are_separate() {
        assert_ne!(token_hash("access", "same"), token_hash("refresh", "same"));
    }
    #[test]
    fn turn_ciphertexts_are_allocation_bound_and_integrity_checked() {
        let vault = VaultKey::from_bytes([9; 32]);
        let encrypted = vault
            .encrypt_turn("allocation-a", b"a-random-turn-password")
            .unwrap();
        assert_eq!(
            vault
                .decrypt_turn("allocation-a", &encrypted)
                .unwrap()
                .as_slice(),
            b"a-random-turn-password"
        );
        assert!(vault.decrypt_turn("allocation-b", &encrypted).is_err());
        let mut tampered = encrypted;
        tampered[30] ^= 1;
        assert!(vault.decrypt_turn("allocation-a", &tampered).is_err());
        assert_eq!(
            turn_auth_key("user", "realm", "pass"),
            md5::Md5::digest(b"user:realm:pass").as_slice()
        );
    }
}
