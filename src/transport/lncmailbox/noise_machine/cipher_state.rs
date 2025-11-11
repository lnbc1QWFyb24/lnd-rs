#![cfg(feature = "transport-mailbox")]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use super::NoiseError;

pub const KEY_ROTATION_INTERVAL: u64 = 1000;

pub struct CipherState {
    pub(crate) nonce: u64,
    pub(crate) secret_key: [u8; 32],
    pub(crate) salt: [u8; 32],
    cipher: Option<ChaCha20Poly1305>,
}

impl Default for CipherState {
    fn default() -> Self {
        Self::new()
    }
}

impl CipherState {
    /// Construct a zeroed cipher state. Caller must initialize a key before use.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nonce: 0,
            secret_key: [0u8; 32],
            salt: [0u8; 32],
            cipher: None,
        }
    }

    pub fn initialize_key(&mut self, key: [u8; 32]) {
        self.secret_key = key;
        self.nonce = 0;
        let cipher_key = Key::from(self.secret_key);
        self.cipher = Some(ChaCha20Poly1305::new(&cipher_key));
    }

    pub fn initialize_key_with_salt(&mut self, salt: [u8; 32], key: [u8; 32]) {
        self.salt = salt;
        self.initialize_key(key);
    }

    /// Encrypt `plaintext` with the current key and nonce using `associated_data` as AAD.
    ///
    /// # Errors
    /// Returns `NoiseError::InvalidState` if the cipher is uninitialized or `NoiseError::Crypto`
    /// if AEAD encryption fails.
    pub fn encrypt(
        &mut self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| NoiseError::InvalidState("cipher not initialized".into()))?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());
        let nonce = Nonce::from(nonce_bytes);
        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| NoiseError::Crypto(e.to_string()))?;
        self.nonce += 1;
        if self.nonce == KEY_ROTATION_INTERVAL {
            self.rotate_key()?;
        }
        Ok(ciphertext)
    }

    /// Decrypt `ciphertext` with the current key and nonce using `associated_data` as AAD.
    ///
    /// # Errors
    /// Returns `NoiseError::InvalidState` if the cipher is uninitialized or `NoiseError::Crypto`
    /// if AEAD decryption fails.
    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| NoiseError::InvalidState("cipher not initialized".into()))?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());
        let nonce = Nonce::from(nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };
        let plaintext = cipher
            .decrypt(&nonce, payload)
            .map_err(|e| NoiseError::Crypto(e.to_string()))?;
        self.nonce += 1;
        if self.nonce == KEY_ROTATION_INTERVAL {
            self.rotate_key()?;
        }
        Ok(plaintext)
    }

    fn rotate_key(&mut self) -> Result<(), NoiseError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.salt), &self.secret_key);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm)
            .map_err(|_| NoiseError::Crypto("hkdf expand failed".into()))?;
        let mut new_salt = [0u8; 32];
        let mut next_key = [0u8; 32];
        new_salt.copy_from_slice(&okm[..32]);
        next_key.copy_from_slice(&okm[32..]);
        self.initialize_key_with_salt(new_salt, next_key);
        Ok(())
    }
}
