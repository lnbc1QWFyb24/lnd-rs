#![cfg(feature = "transport-mailbox")]

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use super::{cipher_state::CipherState, NoiseError};

pub struct SymmetricState {
    pub(crate) cipher_state: CipherState,
    pub(crate) chaining_key: [u8; 32],
    pub(crate) temp_key: [u8; 32],
    pub(crate) handshake_digest: [u8; 32],
}

impl Default for SymmetricState {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricState {
    /// Construct a symmetric handshake state with zeroed keys and digest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cipher_state: CipherState::new(),
            chaining_key: [0u8; 32],
            temp_key: [0u8; 32],
            handshake_digest: [0u8; 32],
        }
    }

    pub fn initialize_symmetric(&mut self, protocol_name: &str) {
        let hash = Sha256::digest(protocol_name.as_bytes());
        self.handshake_digest.copy_from_slice(&hash);
        self.chaining_key.copy_from_slice(&hash);
        self.cipher_state.initialize_key([0u8; 32]);
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.handshake_digest);
        hasher.update(data);
        self.handshake_digest.copy_from_slice(&hasher.finalize());
    }

    /// Mix the provided input keying material into the chaining key and initialize a new temp key.
    ///
    /// # Errors
    /// Returns `NoiseError::Crypto` if HKDF expansion fails.
    pub fn mix_key(&mut self, input: &[u8]) -> Result<(), NoiseError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.chaining_key), input);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm)
            .map_err(|_| NoiseError::Crypto("hkdf expand failed".into()))?;
        self.chaining_key.copy_from_slice(&okm[..32]);
        self.temp_key.copy_from_slice(&okm[32..]);
        self.cipher_state.initialize_key(self.temp_key);
        Ok(())
    }

    /// Encrypt the plaintext using the handshake digest as AAD, then absorb the ciphertext.
    ///
    /// # Errors
    /// Propagates errors from the underlying cipher state if encryption fails.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = self
            .cipher_state
            .encrypt(&self.handshake_digest, plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt the ciphertext using the handshake digest as AAD, then absorb the ciphertext.
    ///
    /// # Errors
    /// Propagates errors from the underlying cipher state if decryption fails.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = self
            .cipher_state
            .decrypt(&self.handshake_digest, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }
}
