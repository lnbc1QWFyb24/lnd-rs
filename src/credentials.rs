use serde::{Deserialize, Serialize};

/// Storage abstraction for persisting pairing credentials across sessions.
pub trait CredentialStore {
    /// Optional passphrase used to guard the serialized credential payload.
    fn password(&self) -> Option<String> {
        None
    }

    /// Return the most recently paired mailbox host.
    fn server_host(&self) -> Option<String>;
    /// Persist the mailbox host associated with the active credentials.
    fn set_server_host(&mut self, v: String);

    /// Return the stored pairing phrase.
    fn pairing_phrase(&self) -> Option<String>;
    /// Update the pairing phrase value.
    fn set_pairing_phrase(&mut self, v: String);

    /// Return the local Noise static private key (hex).
    fn local_key(&self) -> Option<String>;
    /// Update the stored local Noise static private key (hex).
    fn set_local_key(&mut self, v: String);

    /// Return the remote Noise static public key (hex).
    fn remote_key(&self) -> Option<String>;
    /// Update the stored remote Noise static public key (hex).
    fn set_remote_key(&mut self, v: String);

    /// Helper indicating whether the store contains pairing material.
    fn is_paired(&self) -> bool {
        self.remote_key().is_some() || self.pairing_phrase().is_some()
    }

    /// Clear credentials held by the store.
    ///
    /// When `memory_only` is `true`, clear only ephemeral values that should not persist between
    /// sessions (pairing phrase and local private key). When `memory_only` is `false`, clear all
    /// values including the remote key and last server host.
    fn clear(&mut self, memory_only: bool) {
        self.set_pairing_phrase(String::new());
        self.set_local_key(String::new());
        if !memory_only {
            self.set_remote_key(String::new());
            self.set_server_host(String::new());
        }
    }
}

/// Simple in-memory credential store suitable for tests or examples.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct InMemoryCredentialStore {
    pub password: Option<String>,
    pub server_host: Option<String>,
    pub pairing_phrase: Option<String>,
    pub local_key: Option<String>,
    pub remote_key: Option<String>,
}

impl CredentialStore for InMemoryCredentialStore {
    fn password(&self) -> Option<String> {
        self.password.clone()
    }
    fn server_host(&self) -> Option<String> {
        self.server_host.clone()
    }
    fn set_server_host(&mut self, v: String) {
        self.server_host = if v.is_empty() { None } else { Some(v) }
    }
    fn pairing_phrase(&self) -> Option<String> {
        self.pairing_phrase.clone()
    }
    fn set_pairing_phrase(&mut self, v: String) {
        self.pairing_phrase = if v.is_empty() { None } else { Some(v) }
    }
    fn local_key(&self) -> Option<String> {
        self.local_key.clone()
    }
    fn set_local_key(&mut self, v: String) {
        self.local_key = if v.is_empty() { None } else { Some(v) }
    }
    fn remote_key(&self) -> Option<String> {
        self.remote_key.clone()
    }
    fn set_remote_key(&mut self, v: String) {
        self.remote_key = if v.is_empty() { None } else { Some(v) }
    }
}
