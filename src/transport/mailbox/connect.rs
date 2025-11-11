use std::sync::Arc;

use base64::Engine;
use k256::{PublicKey, SecretKey};
use parking_lot::Mutex;
use tracing::{debug, trace};

use crate::transport::lncmailbox::{
    aezeed, crypto,
    noise::{HANDSHAKE_VERSION0, HANDSHAKE_VERSION2},
    noise_machine::{BrontideMachineConfig, PatternRef},
    sid,
};
use crate::transport::TransportError;

pub struct MailboxConnectContext {
    pub recv_sid: [u8; 64],
    pub send_sid: [u8; 64],
    pub remote_hint: Arc<Mutex<Option<PublicKey>>>,
    pub auth_capture: Arc<Mutex<Vec<u8>>>,
    pub builder: NoiseConfigBuilder,
}

impl MailboxConnectContext {
    /// Build a connection context from pairing inputs.
    ///
    /// When performing an XX handshake (no remote static key provided), this spawns a blocking
    /// scrypt stretch in a background thread to avoid blocking the async runtime.
    pub async fn new_async(
        server_host: &str,
        pairing_phrase: &str,
        local_key_hex: &str,
        remote_key_hex: &str,
    ) -> Result<Self, TransportError> {
        debug!(
            target: "lnd_rs::mailbox",
            server_host = %server_host,
            "transport.connect"
        );
        let words: Vec<String> = pairing_phrase
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let entropy14 = aezeed::mnemonic_to_entropy(&words).map_err(|e| {
            TransportError::connection_message(format!("invalid pairing phrase: {e}"))
        })?;

        let local_sk = if local_key_hex.is_empty() {
            SecretKey::random(&mut rand::thread_rng())
        } else {
            SecretKey::from_slice(
                &hex::decode(local_key_hex)
                    .map_err(|e| TransportError::connection("invalid local key hex", e))?,
            )
            .map_err(|e| TransportError::connection("invalid local key bytes", e))?
        };

        let remote_pk = if remote_key_hex.is_empty() {
            None
        } else {
            let bytes = hex::decode(remote_key_hex)
                .map_err(|e| TransportError::connection("invalid remote key hex", e))?;
            Some(
                PublicKey::from_sec1_bytes(&bytes)
                    .map_err(|e| TransportError::connection("invalid remote key bytes", e))?,
            )
        };

        let sid_val = sid::derive_sid(&entropy14, &local_sk, remote_pk.as_ref());
        let (recv_sid, send_sid) = sid::sid_stream_ids(sid_val);
        trace!(
            target: "lnd_rs::mailbox::sid",
            recv_prefix = %hex::encode(&recv_sid[..4]),
            send_prefix = %hex::encode(&send_sid[..4]),
            pattern = %if remote_pk.is_some() { "KK" } else { "XX" },
            "derived SID prefixes"
        );
        trace!(
            target: "lnd_rs::mailbox::sid",
            recv_sid = %base64::engine::general_purpose::STANDARD.encode(recv_sid),
            send_sid = %base64::engine::general_purpose::STANDARD.encode(send_sid),
            "derived SID values"
        );

        let entropy_vec = entropy14.to_vec();
        let passphrase_entropy = if remote_pk.is_none() {
            let entropy_clone = entropy_vec.clone();
            // Offload the CPU-heavy scrypt to a blocking thread.
            let stretched =
                tokio::task::spawn_blocking(move || crypto::scrypt_stretch(&entropy_clone))
                    .await
                    .map_err(|e| TransportError::connection("scrypt task join failed", e))?
                    .map_err(|e| {
                        TransportError::connection_message(format!(
                            "passphrase stretch failed: {e}"
                        ))
                    })?;
            trace!(
                target: "lnd_rs::mailbox",
                stretch_hex = %hex::encode(&stretched),
                "XX passphrase stretch (32b)"
            );
            Arc::new(stretched)
        } else {
            Arc::new(entropy_vec.clone())
        };

        let remote_hint = Arc::new(Mutex::new(remote_pk));
        let auth_capture = Arc::new(Mutex::new(Vec::new()));
        let builder = NoiseConfigBuilder::new(
            Arc::new(local_sk),
            passphrase_entropy,
            remote_hint.clone(),
            auth_capture.clone(),
        );

        Ok(Self {
            recv_sid,
            send_sid,
            remote_hint,
            auth_capture,
            builder,
        })
    }
}

#[derive(Clone)]
pub struct NoiseConfigBuilder {
    local_static: Arc<SecretKey>,
    passphrase_entropy: Arc<Vec<u8>>,
    remote_hint: Arc<Mutex<Option<PublicKey>>>,
    auth_capture: Arc<Mutex<Vec<u8>>>,
}

impl NoiseConfigBuilder {
    pub fn new(
        local_static: Arc<SecretKey>,
        passphrase_entropy: Arc<Vec<u8>>,
        remote_hint: Arc<Mutex<Option<PublicKey>>>,
        auth_capture: Arc<Mutex<Vec<u8>>>,
    ) -> Self {
        Self {
            local_static,
            passphrase_entropy,
            remote_hint,
            auth_capture,
        }
    }

    pub fn build(&self) -> BrontideMachineConfig {
        let remote_sink = self.remote_hint.clone();
        let auth_sink = self.auth_capture.clone();
        let current_remote = *remote_sink.lock();
        let pattern = if current_remote.is_some() {
            PatternRef::Kk
        } else {
            PatternRef::Xx
        };
        let (min_version, max_version) = if matches!(pattern, PatternRef::Kk) {
            (HANDSHAKE_VERSION2, HANDSHAKE_VERSION2)
        } else {
            (HANDSHAKE_VERSION0, HANDSHAKE_VERSION2)
        };
        BrontideMachineConfig {
            initiator: true,
            pattern,
            min_handshake_version: min_version,
            max_handshake_version: max_version,
            local_static: self.local_static.clone(),
            remote_static: current_remote,
            passphrase_entropy: self.passphrase_entropy.clone(),
            auth_payload: None,
            on_remote_static: Some(Box::new(move |pk| {
                *remote_sink.lock() = Some(*pk);
                Ok(())
            })),
            on_auth_data: Some(Box::new(move |data| {
                let mut buf = auth_sink.lock();
                buf.clear();
                buf.extend_from_slice(data);
                Ok(())
            })),
        }
    }
}
