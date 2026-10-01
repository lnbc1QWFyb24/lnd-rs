use std::sync::Arc;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{elliptic_curve::rand_core::OsRng, PublicKey, SecretKey};
use parking_lot::Mutex;
use tracing::debug;

use crate::transport::lncmailbox::{
    aezeed,
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
    /// scrypt stretch on a bounded process-owned worker. Dropping the future
    /// never makes shutdown of the caller's async runtime wait for this work.
    pub async fn new_async(
        _server_host: &str,
        pairing_phrase: &str,
        local_key_hex: &str,
        remote_key_hex: &str,
    ) -> Result<Self, TransportError> {
        debug!(
            target: "lnd_rs::mailbox",
            local_key_len = local_key_hex.len(),
            remote_key_len = remote_key_hex.len(),
            has_remote = !remote_key_hex.is_empty(),
            "transport.connect"
        );
        check_material_lengths(pairing_phrase, local_key_hex, remote_key_hex)?;
        let entropy14 = parse_phrase(pairing_phrase)?;
        let local_sk =
            parse_local_key(local_key_hex)?.unwrap_or_else(|| SecretKey::random(&mut OsRng));
        let remote_pk = parse_remote_key(remote_key_hex)?;

        let sid_val = sid::derive_sid(&entropy14, &local_sk, remote_pk.as_ref());
        let (recv_sid, send_sid) = sid::sid_stream_ids(sid_val);
        let entropy_vec = entropy14.to_vec();
        let passphrase_entropy = if remote_pk.is_none() {
            let stretched = super::stretch::pairing_entropy(entropy_vec.clone()).await?;
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

const MAX_PAIRING_FIELD_BYTES: usize = 4096;

pub(super) fn validate_pairing_material(
    pairing_phrase: &str,
    local_key_hex: &str,
    remote_key_hex: &str,
) -> Result<(), TransportError> {
    check_material_lengths(pairing_phrase, local_key_hex, remote_key_hex)?;
    parse_phrase(pairing_phrase)?;
    parse_local_key(local_key_hex)?;
    parse_remote_key(remote_key_hex)?;
    Ok(())
}

/// Commit to semantic pairing inputs without stretching entropy or doing I/O.
pub(super) fn pairing_commitment(
    authority: &str,
    pairing_phrase: &str,
    local_key_hex: &str,
    remote_key_hex: &str,
) -> Result<[u8; 32], TransportError> {
    use sha2::{Digest, Sha256};

    if authority.is_empty() || authority.len() > 320 || !authority.is_ascii() {
        return Err(TransportError::connection_message(
            "invalid pairing authority",
        ));
    }
    check_material_lengths(pairing_phrase, local_key_hex, remote_key_hex)?;
    let entropy = parse_phrase(pairing_phrase)?;
    let local = parse_local_key(local_key_hex)?.ok_or_else(|| {
        TransportError::connection_message("local key required for pairing commitment")
    })?;
    let remote = parse_remote_key(remote_key_hex)?;
    let encoded_remote = remote.map(|key| key.to_encoded_point(true));
    let mut digest = Sha256::new();
    digest.update(b"lnd-rs:lnc-pairing-commitment:v1\0");
    let local_bytes = local.to_bytes();
    let mode = [u8::from(encoded_remote.is_some())];
    for field in [
        authority.as_bytes(),
        &entropy,
        local_bytes.as_slice(),
        &mode,
        encoded_remote
            .as_ref()
            .map_or(&[][..], |key| key.as_bytes()),
    ] {
        // Inputs have fixed or validated bounds of at most 4096 bytes.
        let length = u64::try_from(field.len()).map_err(|_| {
            TransportError::connection_message("pairing commitment field exceeds byte limit")
        })?;
        digest.update(length.to_be_bytes());
        digest.update(field);
    }
    Ok(digest.finalize().into())
}

fn check_material_lengths(
    pairing_phrase: &str,
    local_key_hex: &str,
    remote_key_hex: &str,
) -> Result<(), TransportError> {
    if [pairing_phrase, local_key_hex, remote_key_hex]
        .iter()
        .any(|field| field.len() > MAX_PAIRING_FIELD_BYTES)
    {
        return Err(TransportError::connection_message(
            "pairing material field exceeds byte limit",
        ));
    }
    Ok(())
}

fn parse_phrase(pairing_phrase: &str) -> Result<[u8; 14], TransportError> {
    let words: Vec<String> = pairing_phrase
        .split_whitespace()
        .map(str::to_string)
        .collect();
    aezeed::mnemonic_to_entropy(&words)
        .map_err(|_| TransportError::connection_message("invalid pairing phrase"))
}

fn parse_local_key(local_key_hex: &str) -> Result<Option<SecretKey>, TransportError> {
    if local_key_hex.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(local_key_hex)
        .map_err(|_| TransportError::connection_message("invalid local key hex"))?;
    SecretKey::from_slice(&bytes)
        .map(Some)
        .map_err(|_| TransportError::connection_message("invalid local key bytes"))
}

fn parse_remote_key(remote_key_hex: &str) -> Result<Option<PublicKey>, TransportError> {
    if remote_key_hex.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(remote_key_hex)
        .map_err(|_| TransportError::connection_message("invalid remote key hex"))?;
    PublicKey::from_sec1_bytes(&bytes)
        .map(Some)
        .map_err(|_| TransportError::connection_message("invalid remote key bytes"))
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
