#![cfg(feature = "transport-mailbox")]

use std::{
    io::{Read, Write},
    sync::Arc,
};

use hkdf::Hkdf;
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use tracing::{debug, trace};

use super::{cipher_state::CipherState, symmetric_state::SymmetricState, NoiseError};
use crate::transport::lncmailbox::noise;
use crate::transport::lncmailbox::noise::{
    ACT_TWO_PAYLOAD_SIZE, HANDSHAKE_VERSION0, HANDSHAKE_VERSION2,
};
use crate::transport::lncmailbox::noise_pattern::{
    HandshakePattern, MessagePattern, PatternRef, Token,
};

const PROLOGUE: &[u8] = b"lightning-node-connect";
const DH_FN: &str = "secp256k1";
const CIPHER_FN: &str = "ChaChaPoly";
const HASH_FN: &str = "SHA256";
const MAX_HANDSHAKE_PAYLOAD: usize = 64 * 1024;

pub const MAC_SIZE: usize = 16;
pub const LENGTH_HEADER_SIZE: usize = 2;
pub const ENC_HEADER_SIZE: usize = LENGTH_HEADER_SIZE + MAC_SIZE;

fn public_from_secret(secret: &SecretKey) -> PublicKey {
    PublicKey::from_secret_scalar(&secret.to_nonzero_scalar())
}

fn ecdh_bytes(local: &SecretKey, remote: &PublicKey) -> [u8; 32] {
    // Match Go reference: ECDH result is sha256 of the compressed shared point.
    let scalar = local.to_nonzero_scalar();
    let shared_point = k256::ProjectivePoint::from(*remote) * *scalar.as_ref();
    let shared_pk = PublicKey::from_affine(shared_point.to_affine());
    assert!(shared_pk.is_ok(), "ECDH produced invalid point");
    let shared_pk = shared_pk.unwrap();
    let enc = shared_pk.to_encoded_point(true);
    let digest = Sha256::digest(enc.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

type RemoteStaticCallback =
    Box<dyn Fn(&PublicKey) -> Result<(), NoiseError> + Send + Sync + 'static>;
type AuthDataCallback = Box<dyn Fn(&[u8]) -> Result<(), NoiseError> + Send + Sync + 'static>;

/// Configuration inputs used to build a Noise machine compatible with the Go LNC handshake.
pub struct BrontideMachineConfig {
    /// Whether this machine is the initiator (client) side of the handshake.
    pub initiator: bool,
    /// Negotiated pattern (XX or KK).
    pub pattern: PatternRef,
    /// Minimum Noise handshake version to accept.
    pub min_handshake_version: u8,
    /// Maximum Noise handshake version to accept.
    pub max_handshake_version: u8,
    /// Local static private key.
    pub local_static: Arc<SecretKey>,
    /// Optional remote static public key (required for KK).
    pub remote_static: Option<PublicKey>,
    /// Entropy derived from the AEZEED phrase (used for SPAKE2 masking).
    pub passphrase_entropy: Arc<Vec<u8>>,
    /// Optional payload to send as part of the auth transport message.
    pub auth_payload: Option<Vec<u8>>,
    /// Callback invoked when the remote static key is learned.
    pub on_remote_static: Option<RemoteStaticCallback>,
    /// Callback invoked when auth data is received.
    pub on_auth_data: Option<AuthDataCallback>,
}

struct HandshakeState {
    symmetric: SymmetricState,
    initiator: bool,
    local_static: Arc<SecretKey>,
    local_ephemeral: Option<SecretKey>,
    remote_static: Option<PublicKey>,
    remote_ephemeral: Option<PublicKey>,
    passphrase_entropy: Arc<Vec<u8>>,
    payload_to_send: Option<Vec<u8>>,
    received_payload: Vec<u8>,
    pattern: HandshakePattern,
    min_version: u8,
    max_version: u8,
    version: u8,
}

impl HandshakeState {
    fn new(cfg: &BrontideMachineConfig) -> Result<Self, NoiseError> {
        let mut symmetric = SymmetricState::new();
        let pattern = cfg.pattern.pattern();
        let protocol_name = format!("Noise_{}_{}_{}_{}", pattern.name, DH_FN, CIPHER_FN, HASH_FN);
        symmetric.initialize_symmetric(&protocol_name);
        symmetric.mix_hash(PROLOGUE);

        let mut state = Self {
            symmetric,
            initiator: cfg.initiator,
            local_static: cfg.local_static.clone(),
            local_ephemeral: None,
            remote_static: cfg.remote_static,
            remote_ephemeral: None,
            passphrase_entropy: cfg.passphrase_entropy.clone(),
            payload_to_send: cfg.auth_payload.clone(),
            received_payload: Vec::new(),
            pattern,
            min_version: cfg.min_handshake_version,
            max_version: cfg.max_handshake_version,
            version: if cfg.initiator {
                cfg.min_handshake_version
            } else {
                cfg.max_handshake_version
            },
        };

        // Pre-messages: mix static keys into transcript per pattern.
        for m in state.pattern.pre_messages {
            if m.initiator == state.initiator {
                let local_pub = public_from_secret(state.local_static.as_ref());
                state
                    .symmetric
                    .mix_hash(local_pub.to_encoded_point(true).as_bytes());
            } else if let Some(remote) = state.remote_static.as_ref() {
                state
                    .symmetric
                    .mix_hash(remote.to_encoded_point(true).as_bytes());
            } else {
                return Err(NoiseError::InvalidState(
                    "remote static required for pattern".into(),
                ));
            }
        }

        Ok(state)
    }

    fn write_msg_pattern(&mut self, mp: &MessagePattern) -> Result<Vec<u8>, NoiseError> {
        let mut buf = Vec::new();
        buf.push(self.version);
        self.write_tokens(mp.tokens, &mut buf)?;
        let payload = self.build_payload(mp)?;
        buf.extend_from_slice(&payload);
        Ok(buf)
    }

    fn read_msg_pattern<R: Read>(
        &mut self,
        reader: &mut R,
        mp: &MessagePattern,
    ) -> Result<(), NoiseError> {
        let mut version_byte = [0u8; 1];
        reader.read_exact(&mut version_byte)?;
        let version = version_byte[0];
        self.validate_version(version, mp)?;

        self.read_tokens(reader, mp.tokens)?;
        self.consume_payload(reader, mp)?;

        Ok(())
    }

    fn validate_version(&mut self, version: u8, mp: &MessagePattern) -> Result<(), NoiseError> {
        match mp.act {
            1 | 2 => {
                if version < self.min_version || version > self.max_version {
                    return Err(NoiseError::InvalidState(format!(
                        "unexpected handshake version {version}"
                    )));
                }
                if self.initiator {
                    self.version = version;
                    debug!(
                        target: "lnd_rs::mailbox::noise",
                        version = self.version,
                        act = mp.act,
                        "negotiated handshake version"
                    );
                }
            }
            3 => {
                if version != self.version {
                    return Err(NoiseError::InvalidState(format!(
                        "handshake version mismatch {version} != {}",
                        self.version
                    )));
                }
                debug!(
                    target: "lnd_rs::mailbox::noise",
                    version = self.version,
                    act = mp.act,
                    "confirmed handshake version"
                );
            }
            _ => {}
        }
        Ok(())
    }

    fn write_tokens(&mut self, tokens: &[Token], out: &mut Vec<u8>) -> Result<(), NoiseError> {
        for token in tokens {
            match token {
                Token::E => {
                    let (sk, pk) = noise::gen_ephemeral();
                    self.local_ephemeral = Some(sk);
                    let encoded = pk.to_encoded_point(true);
                    self.symmetric.mix_hash(encoded.as_bytes());
                    out.extend_from_slice(encoded.as_bytes());
                }
                Token::Me => {
                    let (sk, pk) = noise::gen_ephemeral();
                    self.local_ephemeral = Some(sk);
                    let encoded = pk.to_encoded_point(true);
                    self.symmetric.mix_hash(encoded.as_bytes());
                    let masked = noise::spake2_mask(&pk, self.passphrase_entropy.as_slice());
                    trace!(
                        target: "lnd_rs::mailbox::noise::act1",
                        version = self.version,
                        unmasked_ephemeral = %hex::encode(encoded.as_bytes()),
                        masked_ephemeral = %hex::encode(masked.to_encoded_point(true).as_bytes()),
                        "prepared masked ephemeral"
                    );
                    out.extend_from_slice(masked.to_encoded_point(true).as_bytes());
                }
                Token::S => {
                    let pk = public_from_secret(self.local_static.as_ref());
                    let ciphertext = self
                        .symmetric
                        .encrypt_and_hash(pk.to_encoded_point(true).as_bytes())?;
                    out.extend_from_slice(&ciphertext);
                }
                Token::Ee => {
                    let remote = self.remote_ephemeral.as_ref().ok_or_else(|| {
                        NoiseError::InvalidState("remote ephemeral missing".into())
                    })?;
                    let local = self.local_ephemeral.as_ref().ok_or_else(|| {
                        NoiseError::InvalidState("local ephemeral missing".into())
                    })?;
                    let secret = ecdh_bytes(local, remote);
                    self.symmetric.mix_key(&secret)?;
                    trace!(
                        target: "lnd_rs::mailbox::noise::act2",
                        chaining_key = %hex::encode(self.symmetric.chaining_key),
                        temp_key = %hex::encode(self.symmetric.temp_key),
                        handshake_digest = %hex::encode(self.symmetric.handshake_digest),
                        "after EE mix_key (write)"
                    );
                }
                Token::Ss => {
                    let remote = self
                        .remote_static
                        .as_ref()
                        .ok_or_else(|| NoiseError::InvalidState("remote static missing".into()))?;
                    let secret = ecdh_bytes(self.local_static.as_ref(), remote);
                    self.symmetric.mix_key(&secret)?;
                }
                Token::Es => {
                    let secret = if self.initiator {
                        let remote = self.remote_static.as_ref().ok_or_else(|| {
                            NoiseError::InvalidState("remote static missing".into())
                        })?;
                        let local = self.local_ephemeral.as_ref().ok_or_else(|| {
                            NoiseError::InvalidState("local ephemeral missing".into())
                        })?;
                        ecdh_bytes(local, remote)
                    } else {
                        let remote = self.remote_ephemeral.as_ref().ok_or_else(|| {
                            NoiseError::InvalidState("remote ephemeral missing".into())
                        })?;
                        ecdh_bytes(self.local_static.as_ref(), remote)
                    };
                    self.symmetric.mix_key(&secret)?;
                }
                Token::Se => {
                    let secret = if self.initiator {
                        let remote = self.remote_ephemeral.as_ref().ok_or_else(|| {
                            NoiseError::InvalidState("remote ephemeral missing".into())
                        })?;
                        ecdh_bytes(self.local_static.as_ref(), remote)
                    } else {
                        let remote = self.remote_static.as_ref().ok_or_else(|| {
                            NoiseError::InvalidState("remote static missing".into())
                        })?;
                        let local = self.local_ephemeral.as_ref().ok_or_else(|| {
                            NoiseError::InvalidState("local ephemeral missing".into())
                        })?;
                        ecdh_bytes(local, remote)
                    };
                    self.symmetric.mix_key(&secret)?;
                }
            }
        }
        Ok(())
    }

    fn read_tokens<R: Read>(&mut self, reader: &mut R, tokens: &[Token]) -> Result<(), NoiseError> {
        for &token in tokens {
            self.read_token(reader, token)?;
        }
        Ok(())
    }

    fn read_token<R: Read>(&mut self, reader: &mut R, token: Token) -> Result<(), NoiseError> {
        match token {
            Token::E => self.read_remote_ephemeral(reader),
            Token::Me => self.read_masked_ephemeral(reader),
            Token::S => self.read_encrypted_static(reader),
            Token::Ee => self.mix_key_from_ephemerals(),
            Token::Ss => self.mix_key_from_statics(),
            Token::Es => self.mix_key_es(),
            Token::Se => self.mix_key_se(),
        }
    }

    fn build_payload(&mut self, mp: &MessagePattern) -> Result<Vec<u8>, NoiseError> {
        match self.version {
            HANDSHAKE_VERSION0 => {
                let payload = if mp.act == 2 {
                    let mut data = vec![0u8; ACT_TWO_PAYLOAD_SIZE];
                    if let Some(auth) = self.payload_to_send.take() {
                        let len = u16::try_from(auth.len()).map_err(|_| {
                            NoiseError::InvalidState("auth payload too large".into())
                        })?;
                        data[..2].copy_from_slice(&len.to_be_bytes());
                        data[2..2 + len as usize].copy_from_slice(&auth);
                    }
                    data
                } else {
                    Vec::new()
                };
                self.symmetric.encrypt_and_hash(&payload)
            }
            HANDSHAKE_VERSION2 => {
                if mp.act == 2 {
                    let data = self.payload_to_send.take().unwrap_or_default();
                    let mut len_buf = [0u8; 4];
                    let data_len = u32::try_from(data.len())
                        .map_err(|_| NoiseError::InvalidState("auth payload too large".into()))?;
                    len_buf.copy_from_slice(&data_len.to_be_bytes());
                    let mut out = self.symmetric.encrypt_and_hash(&len_buf)?;
                    let enc_payload = self.symmetric.encrypt_and_hash(&data)?;
                    out.extend_from_slice(&enc_payload);
                    Ok(out)
                } else {
                    self.symmetric.encrypt_and_hash(&[])
                }
            }
            _ => Err(NoiseError::InvalidState(format!(
                "unsupported handshake version {}",
                self.version
            ))),
        }
    }

    fn consume_payload<R: Read>(
        &mut self,
        reader: &mut R,
        mp: &MessagePattern,
    ) -> Result<(), NoiseError> {
        match self.version {
            HANDSHAKE_VERSION0 => {
                let payload_len = if mp.act == 2 { ACT_TWO_PAYLOAD_SIZE } else { 0 };
                let cipher_len = payload_len + MAC_SIZE;
                let mut buf = vec![0u8; cipher_len];
                reader.read_exact(&mut buf)?;
                let plaintext = self.symmetric.decrypt_and_hash(&buf)?;
                if mp.act == 2 {
                    if plaintext.len() < 2 {
                        return Err(NoiseError::InvalidState("payload too small".into()));
                    }
                    let declared_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
                    if declared_len > plaintext.len().saturating_sub(2) {
                        return Err(NoiseError::InvalidState("payload length invalid".into()));
                    }
                    self.received_payload = plaintext[2..2 + declared_len].to_vec();
                }
            }
            HANDSHAKE_VERSION2 => match mp.act {
                1 | 3 => {
                    let mut buf = vec![0u8; MAC_SIZE];
                    reader.read_exact(&mut buf)?;
                    let _ = self.symmetric.decrypt_and_hash(&buf)?;
                }
                2 => {
                    let mut header = vec![0u8; 4 + MAC_SIZE];
                    reader.read_exact(&mut header)?;
                    let len_bytes = self.symmetric.decrypt_and_hash(&header)?;
                    if len_bytes.len() != 4 {
                        return Err(NoiseError::InvalidState("invalid length header".into()));
                    }
                    let payload_len = u32::from_be_bytes([
                        len_bytes[0],
                        len_bytes[1],
                        len_bytes[2],
                        len_bytes[3],
                    ]) as usize;
                    trace!(
                        target: "lnd_rs::mailbox::noise::act2",
                        version = self.version,
                        payload_len,
                        "parsed payload length from header"
                    );
                    if payload_len > MAX_HANDSHAKE_PAYLOAD {
                        return Err(NoiseError::InvalidState(
                            "handshake payload too large".into(),
                        ));
                    }
                    let mut body = vec![0u8; payload_len + MAC_SIZE];
                    reader.read_exact(&mut body)?;
                    let payload = self.symmetric.decrypt_and_hash(&body)?;
                    self.received_payload = payload;
                }
                _ => {}
            },
            _ => {
                return Err(NoiseError::InvalidState(format!(
                    "unsupported handshake version {}",
                    self.version
                )))
            }
        }
        Ok(())
    }

    fn read_remote_ephemeral<R: Read>(&mut self, reader: &mut R) -> Result<(), NoiseError> {
        let mut buf = [0u8; 33];
        reader.read_exact(&mut buf)?;
        let pk = PublicKey::from_sec1_bytes(&buf).map_err(|e| NoiseError::Crypto(e.to_string()))?;
        let encoded = pk.to_encoded_point(true);
        self.symmetric.mix_hash(encoded.as_bytes());
        self.remote_ephemeral = Some(pk);
        trace!(
            target: "lnd_rs::mailbox::noise::act2",
            remote_ephemeral = %hex::encode(encoded.as_bytes()),
            "read remote ephemeral"
        );
        Ok(())
    }

    fn read_masked_ephemeral<R: Read>(&mut self, reader: &mut R) -> Result<(), NoiseError> {
        let mut buf = [0u8; 33];
        reader.read_exact(&mut buf)?;
        let masked =
            PublicKey::from_sec1_bytes(&buf).map_err(|e| NoiseError::Crypto(e.to_string()))?;
        let pk = noise::spake2_unmask(&masked, self.passphrase_entropy.as_slice());
        let encoded = pk.to_encoded_point(true);
        self.symmetric.mix_hash(encoded.as_bytes());
        self.remote_ephemeral = Some(pk);
        Ok(())
    }

    fn read_encrypted_static<R: Read>(&mut self, reader: &mut R) -> Result<(), NoiseError> {
        let mut buf = vec![0u8; 33 + MAC_SIZE];
        reader.read_exact(&mut buf)?;
        trace!(
            target: "lnd_rs::mailbox::noise::act2",
            ciphertext = %hex::encode(&buf),
            handshake_digest = %hex::encode(self.symmetric.handshake_digest),
            "received encrypted static key"
        );
        let plaintext = self.symmetric.decrypt_and_hash(&buf)?;
        let pk = PublicKey::from_sec1_bytes(&plaintext)
            .map_err(|e| NoiseError::Crypto(e.to_string()))?;
        self.remote_static = Some(pk);
        trace!(
            target: "lnd_rs::mailbox::noise::act2",
            remote_static = %hex::encode(&plaintext),
            "decrypted remote static key"
        );
        Ok(())
    }

    fn mix_key_from_ephemerals(&mut self) -> Result<(), NoiseError> {
        let remote = self
            .remote_ephemeral
            .as_ref()
            .ok_or_else(|| NoiseError::InvalidState("remote ephemeral missing".into()))?;
        let local = self
            .local_ephemeral
            .as_ref()
            .ok_or_else(|| NoiseError::InvalidState("local ephemeral missing".into()))?;
        let secret = ecdh_bytes(local, remote);
        self.symmetric.mix_key(&secret)?;
        trace!(
            target: "lnd_rs::mailbox::noise::act2",
            chaining_key = %hex::encode(self.symmetric.chaining_key),
            temp_key = %hex::encode(self.symmetric.temp_key),
            handshake_digest = %hex::encode(self.symmetric.handshake_digest),
            "after EE mix_key (read)"
        );
        Ok(())
    }

    fn mix_key_from_statics(&mut self) -> Result<(), NoiseError> {
        let remote = self
            .remote_static
            .as_ref()
            .ok_or_else(|| NoiseError::InvalidState("remote static missing".into()))?;
        let secret = ecdh_bytes(self.local_static.as_ref(), remote);
        self.symmetric.mix_key(&secret)
    }

    fn mix_key_es(&mut self) -> Result<(), NoiseError> {
        let secret = if self.initiator {
            let remote = self
                .remote_static
                .as_ref()
                .ok_or_else(|| NoiseError::InvalidState("remote static missing".into()))?;
            let local = self
                .local_ephemeral
                .as_ref()
                .ok_or_else(|| NoiseError::InvalidState("local ephemeral missing".into()))?;
            ecdh_bytes(local, remote)
        } else {
            let remote = self
                .remote_ephemeral
                .as_ref()
                .ok_or_else(|| NoiseError::InvalidState("remote ephemeral missing".into()))?;
            ecdh_bytes(self.local_static.as_ref(), remote)
        };
        self.symmetric.mix_key(&secret)
    }

    fn mix_key_se(&mut self) -> Result<(), NoiseError> {
        let secret = if self.initiator {
            let remote = self
                .remote_ephemeral
                .as_ref()
                .ok_or_else(|| NoiseError::InvalidState("remote ephemeral missing".into()))?;
            ecdh_bytes(self.local_static.as_ref(), remote)
        } else {
            let remote = self
                .remote_static
                .as_ref()
                .ok_or_else(|| NoiseError::InvalidState("remote static missing".into()))?;
            let local = self
                .local_ephemeral
                .as_ref()
                .ok_or_else(|| NoiseError::InvalidState("local ephemeral missing".into()))?;
            ecdh_bytes(local, remote)
        };
        self.symmetric.mix_key(&secret)
    }
}

pub struct BrontideMachine {
    cfg: BrontideMachineConfig,
    handshake: Option<HandshakeState>,
    send_cipher: CipherState,
    recv_cipher: CipherState,
    next_header_send: Vec<u8>,
    next_body_send: Vec<u8>,
    next_cipher_header: [u8; ENC_HEADER_SIZE],
}

impl BrontideMachine {
    /// Construct a Noise machine using the provided configuration.
    ///
    /// # Errors
    /// Returns a [`NoiseError`] when the handshake state cannot be initialized.
    pub fn new(cfg: BrontideMachineConfig) -> Result<Self, NoiseError> {
        let handshake = Some(HandshakeState::new(&cfg)?);
        Ok(Self {
            cfg,
            handshake,
            send_cipher: CipherState::new(),
            recv_cipher: CipherState::new(),
            next_header_send: Vec::new(),
            next_body_send: Vec::new(),
            next_cipher_header: [0u8; ENC_HEADER_SIZE],
        })
    }

    /// Run the Noise handshake over the supplied read/write transport.
    ///
    /// # Errors
    /// Returns a [`NoiseError`] when the IO operations fail or the peer produces invalid data.
    pub fn do_handshake<RW: Read + Write>(&mut self, rw: &mut RW) -> Result<(), NoiseError> {
        let mut handshake = self
            .handshake
            .take()
            .ok_or_else(|| NoiseError::InvalidState("handshake already completed".into()))?;
        for mp in handshake.pattern.pattern {
            if mp.initiator == handshake.initiator {
                let msg = handshake.write_msg_pattern(mp)?;
                rw.write_all(&msg)?;
            } else {
                handshake.read_msg_pattern(rw, mp)?;
            }
        }
        let result = self.complete_handshake(&handshake);
        if result.is_ok() {
            self.handshake = None;
        }
        result
    }

    fn complete_handshake(&mut self, handshake: &HandshakeState) -> Result<(), NoiseError> {
        let hk = Hkdf::<Sha256>::new(Some(&handshake.symmetric.chaining_key), &[]);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm)
            .map_err(|_| NoiseError::Crypto("hkdf expand failed".into()))?;
        let mut first_key = [0u8; 32];
        let mut second_key = [0u8; 32];
        first_key.copy_from_slice(&okm[..32]);
        second_key.copy_from_slice(&okm[32..]);

        if self.cfg.initiator {
            self.send_cipher
                .initialize_key_with_salt(handshake.symmetric.chaining_key, first_key);
            self.recv_cipher
                .initialize_key_with_salt(handshake.symmetric.chaining_key, second_key);
        } else {
            self.recv_cipher
                .initialize_key_with_salt(handshake.symmetric.chaining_key, first_key);
            self.send_cipher
                .initialize_key_with_salt(handshake.symmetric.chaining_key, second_key);
        }

        if handshake.version >= HANDSHAKE_VERSION2 {
            if let Some(remote) = handshake.remote_static {
                self.cfg.remote_static = Some(remote);
                if let Some(cb) = &self.cfg.on_remote_static {
                    cb(&remote)?;
                }
            }
        }
        if !handshake.received_payload.is_empty() {
            if let Some(cb) = &self.cfg.on_auth_data {
                cb(&handshake.received_payload)?;
            }
        }

        Ok(())
    }

    /// Queue an encrypted payload to be flushed out on the transport.
    ///
    /// # Errors
    /// Returns a `NoiseError` when the handshake is incomplete, the payload exceeds `u16::MAX`,
    /// or the previous payload has not yet been flushed.
    ///
    /// # Panics
    /// Panics if the payload length no longer satisfies the precondition `payload.len() <= u16::MAX`
    /// despite the guard earlier in this method.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<(), NoiseError> {
        if self.handshake.is_some() {
            return Err(NoiseError::InvalidState("handshake not complete".into()));
        }
        if payload.len() > u16::MAX as usize {
            return Err(NoiseError::InvalidState(
                "payload exceeds max length".into(),
            ));
        }
        if !self.next_body_send.is_empty() {
            return Err(NoiseError::InvalidState(
                "previous payload not flushed".into(),
            ));
        }

        let mut len_buf = [0u8; 2];
        let payload_len = u16::try_from(payload.len());
        assert!(payload_len.is_ok(), "payload len bounded by earlier check");
        let payload_len = payload_len.unwrap();
        len_buf.copy_from_slice(&payload_len.to_be_bytes());
        self.next_header_send = self.send_cipher.encrypt(&[], &len_buf)?;
        self.next_body_send = self.send_cipher.encrypt(&[], payload)?;
        Ok(())
    }

    /// Flush the pending encrypted payload to the provided writer.
    ///
    /// # Errors
    /// Returns a `NoiseError` when the cipher state fails to encrypt the buffered data.
    pub fn flush<W: Write>(&mut self, writer: &mut W) -> Result<usize, NoiseError> {
        if self.next_header_send.is_empty() && self.next_body_send.is_empty() {
            return Ok(0);
        }
        writer.write_all(&self.next_header_send)?;
        self.next_header_send.clear();
        let payload_len = self.next_body_send.len().saturating_sub(MAC_SIZE);
        writer.write_all(&self.next_body_send)?;
        self.next_body_send.clear();
        Ok(payload_len)
    }

    /// Read and decrypt the length header for the next ciphertext.
    ///
    /// # Errors
    /// Returns a `NoiseError` when the handshake is incomplete or the decrypted header is
    /// malformed.
    ///
    /// # Panics
    /// Panics if the constant `MAC_SIZE` no longer fits in `u32`, which would indicate a
    /// programming error.
    pub fn read_header<R: Read>(&mut self, reader: &mut R) -> Result<u32, NoiseError> {
        if self.handshake.is_some() {
            return Err(NoiseError::InvalidState("handshake not complete".into()));
        }
        reader.read_exact(&mut self.next_cipher_header)?;
        let pkt_len_bytes = self.recv_cipher.decrypt(&[], &self.next_cipher_header)?;
        if pkt_len_bytes.len() != 2 {
            return Err(NoiseError::InvalidState("invalid length header".into()));
        }
        let pkt_len = u32::from(u16::from_be_bytes([pkt_len_bytes[0], pkt_len_bytes[1]])) + {
            let mac_u32 = u32::try_from(MAC_SIZE);
            assert!(mac_u32.is_ok(), "MAC_SIZE fits in u32");
            mac_u32.unwrap()
        };
        Ok(pkt_len)
    }

    /// Read and decrypt the ciphertext body using the previously parsed header.
    ///
    /// # Errors
    /// Returns a `NoiseError` when the ciphertext cannot be read or decrypted.
    pub fn read_body<R: Read>(
        &mut self,
        reader: &mut R,
        buf: &mut [u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if self.handshake.is_some() {
            return Err(NoiseError::InvalidState("handshake not complete".into()));
        }
        reader.read_exact(buf)?;
        let plaintext = self.recv_cipher.decrypt(&[], buf)?;
        Ok(plaintext)
    }

    /// Convenience wrapper that reads both the header and body for a complete message.
    ///
    /// # Errors
    /// Propagates `NoiseError` values from `Self::read_header` and `Self::read_body`.
    pub fn read_message<R: Read>(&mut self, reader: &mut R) -> Result<Vec<u8>, NoiseError> {
        let pkt_len = self.read_header(reader)? as usize;
        let mut buf = vec![0u8; pkt_len];
        self.read_body(reader, &mut buf)
    }
}

// Inline tests from the original module retained here.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::lncmailbox::noise::HANDSHAKE_VERSION2;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::thread;

    #[derive(Clone)]
    struct InMemoryStream {
        recv: Arc<Mutex<VecDeque<u8>>>,
        send: Arc<Mutex<VecDeque<u8>>>,
    }

    impl InMemoryStream {
        fn pair() -> (Self, Self) {
            let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
            let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
            let a = Self {
                recv: b_to_a.clone(),
                send: a_to_b.clone(),
            };
            let b = Self {
                recv: a_to_b,
                send: b_to_a,
            };
            (a, b)
        }

        fn snapshot_send(&self) -> Vec<u8> {
            let send = self.send.lock().unwrap();
            send.iter().copied().collect()
        }
    }

    impl Read for InMemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                if let Some(n) = {
                    let mut recv = self.recv.lock().unwrap();
                    if recv.is_empty() {
                        None
                    } else {
                        let n = buf.len().min(recv.len());
                        for (dst, value) in buf.iter_mut().take(n).zip(recv.drain(..n)) {
                            *dst = value;
                        }
                        Some(n)
                    }
                } {
                    return Ok(n);
                }
                thread::yield_now();
            }
        }
    }

    impl Write for InMemoryStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut send = self.send.lock().unwrap();
            send.extend(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // Bring over the existing tests with minimal edits.
    const XX_REMOTE_HEX: &str =
        "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
    const XX_CIPHER_HEX: &str =
        "4a39e56b901c3c8f0312fb64d6e017786761bd8c4311077f6cf39ad673e7ac3967acbd0aaf281c939c8127";
    const KK_REMOTE_HEX: &str =
        "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";
    const KK_CIPHER_HEX: &str =
        "a26a53fb728c7b84f3fa98b3248320eb0fb7e0575aa4b00e69af2c6202981004a702aaafb7cfb64897b5a7";

    #[test]
    fn xx_handshake_roundtrip_and_message() {
        let (mut client_stream, mut server_stream) = InMemoryStream::pair();
        let client_sk = Arc::new(SecretKey::random(&mut rand::thread_rng()));
        let server_sk = Arc::new(SecretKey::random(&mut rand::thread_rng()));
        let entropy = Arc::new(Sha256::digest(b"pairing entropy").to_vec());
        let auth_payload = b"macaroon-data".to_vec();

        let client_remote = Arc::new(Mutex::new(None));
        let client_remote_cb = client_remote.clone();
        let client_auth = Arc::new(Mutex::new(Vec::new()));
        let client_auth_cb = client_auth.clone();

        let client_cfg = BrontideMachineConfig {
            initiator: true,
            pattern: PatternRef::Xx,
            min_handshake_version: HANDSHAKE_VERSION2,
            max_handshake_version: HANDSHAKE_VERSION2,
            local_static: client_sk.clone(),
            remote_static: None,
            passphrase_entropy: entropy.clone(),
            auth_payload: None,
            on_remote_static: Some(Box::new(move |pk| {
                *client_remote_cb.lock().unwrap() = Some(*pk);
                Ok(())
            })),
            on_auth_data: Some(Box::new(move |data| {
                *client_auth_cb.lock().unwrap() = data.to_vec();
                Ok(())
            })),
        };

        let server_cfg = BrontideMachineConfig {
            initiator: false,
            pattern: PatternRef::Xx,
            min_handshake_version: HANDSHAKE_VERSION2,
            max_handshake_version: HANDSHAKE_VERSION2,
            local_static: server_sk.clone(),
            remote_static: None,
            passphrase_entropy: entropy,
            auth_payload: Some(auth_payload.clone()),
            on_remote_static: None,
            on_auth_data: None,
        };

        let mut client_machine = BrontideMachine::new(client_cfg).expect("client machine");
        let server_handle = thread::spawn(move || {
            let mut machine = BrontideMachine::new(server_cfg).expect("server machine");
            machine
                .do_handshake(&mut server_stream)
                .expect("server handshake");
            (machine, server_stream)
        });

        client_machine
            .do_handshake(&mut client_stream)
            .expect("client handshake");
        let (mut server_machine, mut server_stream) = server_handle.join().unwrap();

        let remote = *client_remote
            .lock()
            .unwrap()
            .as_ref()
            .expect("remote key set");
        assert_eq!(
            remote.to_encoded_point(true).as_bytes(),
            public_from_secret(server_sk.as_ref())
                .to_encoded_point(true)
                .as_bytes()
        );
        assert_eq!(*client_auth.lock().unwrap(), auth_payload);

        client_machine
            .write_message(b"hello")
            .expect("write message");
        client_machine.flush(&mut client_stream).expect("flush");

        let plaintext = server_machine
            .read_message(&mut server_stream)
            .expect("read message");
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn xx_handshake_matches_vector() {
        noise::seed_ephemeral_rng(42);
        let (mut client_stream, mut server_stream) = InMemoryStream::pair();
        let client_sk = Arc::new(SecretKey::from_slice(&[0x11u8; 32]).expect("client secret key"));
        let server_sk = Arc::new(SecretKey::from_slice(&[0x22u8; 32]).expect("server secret key"));
        let entropy = Arc::new(vec![0xAB; 32]);
        let auth_payload = b"vector-auth".to_vec();

        let client_remote = Arc::new(Mutex::new(None));
        let client_remote_cb = client_remote.clone();
        let client_auth = Arc::new(Mutex::new(Vec::new()));
        let client_auth_cb = client_auth.clone();

        let client_cfg = BrontideMachineConfig {
            initiator: true,
            pattern: PatternRef::Xx,
            min_handshake_version: HANDSHAKE_VERSION2,
            max_handshake_version: HANDSHAKE_VERSION2,
            local_static: client_sk.clone(),
            remote_static: None,
            passphrase_entropy: entropy.clone(),
            auth_payload: None,
            on_remote_static: Some(Box::new(move |pk| {
                *client_remote_cb.lock().unwrap() = Some(*pk);
                Ok(())
            })),
            on_auth_data: Some(Box::new(move |data| {
                *client_auth_cb.lock().unwrap() = data.to_vec();
                Ok(())
            })),
        };

        let server_cfg = BrontideMachineConfig {
            initiator: false,
            pattern: PatternRef::Xx,
            min_handshake_version: HANDSHAKE_VERSION2,
            max_handshake_version: HANDSHAKE_VERSION2,
            local_static: server_sk.clone(),
            remote_static: None,
            passphrase_entropy: entropy,
            auth_payload: Some(auth_payload.clone()),
            on_remote_static: None,
            on_auth_data: None,
        };

        let mut client_machine = BrontideMachine::new(client_cfg).expect("client machine");
        let server_handle = thread::spawn(move || {
            let mut machine = BrontideMachine::new(server_cfg).expect("server machine");
            machine
                .do_handshake(&mut server_stream)
                .expect("server handshake");
            (machine, server_stream)
        });

        client_machine
            .do_handshake(&mut client_stream)
            .expect("client handshake");
        let (mut server_machine, mut server_stream) = server_handle.join().unwrap();

        let remote = client_remote
            .lock()
            .unwrap()
            .as_ref()
            .map(|pk| hex::encode(pk.to_encoded_point(true).as_bytes()))
            .expect("remote key captured");
        assert_eq!(remote, XX_REMOTE_HEX);
        assert_eq!(*client_auth.lock().unwrap(), auth_payload);

        client_machine
            .write_message(b"vector-xx")
            .expect("write message");
        client_machine
            .flush(&mut client_stream)
            .expect("flush message");
        let cipher_hex = hex::encode(client_stream.snapshot_send());
        assert_eq!(cipher_hex, XX_CIPHER_HEX);

        let plaintext = server_machine
            .read_message(&mut server_stream)
            .expect("read vector");
        assert_eq!(plaintext, b"vector-xx");
    }

    #[test]
    fn kk_handshake_matches_vector() {
        noise::seed_ephemeral_rng(1337);
        let (mut client_stream, mut server_stream) = InMemoryStream::pair();
        let client_sk = Arc::new(SecretKey::from_slice(&[0x33u8; 32]).expect("client secret key"));
        let server_sk = Arc::new(SecretKey::from_slice(&[0x44u8; 32]).expect("server secret key"));
        let entropy = Arc::new(vec![0xCD; 32]);

        let client_remote = PublicKey::from_secret_scalar(&server_sk.to_nonzero_scalar());
        let server_remote = PublicKey::from_secret_scalar(&client_sk.to_nonzero_scalar());

        let client_cfg = BrontideMachineConfig {
            initiator: true,
            pattern: PatternRef::Kk,
            min_handshake_version: HANDSHAKE_VERSION2,
            max_handshake_version: HANDSHAKE_VERSION2,
            local_static: client_sk.clone(),
            remote_static: Some(client_remote),
            passphrase_entropy: entropy.clone(),
            auth_payload: None,
            on_remote_static: None,
            on_auth_data: None,
        };

        let server_cfg = BrontideMachineConfig {
            initiator: false,
            pattern: PatternRef::Kk,
            min_handshake_version: HANDSHAKE_VERSION2,
            max_handshake_version: HANDSHAKE_VERSION2,
            local_static: server_sk.clone(),
            remote_static: Some(server_remote),
            passphrase_entropy: entropy,
            auth_payload: None,
            on_remote_static: None,
            on_auth_data: None,
        };

        let mut client_machine = BrontideMachine::new(client_cfg).expect("client machine");
        let server_handle = thread::spawn(move || {
            let mut machine = BrontideMachine::new(server_cfg).expect("server machine");
            machine
                .do_handshake(&mut server_stream)
                .expect("server handshake");
            (machine, server_stream)
        });

        client_machine
            .do_handshake(&mut client_stream)
            .expect("client handshake");
        let (mut server_machine, mut server_stream) = server_handle.join().unwrap();

        client_machine
            .write_message(b"vector-kk")
            .expect("write message");
        client_machine.flush(&mut client_stream).expect("flush");
        let cipher_hex = hex::encode(client_stream.snapshot_send());
        assert_eq!(cipher_hex, KK_CIPHER_HEX);

        let plaintext = server_machine
            .read_message(&mut server_stream)
            .expect("read kk vector");
        assert_eq!(plaintext, b"vector-kk");

        let server_remote_hex = hex::encode(server_remote.to_encoded_point(true).as_bytes());
        assert_eq!(server_remote_hex, KK_REMOTE_HEX);
    }
}
