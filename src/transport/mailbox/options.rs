//! Caller-owned mailbox address and pure pairing preflight options.

use super::{connect, MailboxTransport};
use crate::transport::TransportError;
use std::sync::Arc;

impl MailboxTransport {
    /// Select caller-owned TLS policy for both websocket streams and reconnects.
    ///
    /// This is runtime-only configuration and performs no network operation.
    /// The caller is responsible for certificate-verifier policy. The original
    /// URL authority still supplies the TLS server name and HTTP Host, including
    /// when a numeric address was supplied separately. Without this option the
    /// upstream bundled Web PKI policy remains in use.
    #[must_use]
    pub fn with_tls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls_config = Some(config);
        self
    }

    #[must_use]
    /// Use a caller-resolved address for both websocket streams and reconnects.
    ///
    /// Resolution happens outside this transport. The original server hostname
    /// remains the HTTP Host and TLS verification/SNI name. This transport never
    /// re-resolves the address; callers must create a new transport to refresh it.
    pub fn with_resolved_address(mut self, address: std::net::SocketAddr) -> Self {
        self.resolved_address = Some(address);
        self
    }

    /// Validate pairing input syntax without deriving a SID, stretching entropy,
    /// generating a key, opening a socket, or requiring an async runtime.
    ///
    /// Uses the same decoders as connection setup. Empty local keys retain the
    /// upstream generate-on-connect meaning; empty remote keys select XX.
    /// Callers that require a supplied local key must enforce that separately.
    ///
    /// # Errors
    /// Rejects fields over 4096 bytes, invalid ten-word AEZEED phrases, non-scalar
    /// private keys and invalid SEC1 public keys. Errors contain no input values.
    pub fn validate_pairing_material(
        pairing_phrase: &str,
        local_key_hex: &str,
        remote_key_hex: &str,
    ) -> Result<(), TransportError> {
        connect::validate_pairing_material(pairing_phrase, local_key_hex, remote_key_hex)
    }

    /// Return a SHA-256 identity for one supplied pairing capability.
    ///
    /// The caller supplies a validated canonical mailbox `host:port` authority;
    /// it is committed verbatim. Domain-separated, u64-length-framed fields are
    /// the authority, decoded 14-byte entropy, 32-byte local scalar, XX/KK tag
    /// and optional compressed remote public key. Whitespace in the phrase and
    /// hex/key encoding differences do not change their semantic identity.
    /// This performs no KDF, randomness, network access or runtime work. The
    /// digest is sensitive correlation data and must not be logged. An XX
    /// commitment identifies the pairing capability, not its learned peer;
    /// callers must bind that authenticated peer separately when resuming.
    ///
    /// # Errors
    /// Rejects an empty, non-ASCII or over-320-byte authority, malformed or
    /// oversized pairing fields, or an absent supplied local key. Errors never
    /// contain the input material or resulting digest.
    ///
    /// # Example
    ///
    /// ```
    /// use lnd_rs::transport::mailbox::MailboxTransport;
    ///
    /// // Synthetic example material; use a supplied secret scalar in practice.
    /// let phrase = "abandon ability able about above absent absorb abstract absurd abuse";
    /// let local = format!("{:064x}", 1);
    /// let identity = MailboxTransport::pairing_commitment(
    ///     "mailbox.example:443", phrase, &local, "",
    /// )?;
    /// // Store the identity privately alongside the separately authenticated XX peer.
    /// assert_eq!(identity, MailboxTransport::pairing_commitment(
    ///     "mailbox.example:443", &format!("  {phrase}  "), &local, "",
    /// )?);
    /// assert!(MailboxTransport::pairing_commitment(
    ///     "mailbox.example:443", phrase, "", "",
    /// ).is_err());
    /// # Ok::<(), lnd_rs::transport::TransportError>(())
    /// ```
    pub fn pairing_commitment(
        canonical_server_authority: &str,
        pairing_phrase: &str,
        local_key_hex: &str,
        remote_key_hex: &str,
    ) -> Result<[u8; 32], TransportError> {
        connect::pairing_commitment(
            canonical_server_authority,
            pairing_phrase,
            local_key_hex,
            remote_key_hex,
        )
    }
}
