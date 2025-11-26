use std::{borrow::Cow, error::Error};

use async_trait::async_trait;
use tonic::{body::BoxBody, client::GrpcService};

use crate::PairingCredentials;

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("not implemented")]
    NotImplemented,
    #[error("{context}")]
    Connection {
        context: Cow<'static, str>,
        #[source]
        source: Option<BoxError>,
    },
}

impl TransportError {
    /// Build a connection error with optional context and source.
    pub fn connection<S, E>(context: S, source: E) -> Self
    where
        S: Into<Cow<'static, str>>,
        E: Error + Send + Sync + 'static,
    {
        Self::Connection {
            context: context.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Build a connection error that only has context (no underlying source).
    pub fn connection_message<S>(context: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self::Connection {
            context: context.into(),
            source: None,
        }
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    /// The underlying gRPC service used by tonic clients.
    type Svc: GrpcService<BoxBody> + Clone + Send + Sync + 'static;
    /// Perform initial pairing using a pairing phrase. Return credentials to persist.
    async fn pair(
        &mut self,
        _server_host: &str,
        _pairing_phrase: &str,
    ) -> Result<PairingCredentials, TransportError> {
        Err(TransportError::NotImplemented)
    }

    /// Connect using the given credential values.
    async fn connect(
        &mut self,
        _server_host: &str,
        _pairing_phrase: &str,
        _local_key: &str,
        _remote_key: &str,
    ) -> Result<(), TransportError>;

    /// Connect using stored [`PairingCredentials`].
    ///
    /// This is a convenience wrapper around [`connect`](Self::connect) that extracts
    /// the individual fields from the credentials struct, making reconnection code
    /// more readable.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let creds: PairingCredentials = load_from_disk()?;
    /// transport.connect_with_credentials(&creds).await?;
    /// ```
    async fn connect_with_credentials(
        &mut self,
        creds: &PairingCredentials,
    ) -> Result<(), TransportError> {
        self.connect(
            &creds.server_host,
            &creds.pairing_phrase,
            &creds.local_key,
            &creds.remote_key,
        )
        .await
    }

    /// Return a tonic-compatible gRPC service bound to the current transport.
    async fn service(&self) -> Result<Self::Svc, TransportError>;

    /// Disconnect/cleanup.
    async fn disconnect(&mut self) -> Result<(), TransportError>;

    /// Optional per-request metadata headers (key, value) to attach.
    fn metadata(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Optional remote static key learned during the current connection.
    fn remote_key_hint(&self) -> Option<String> {
        None
    }
}

#[cfg(feature = "transport-direct")]
pub mod direct;
pub mod mailbox;
#[cfg(feature = "transport-mailbox")]
pub mod lncmailbox {
    pub mod aezeed;
    pub mod conn;
    pub mod crypto;
    pub mod gbn;
    pub mod gbn_wire;
    pub mod noise;
    pub mod noise_conn;
    pub mod noise_machine;
    pub mod noise_pattern;
    pub mod sid;
    pub mod ws;
}
