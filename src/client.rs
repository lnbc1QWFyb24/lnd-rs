use crate::{
    config::{LncConfig, DEFAULT_SERVER_HOST},
    credentials::{CredentialStore, InMemoryCredentialStore},
    proto,
    transport::{Transport, TransportError},
};
use thiserror::Error;
use tonic::{
    service::interceptor::InterceptedService, service::Interceptor as TonicInterceptor, Code,
    Status,
};

/// Persistent credential tuple returned by [`Lnc::pair_node`] and consumed by [`Lnc::connect`].
///
/// The tuple mirrors the LND/LNC expectations:
///
/// - `server_host` indicates which mailbox cluster issued the credentials.
/// - `pairing_phrase` is the AEZEED phrase the user originally entered.
/// - `local_key` / `remote_key` are the Noise static key material tracked by LNC.
/// - `macaroon_hex` carries the authentication macaroon captured from the handshake metadata.
///
/// # Examples
///
/// ```
/// use lnd_rs::PairingCredentials;
///
/// let creds = PairingCredentials {
///     server_host: "mailbox.example.org:443".into(),
///     pairing_phrase: "absorb abstract abuse ...".into(),
///     local_key: "01abcd".into(),
///     remote_key: "02feedface".into(),
///     macaroon_hex: Some("ff00".into()),
/// };
/// assert!(creds.macaroon_hex.is_some());
/// ```
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PairingCredentials {
    /// Mailbox host/port that issued the credentials (e.g. `mailbox.terminal.lightning.today:443`).
    pub server_host: String,
    /// Original AEZEED pairing phrase entered by the user.
    pub pairing_phrase: String,
    /// Local Noise static private key encoded as lowercase hex.
    pub local_key: String,
    /// Remote Noise static public key encoded as compressed SEC1 hex.
    pub remote_key: String,
    /// Hex-encoded macaroon captured during Noise authentication, if present.
    pub macaroon_hex: Option<String>,
}

/// Library-level error type surfaced by [`Lnc`].
#[derive(Debug, Error)]
pub enum LncError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    GrpcStatus(#[from] Box<Status>),
    #[error("pairing not supported by transport")]
    PairingUnsupported,
    #[error("not connected")]
    NotConnected,
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
}

impl From<Status> for LncError {
    fn from(status: Status) -> Self {
        Self::GrpcStatus(Box::new(status))
    }
}

/// Result alias that defaults to [`LncError`].
pub type Result<T, E = LncError> = std::result::Result<T, E>;

// Intercepted service over the transport-provided gRPC service.
type LncGrpcService<T> = InterceptedService<<T as Transport>::Svc, LncInterceptor>;

/// Primary entry point. Holds a transport, credential store, and runtime configuration.
pub struct Lnc<T: Transport> {
    transport: T,
    creds: Box<dyn CredentialStore + Send + Sync>,
    connected: bool,
    config: LncConfig,
}

impl<T: Transport> Lnc<T> {
    /// Construct an [`Lnc`] instance with the default in-memory credential store.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            creds: Box::new(InMemoryCredentialStore::default()),
            connected: false,
            config: LncConfig::default(),
        }
    }

    /// Construct an [`Lnc`] instance backed by the provided credential store.
    pub fn with_store(transport: T, store: Box<dyn CredentialStore + Send + Sync>) -> Self {
        Self {
            transport,
            creds: store,
            connected: false,
            config: LncConfig::default(),
        }
    }

    /// Construct an [`Lnc`] instance with an explicit [`LncConfig`].
    pub fn with_config(transport: T, config: LncConfig) -> Self {
        Self {
            transport,
            creds: Box::new(InMemoryCredentialStore::default()),
            connected: false,
            config,
        }
    }

    /// Construct an [`Lnc`] instance pre-configured with stored pairing credentials.
    ///
    /// Use this when reconnecting with credentials saved from a previous
    /// [`pair_node`](Self::pair_node) call. After construction, call [`connect`](Self::connect)
    /// to establish the session.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let creds: PairingCredentials = serde_json::from_slice(&data)?;
    /// let transport = MailboxTransport::new(Some(creds.server_host.clone()));
    /// let mut lnc = Lnc::from_credentials(transport, creds);
    /// lnc.connect().await?;
    /// ```
    pub fn from_credentials(transport: T, creds: PairingCredentials) -> Self {
        let mut store = InMemoryCredentialStore::default();
        store.set_server_host(creds.server_host);
        store.set_pairing_phrase(creds.pairing_phrase);
        store.set_local_key(creds.local_key);
        store.set_remote_key(creds.remote_key);
        Self::with_store(transport, Box::new(store))
    }

    /// Access the underlying credential store.
    pub fn credentials_store(&self) -> &dyn CredentialStore {
        &*self.creds
    }

    /// Mutably access the underlying credential store.
    pub fn credentials_store_mut(&mut self) -> &mut dyn CredentialStore {
        &mut *self.creds
    }

    /// Pair using a pairing phrase via the transport (LNC mailbox expected).
    ///
    /// # Errors
    /// Returns [`LncError`] when the underlying transport pairing attempt fails.
    pub async fn pair(
        &mut self,
        server_host: &str,
        pairing_phrase: &str,
    ) -> Result<PairingCredentials> {
        match self.transport.pair(server_host, pairing_phrase).await {
            Ok(creds) => {
                self.creds.set_server_host(server_host.to_string());
                self.creds.set_pairing_phrase(creds.pairing_phrase.clone());
                self.creds.set_local_key(creds.local_key.clone());
                self.creds.set_remote_key(creds.remote_key.clone());
                Ok(creds)
            }
            Err(TransportError::NotImplemented) => Err(LncError::PairingUnsupported),
            Err(e) => Err(LncError::from(e)),
        }
    }

    /// Convenience wrapper: pair using configured or default server host.
    ///
    /// # Errors
    /// Returns [`LncError`] when pairing or the subsequent connection attempt fails.
    pub async fn pair_node(&mut self, pairing_phrase: &str) -> Result<PairingCredentials> {
        let server_host = self
            .creds
            .server_host()
            .or_else(|| self.config.server_host.clone())
            .unwrap_or_else(|| DEFAULT_SERVER_HOST.to_string());
        let mut creds = self.pair(&server_host, pairing_phrase).await?;
        self.connect().await?;
        creds.remote_key = self.creds.remote_key().unwrap_or_default();
        creds.macaroon_hex = self.macaroon_from_metadata();
        Ok(creds)
    }

    /// Connect using current credentials.
    ///
    /// # Errors
    /// Returns [`LncError`] when the transport connection cannot be established.
    pub async fn connect(&mut self) -> Result<()> {
        if self.connected {
            return Ok(());
        }
        let server_host = self
            .creds
            .server_host()
            .or_else(|| self.config.server_host.clone())
            .unwrap_or_else(|| DEFAULT_SERVER_HOST.to_string());
        let pairing_phrase = self.creds.pairing_phrase().unwrap_or_default();
        let local_key = self.creds.local_key().unwrap_or_default();
        let remote_key = self.creds.remote_key().unwrap_or_default();

        self.transport
            .connect(&server_host, &pairing_phrase, &local_key, &remote_key)
            .await
            .map_err(LncError::from)?;
        self.connected = true;
        self.sync_remote_key_from_transport();
        Ok(())
    }

    /// Disconnect the current transport session.
    ///
    /// # Errors
    /// Returns [`LncError`] when the transport reports a disconnect failure.
    pub async fn disconnect(&mut self) -> Result<()> {
        self.transport.disconnect().await.map_err(LncError::from)?;
        self.connected = false;
        Ok(())
    }

    /// Returns `true` when the transport has completed `connect`.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Attempt to read the remote key hint from the transport and persist it.
    pub fn sync_remote_key_from_transport(&mut self) {
        if let Some(remote) = self.transport.remote_key_hint() {
            if remote != self.creds.remote_key().unwrap_or_default() {
                self.creds.set_remote_key(remote);
            }
        }
    }

    /// Extract the current macaroon from transport metadata (if present).
    fn macaroon_from_metadata(&self) -> Option<String> {
        self.transport
            .metadata()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("macaroon"))
            .map(|(_, v)| v.clone())
    }

    /// Build a tonic client by supplying a constructor closure over an intercepted service.
    async fn client_with<F>(
        &self,
        ctor: F,
    ) -> Result<proto::lnrpc::lightning_client::LightningClient<LncGrpcService<T>>>
    where
        F: FnOnce(
            LncGrpcService<T>,
        ) -> proto::lnrpc::lightning_client::LightningClient<LncGrpcService<T>>,
        T::Svc: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
        >,
        <T::Svc as tower::Service<http::Request<tonic::body::BoxBody>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    {
        let svc = self.intercepted_service().await?;
        Ok(ctor(svc))
    }

    /// Call lnrpc.Lightning.GetInfo via the transport-backed channel.
    ///
    /// # Errors
    /// Returns [`LncError`] when the RPC fails or the transport channel cannot be created.
    pub async fn get_info(&self) -> Result<proto::lnrpc::GetInfoResponse>
    where
        T::Svc: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
        >,
        <T::Svc as tower::Service<http::Request<tonic::body::BoxBody>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    {
        let mut client = self.lightning_client().await?;
        let res = client
            .get_info(proto::lnrpc::GetInfoRequest {})
            .await
            .map_err(LncError::from)?;
        Ok(res.into_inner())
    }

    /// Call `GetInfo` with a single reconnect retry on transient transport failures.
    ///
    /// # Errors
    /// Returns [`LncError`] if reconnection or the RPC invocation fails.
    pub async fn get_info_retry(&mut self) -> Result<proto::lnrpc::GetInfoResponse>
    where
        T::Svc: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
        >,
        <T::Svc as tower::Service<http::Request<tonic::body::BoxBody>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    {
        // Gate on auth metadata: if missing, reconnect once to capture it.
        let has_macaroon = self
            .transport
            .metadata()
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("macaroon"));
        if !has_macaroon {
            let _ = self.transport.disconnect().await;
            let _ = self.connect().await;
        }

        match self.get_info().await {
            Ok(info) => return Ok(info),
            Err(LncError::GrpcStatus(status))
                if matches!(
                    status.code(),
                    Code::Unknown | Code::Unavailable | Code::Internal | Code::Aborted
                ) => {}
            Err(LncError::Transport(_)) => {}
            Err(other) => return Err(other),
        }

        let _ = self.transport.disconnect().await;
        self.connected = false;
        self.connect().await?;
        self.get_info().await
    }

    /// Returns the underlying gRPC service for building custom clients.
    ///
    /// This is useful when you need clients beyond [`LightningClient`], such as
    /// `WalletKitClient` or `RouterClient`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use lnd_rs::proto::walletrpc::wallet_kit_client::WalletKitClient;
    ///
    /// let svc = lnc.service().await?;
    /// let mut wallet_kit = WalletKitClient::new(svc);
    /// ```
    ///
    /// # Errors
    /// Returns [`LncError`] when the transport service cannot be created.
    pub async fn service(&self) -> Result<LncGrpcService<T>>
    where
        T::Svc: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
        >,
        <T::Svc as tower::Service<http::Request<tonic::body::BoxBody>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    {
        self.intercepted_service().await
    }

    /// Returns the transport metadata for manual interceptor setup.
    ///
    /// This provides access to the per-request headers (typically the macaroon)
    /// that the transport captured during connection.
    pub fn transport_metadata(&self) -> Vec<(String, String)> {
        self.transport.metadata()
    }

    /// Construct an lnrpc.Lightning client bound to the active LNC channel.
    ///
    /// # Errors
    /// Returns [`LncError`] when establishing the intercepted service fails.
    pub async fn lightning_client(
        &self,
    ) -> Result<proto::lnrpc::lightning_client::LightningClient<LncGrpcService<T>>>
    where
        T::Svc: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
        >,
        <T::Svc as tower::Service<http::Request<tonic::body::BoxBody>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    {
        // Use with_origin so tonic sets :authority on HTTP/2 requests. Without
        // an origin, path-only requests may not be routed by the server.
        let server_host = self
            .creds
            .server_host()
            .or_else(|| self.config.server_host.clone())
            .unwrap_or_else(|| DEFAULT_SERVER_HOST.to_string());
        let origin: http::Uri = format!("http://{server_host}")
            .parse::<http::Uri>()
            .map_err(|e: http::uri::InvalidUri| {
                TransportError::connection("invalid static origin", e)
            })?;
        self.client_with(move |svc| {
            proto::lnrpc::lightning_client::LightningClient::with_origin(svc, origin)
        })
        .await
    }

    /// Construct a Lightning client bound to the given channel and transport metadata.
    ///
    /// # Errors
    /// Returns [`LncError`] if `server_host` cannot be converted into an HTTP origin.
    pub fn lightning_client_with_service(
        &self,
        svc: <T as Transport>::Svc,
    ) -> Result<proto::lnrpc::lightning_client::LightningClient<LncGrpcService<T>>>
    where
        T::Svc: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
        >,
        <T::Svc as tower::Service<http::Request<tonic::body::BoxBody>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    {
        let interceptor = LncInterceptor {
            md: self.transport.metadata(),
        };
        let svc = InterceptedService::new(svc, interceptor);
        let server_host = self
            .creds
            .server_host()
            .or_else(|| self.config.server_host.clone())
            .unwrap_or_else(|| DEFAULT_SERVER_HOST.to_string());
        let origin: http::Uri =
            format!("http://{server_host}")
                .parse()
                .map_err(|e: http::uri::InvalidUri| {
                    TransportError::connection("invalid static origin", e)
                })?;
        Ok(proto::lnrpc::lightning_client::LightningClient::with_origin(svc, origin))
    }

    async fn intercepted_service(&self) -> Result<LncGrpcService<T>>
    where
        T::Svc: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
        >,
        <T::Svc as tower::Service<http::Request<tonic::body::BoxBody>>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    {
        let svc = self.transport.service().await.map_err(LncError::from)?;
        let interceptor = LncInterceptor {
            md: self.transport.metadata(),
        };
        Ok(InterceptedService::new(svc, interceptor))
    }
}

#[derive(Clone)]
pub struct LncInterceptor {
    md: Vec<(String, String)>,
}

impl TonicInterceptor for LncInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        for (k, v) in &self.md {
            let val = tonic::metadata::MetadataValue::try_from(v.as_str())
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            let key = tonic::metadata::AsciiMetadataKey::from_bytes(k.as_bytes())
                .map_err(|_| tonic::Status::internal("invalid metadata key"))?;
            req.metadata_mut().insert(key, val);
        }
        Ok(req)
    }
}
