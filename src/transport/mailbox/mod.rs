#[cfg(feature = "transport-mailbox")]
mod connect;
#[cfg(feature = "transport-mailbox")]
mod http2;
#[cfg(feature = "transport-mailbox")]
mod state;

#[cfg(feature = "transport-mailbox")]
use self::{
    connect::MailboxConnectContext,
    http2::Http2Channel,
    state::{parse_auth_metadata, MailboxState},
};
#[cfg(feature = "transport-mailbox")]
use crate::{
    config::MailboxConfig,
    transport::lncmailbox::{
        conn::{ClientConn, ClientConnParams, ClientStatus},
        noise_conn::NoiseConn,
        noise_machine::BrontideMachineConfig,
        ws::WsTimeouts,
    },
};
use async_trait::async_trait;
#[cfg(feature = "transport-mailbox")]
use hyper::client::conn::http2 as hyper_http2;
#[cfg(feature = "transport-mailbox")]
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
#[cfg(feature = "transport-mailbox")]
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
#[cfg(feature = "transport-mailbox")]
use std::sync::Arc;
#[cfg(feature = "transport-mailbox")]
use tokio::{sync::watch, time::timeout};
// no Endpoint usage in the HTTP/2 prior-knowledge path
#[cfg(not(feature = "transport-mailbox"))]
use tonic::transport::Channel;

#[cfg(feature = "transport-mailbox")]
type MailboxSvc = Http2Channel;
#[cfg(not(feature = "transport-mailbox"))]
type MailboxSvc = Channel;

use super::{Transport, TransportError};
use crate::PairingCredentials;
#[cfg(feature = "transport-mailbox")]
use tracing::{debug, trace};

/// Implementation of the [`Transport`] trait that speaks the Lightning Node Connect mailbox stack.
///
/// The mailbox transport tunnels a Noise-encrypted HTTP/2 channel over the hashmail websocket
/// endpoints, matching the behavior of the reference Go client.
pub struct MailboxTransport {
    pub server_host: Option<String>,
    last_remote_key: Option<String>,
    #[cfg(feature = "transport-mailbox")]
    config: MailboxConfig,
    #[cfg(feature = "transport-mailbox")]
    state: Option<MailboxState>,
}

impl MailboxTransport {
    #[must_use]
    pub fn new(server_host: Option<String>) -> Self {
        Self {
            server_host,
            last_remote_key: None,
            #[cfg(feature = "transport-mailbox")]
            config: MailboxConfig::default(),
            #[cfg(feature = "transport-mailbox")]
            state: None,
        }
    }

    #[cfg(feature = "transport-mailbox")]
    #[must_use]
    /// Construct a mailbox transport with explicit runtime tuning parameters.
    pub fn with_mailbox_config(server_host: Option<String>, config: MailboxConfig) -> Self {
        Self {
            server_host,
            last_remote_key: None,
            config,
            state: None,
        }
    }

    #[cfg(feature = "transport-mailbox")]
    #[must_use]
    /// Return the remote static key captured during the last mailbox session.
    pub fn remote_key_hex(&self) -> Option<String> {
        self.last_remote_key.clone()
    }

    #[cfg(feature = "transport-mailbox")]
    #[must_use]
    /// Return the last observed mailbox client status.
    pub fn client_status(&self) -> ClientStatus {
        self.state
            .as_ref()
            .map_or(ClientStatus::NotConnected, |state| {
                *state.status_rx.borrow()
            })
    }

    #[cfg(feature = "transport-mailbox")]
    async fn connect_mailbox_client(
        &self,
        server_host: &str,
        ctx: &MailboxConnectContext,
    ) -> Result<(Arc<ClientConn>, watch::Receiver<ClientStatus>), TransportError> {
        let params = ClientConnParams {
            recv_sid: ctx.recv_sid,
            send_sid: ctx.send_sid,
            gbn_opts: self.config.gbn.clone(),
            retry_wait: self.config.retry_wait,
            timeouts: WsTimeouts::new(self.config.ws_connect_timeout, self.config.ws_send_timeout),
        };
        let client = timeout(
            self.config.session_timeout,
            ClientConn::connect(server_host, params),
        )
        .await
        .map_err(|_| {
            TransportError::connection_message("mailbox connect timed out before handshake")
        })?
        .map_err(|e| TransportError::connection("mailbox connect failed", e))?;
        let client = Arc::new(client);
        let status_rx = client.subscribe_status();
        Ok((client, status_rx))
    }

    #[cfg(feature = "transport-mailbox")]
    async fn perform_noise_handshake(
        &self,
        client: Arc<ClientConn>,
        cfg: BrontideMachineConfig,
        status_rx: watch::Receiver<ClientStatus>,
    ) -> Result<NoiseConn, TransportError> {
        debug!(target: "lnd_rs::mailbox", "starting noise handshake");
        let attempt = timeout(self.config.session_timeout, NoiseConn::connect(client, cfg))
            .await
            .map_err(|_| {
                TransportError::connection_message("noise handshake timed out before HTTP/2")
            })?;
        match attempt {
            Ok(conn) => {
                debug!(target: "lnd_rs::mailbox", "noise handshake complete");
                Ok(conn)
            }
            Err(e) => {
                debug!(target: "lnd_rs::mailbox", error = %e, "noise connect error");
                let hint = Self::status_hint(*status_rx.borrow());
                if let Some(prefix) = hint {
                    Err(TransportError::connection_message(format!("{prefix}: {e}")))
                } else {
                    Err(TransportError::connection("noise handshake failed", e))
                }
            }
        }
    }

    #[cfg(feature = "transport-mailbox")]
    async fn establish_http2_channel(
        &self,
        noise_conn: NoiseConn,
        server_host: &str,
    ) -> Result<Http2Channel, TransportError> {
        debug!(target: "lnd_rs::mailbox", "establishing HTTP/2 connection");
        let io = TokioIo::new(noise_conn);
        let mut builder = hyper_http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        let keepalive = &self.config.http2_keepalive;
        builder.keep_alive_interval(keepalive.interval);
        builder.keep_alive_timeout(keepalive.timeout);
        builder.keep_alive_while_idle(keepalive.while_idle);
        let (send_request, conn) = timeout(self.config.session_timeout, builder.handshake(io))
            .await
            .map_err(|_| {
                TransportError::connection_message("HTTP/2 handshake timed out over Noise tunnel")
            })?
            .map_err(|e| TransportError::connection("HTTP/2 handshake failed", e))?;
        tokio::spawn(async move {
            trace!(target: "lnd_rs::mailbox::http2", "driver started");
            let res = conn.await;
            match res {
                Ok(()) => trace!(target: "lnd_rs::mailbox::http2", "driver finished (ok)"),
                Err(e) => {
                    debug!(target: "lnd_rs::mailbox::http2", error = %e, "connection error");
                }
            }
        });
        debug!(target: "lnd_rs::mailbox", "HTTP/2 connection established");
        let authority = server_host
            .parse::<http::uri::Authority>()
            .map_err(|e| TransportError::connection("invalid mailbox authority", e))?;
        Ok(Http2Channel::new(send_request, authority))
    }

    #[cfg(feature = "transport-mailbox")]
    fn capture_session_state(
        ctx: &MailboxConnectContext,
    ) -> (Arc<[(String, String)]>, Option<String>) {
        let metadata_buf = ctx.auth_capture.lock();
        let metadata = parse_auth_metadata(metadata_buf.as_slice());
        drop(metadata_buf);
        if metadata.is_empty() {
            debug!(target: "lnd_rs::mailbox", "auth metadata: <none>");
        } else {
            for (k, v) in &metadata {
                if k.eq_ignore_ascii_case("macaroon") {
                    debug!(target: "lnd_rs::mailbox", macaroon_len = v.len(), "auth metadata: macaroon");
                } else {
                    debug!(target: "lnd_rs::mailbox", key = %k, value = %v, "auth metadata");
                }
            }
        }
        let metadata = Arc::from(metadata.into_boxed_slice());
        let remote_key_hex = ctx
            .remote_hint
            .lock()
            .as_ref()
            .map(|pk| hex::encode(pk.to_encoded_point(true).as_bytes()));
        (metadata, remote_key_hex)
    }

    #[cfg(feature = "transport-mailbox")]
    fn status_hint(status: ClientStatus) -> Option<&'static str> {
        match status {
            ClientStatus::SessionNotFound => Some("mailbox session not found"),
            ClientStatus::SessionInUse => Some("mailbox session in use"),
            _ => None,
        }
    }
}

#[async_trait]
impl Transport for MailboxTransport {
    type Svc = MailboxSvc;
    /// Generate pairing credentials for the mailbox transport.
    ///
    /// Derives a fresh random 32-byte local private key (hex-encoded). The remote static key is
    /// learned during the Noise handshake.
    async fn pair(
        &mut self,
        server_host: &str,
        pairing_phrase: &str,
    ) -> Result<PairingCredentials, TransportError> {
        // Generate a random 32-byte local private key (hex). In the full
        // implementation this key is used for Noise handshake and reconnection.
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let local_key = hex::encode(bytes);

        Ok(PairingCredentials {
            server_host: server_host.to_string(),
            pairing_phrase: pairing_phrase.to_string(),
            local_key,
            // Remote static pubkey will be learned during handshake.
            remote_key: String::new(),
            macaroon_hex: None,
        })
    }

    /// Establish the mailbox transport and perform Noise + HTTP/2 handshakes.
    ///
    /// For the XX handshake path (no remote key hint), the passphrase stretching uses a blocking
    /// task via `tokio::task::spawn_blocking` to avoid stalling the async runtime.
    async fn connect(
        &mut self,
        server_host: &str,
        pairing_phrase: &str,
        _local_key: &str,
        _remote_key: &str,
    ) -> Result<(), TransportError> {
        #[cfg(not(feature = "transport-mailbox"))]
        {
            let _ = (server_host, pairing_phrase);
            return Err(TransportError::NotImplemented);
        }
        #[cfg(feature = "transport-mailbox")]
        {
            let ctx = MailboxConnectContext::new_async(
                server_host,
                pairing_phrase,
                _local_key,
                _remote_key,
            )
            .await?;
            let (client, status_rx) = self.connect_mailbox_client(server_host, &ctx).await?;
            let noise_conn = self
                .perform_noise_handshake(client.clone(), ctx.builder.build(), status_rx.clone())
                .await?;
            let svc = self
                .establish_http2_channel(noise_conn, server_host)
                .await?;
            let (metadata, remote_key_hex) = Self::capture_session_state(&ctx);

            self.last_remote_key.clone_from(&remote_key_hex);
            if let Some(ref rk) = self.last_remote_key {
                debug!(target: "lnd_rs::mailbox", remote_key = %rk, "remote key captured");
            }
            self.state = Some(MailboxState {
                client,
                svc,
                metadata,
                status_rx,
            });
            Ok(())
        }
    }

    async fn service(&self) -> Result<Self::Svc, TransportError> {
        #[cfg(not(feature = "transport-mailbox"))]
        {
            Err(TransportError::NotImplemented)
        }
        #[cfg(feature = "transport-mailbox")]
        {
            self.state.as_ref().map(|s| s.svc.clone()).ok_or_else(|| {
                TransportError::connection_message("mailbox transport not connected")
            })
        }
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        #[cfg(feature = "transport-mailbox")]
        {
            if let Some(state) = self.state.take() {
                state.client.close().await;
            }
        }
        Ok(())
    }

    fn metadata(&self) -> Vec<(String, String)> {
        #[cfg(feature = "transport-mailbox")]
        {
            if let Some(state) = &self.state {
                return state.metadata.iter().cloned().collect();
            }
        }
        Vec::new()
    }

    fn remote_key_hint(&self) -> Option<String> {
        self.last_remote_key.clone()
    }
}
