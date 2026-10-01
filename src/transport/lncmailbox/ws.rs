#![cfg(feature = "transport-mailbox")]

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::SinkExt;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::debug;

mod connect;
mod envelope;
mod receive;

#[cfg(test)]
use envelope::decode_cipher_box;

const RECEIVE_PATH: &str = "/v1/lightning-node-connect/hashmail/receive?method=POST";
const SEND_PATH: &str = "/v1/lightning-node-connect/hashmail/send?method=POST";

/// Timeouts used when establishing and sending over the mailbox websocket endpoints.
#[derive(Clone, Copy, Debug)]
pub struct WsTimeouts {
    pub connect: Duration,
    pub send: Duration,
}

impl WsTimeouts {
    #[must_use]
    /// Build a timeout tuple for websocket connect and send operations.
    pub const fn new(connect: Duration, send: Duration) -> Self {
        Self { connect, send }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("receive retention budget exceeded")]
    ReceiveLimit,
    #[error("websocket closed")]
    Closed,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("decode error: {0}")]
    Decode(String),
}

impl WsError {
    #[must_use]
    pub fn status_hint(&self) -> &str {
        match self {
            WsError::Server(msg) => msg.as_str(),
            _ => "",
        }
    }
}

/// Client-side receive stream bound to the hashmail `/receive` endpoint.
pub struct MailboxRecv {
    addr: String,
    stream_id: Vec<u8>,
    socket: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    timeouts: WsTimeouts,
    resolved_address: Option<std::net::SocketAddr>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

/// Client-side send stream bound to the hashmail `/send` endpoint.
pub struct MailboxSend {
    addr: String,
    stream_id: Vec<u8>,
    socket: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    timeouts: WsTimeouts,
    resolved_address: Option<std::net::SocketAddr>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

/// Build paired websocket send/receive handles for the provided stream identifiers.
pub fn mailbox_pair(
    addr: impl Into<String>,
    recv_sid: Vec<u8>,
    send_sid: Vec<u8>,
    timeouts: WsTimeouts,
) -> (MailboxRecv, MailboxSend) {
    mailbox_pair_with_resolved_address(addr, recv_sid, send_sid, timeouts, None)
}

/// Build streams using one caller-resolved address for every connection attempt.
///
/// The original authority is retained for TLS and HTTP. No additional DNS work
/// occurs when an address is supplied; the caller owns resolution and refresh.
pub fn mailbox_pair_with_resolved_address(
    addr: impl Into<String>,
    recv_sid: Vec<u8>,
    send_sid: Vec<u8>,
    timeouts: WsTimeouts,
    resolved_address: Option<std::net::SocketAddr>,
) -> (MailboxRecv, MailboxSend) {
    mailbox_pair_with_tls_config(addr, recv_sid, send_sid, timeouts, resolved_address, None)
}

/// Shared construction keeps caller TLS policy identical on both streams.
pub(crate) fn mailbox_pair_with_tls_config(
    addr: impl Into<String>,
    recv_sid: Vec<u8>,
    send_sid: Vec<u8>,
    timeouts: WsTimeouts,
    resolved_address: Option<std::net::SocketAddr>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
) -> (MailboxRecv, MailboxSend) {
    let addr = addr.into();
    (
        MailboxRecv {
            addr: addr.clone(),
            stream_id: recv_sid,
            socket: None,
            timeouts,
            resolved_address,
            tls_config: tls_config.clone(),
        },
        MailboxSend {
            addr,
            stream_id: send_sid,
            socket: None,
            timeouts,
            resolved_address,
            tls_config,
        },
    )
}

impl MailboxSend {
    pub fn is_connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Establish the send-side websocket connection.
    ///
    /// # Errors
    /// Returns a [`WsError`] when connecting to the hashmail server fails.
    pub async fn ensure_connected(&mut self) -> Result<(), WsError> {
        if self.socket.is_some() {
            return Ok(());
        }
        let url = format!("wss://{}{}", self.addr, SEND_PATH);
        debug!(target: "lnd_rs::mailbox::ws", "send connecting");
        let ws = match timeout(
            self.timeouts.connect,
            connect::open(&url, self.resolved_address, self.tls_config.clone()),
        )
        .await
        {
            Ok(Ok(socket)) => socket,
            Ok(Err(e)) => return Err(WsError::Transport(e.to_string())),
            Err(_) => return Err(WsError::Transport("send connect timeout".into())),
        };
        debug!(target: "lnd_rs::mailbox::ws", "send connected");
        self.socket = Some(ws);
        Ok(())
    }

    /// Send an encrypted payload over the mailbox transport.
    ///
    /// # Errors
    /// Returns a [`WsError`] when the websocket send operation or timeout fails.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), WsError> {
        let socket = self
            .socket
            .as_mut()
            .ok_or_else(|| WsError::Transport("send socket not connected".into()))?;
        let boxed = build_cipher_box(&self.stream_id, payload)?;
        let send_fut = socket.send(Message::Text(boxed.into()));
        match timeout(self.timeouts.send, send_fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                debug!(target: "lnd_rs::mailbox::ws", "send socket error; reconnecting");
                self.socket = None;
                Err(WsError::Transport(err.to_string()))
            }
            Err(_) => {
                debug!(target: "lnd_rs::mailbox::ws", "send timeout; reconnecting");
                self.socket = None;
                Err(WsError::Transport("send timeout".into()))
            }
        }
    }

    pub async fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.close(None).await;
        }
    }
}

#[derive(Serialize)]
struct DescPayload<'a> {
    #[serde(rename = "stream_id")]
    stream_id: &'a str,
}

#[derive(Serialize)]
struct CipherBox<'a> {
    desc: DescPayload<'a>,
    #[serde(rename = "msg")]
    msg: &'a str,
}

fn build_desc(stream_id: &[u8]) -> Result<String, WsError> {
    let sid = STANDARD.encode(stream_id);
    // Use proto JSON field name `stream_id` to match the server.
    serde_json::to_string(&serde_json::json!({ "stream_id": sid }))
        .map_err(|e| WsError::Decode(e.to_string()))
}

fn build_cipher_box(stream_id: &[u8], payload: &[u8]) -> Result<String, WsError> {
    let sid = STANDARD.encode(stream_id);
    let msg = STANDARD.encode(payload);
    serde_json::to_string(&CipherBox {
        desc: DescPayload { stream_id: &sid },
        msg: &msg,
    })
    .map_err(|e| WsError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_wrapper_preserves_ciphertext_and_skips_unused_fields() {
        let raw = r#"{"result":{"msg":"aGVsbG8="}}"#;
        assert_eq!(decode_cipher_box(raw).unwrap(), b"hello");
        let extended = r#"{"ignored":[0,{"nested":true}],"result":{"desc":{"stream_id":"unused"},"extra":[1,2,3],"msg":"aGVsbG8="}}"#;
        assert_eq!(decode_cipher_box(extended).unwrap(), b"hello");
        let escaped = r#"{"result":{"msg":"aGVsbG8\u003d"}}"#;
        assert_eq!(decode_cipher_box(escaped).unwrap(), b"hello");
        for invalid in [
            r#"[{"msg":"aGVsbG8="},null]"#,
            r#"{"result":{"msg":"!"}}"#,
            r#"{"result":{"extra":[]}}"#,
        ] {
            assert!(matches!(
                decode_cipher_box(invalid),
                Err(WsError::Decode(_))
            ));
        }
    }

    #[test]
    fn typed_wrapper_preserves_server_status() {
        let raw = r#"{"error":{"code":3,"message":"stream not found"}}"#;
        let err = decode_cipher_box(raw).unwrap_err();
        match err {
            WsError::Server(msg) => assert!(msg.contains("stream not found")),
            other => panic!("unexpected error {other:?}"),
        }
    }
}
