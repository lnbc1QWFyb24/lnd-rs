#![cfg(feature = "transport-mailbox")]

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{debug, trace};

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
}

/// Client-side send stream bound to the hashmail `/send` endpoint.
pub struct MailboxSend {
    addr: String,
    stream_id: Vec<u8>,
    socket: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    timeouts: WsTimeouts,
}

/// Build paired websocket send/receive handles for the provided stream identifiers.
pub fn mailbox_pair(
    addr: impl Into<String>,
    recv_sid: Vec<u8>,
    send_sid: Vec<u8>,
    timeouts: WsTimeouts,
) -> (MailboxRecv, MailboxSend) {
    let addr = addr.into();
    (
        MailboxRecv {
            addr: addr.clone(),
            stream_id: recv_sid,
            socket: None,
            timeouts,
        },
        MailboxSend {
            addr,
            stream_id: send_sid,
            socket: None,
            timeouts,
        },
    )
}

impl MailboxRecv {
    pub fn is_connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Establish the websocket connection if it is not already active.
    ///
    /// # Errors
    /// Returns a [`WsError`] when the underlying websocket connect or initialization fails.
    #[allow(unused_mut)]
    pub async fn ensure_connected(&mut self) -> Result<(), WsError> {
        if self.socket.is_some() {
            return Ok(());
        }
        let url = format!("wss://{}{}", self.addr, RECEIVE_PATH);
        debug!(target: "lnd_rs::mailbox::ws", %url, "recv connecting");
        #[allow(unused_mut)]
        let (mut ws, _) = match timeout(self.timeouts.connect, connect_async(&url)).await {
            Ok(Ok(tuple)) => tuple,
            Ok(Err(e)) => return Err(WsError::Transport(e.to_string())),
            Err(_) => return Err(WsError::Transport("receive connect timeout".into())),
        };
        debug!(target: "lnd_rs::mailbox::ws", "recv connected");
        let _ = ws.get_mut();

        let init = build_desc(&self.stream_id)?;
        trace!(
            target: "lnd_rs::mailbox::ws",
            init_json = %init,
            stream_id_b64 = %base64::engine::general_purpose::STANDARD.encode(&self.stream_id),
            "recv init"
        );
        let _ = ws.get_mut();
        let send_fut = ws.send(Message::Text(init));
        timeout(self.timeouts.send, send_fut)
            .await
            .map_err(|_| WsError::Transport("receive init timeout".into()))?
            .map_err(|e| WsError::Transport(e.to_string()))?;
        debug!(target: "lnd_rs::mailbox::ws", "recv sent init");

        self.socket = Some(ws);
        Ok(())
    }

    /// Receive the next payload from the mailbox stream.
    ///
    /// # Errors
    /// Returns a [`WsError`] when the websocket closes, the server reports an error, or the
    /// payload cannot be decoded.
    pub async fn recv(&mut self) -> Result<Vec<u8>, WsError> {
        loop {
            let socket = self
                .socket
                .as_mut()
                .ok_or_else(|| WsError::Transport("receive socket not connected".into()))?;
            match socket.next().await {
                Some(Ok(Message::Text(txt))) => {
                    let unwrapped = strip_json_wrapper(&txt)?;
                    let msg = parse_cipher_box(&unwrapped)?;
                    return Ok(msg);
                }
                Some(Ok(Message::Binary(data))) => return Ok(data),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = socket.send(Message::Pong(payload)).await;
                }
                Some(Ok(Message::Close(_))) | None => {
                    debug!(target: "lnd_rs::mailbox::ws", "recv socket closed; reconnecting");
                    self.socket = None;
                    return Err(WsError::Closed);
                }
                Some(Err(err)) => {
                    debug!(target: "lnd_rs::mailbox::ws", error = %err, "recv socket error; reconnecting");
                    self.socket = None;
                    return Err(WsError::Transport(err.to_string()));
                }
                Some(Ok(_)) => {}
            }
        }
    }

    pub async fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.close(None).await;
        }
    }
}

impl MailboxSend {
    pub fn is_connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Establish the send-side websocket connection.
    ///
    /// # Errors
    /// Returns a [`WsError`] when connecting to the hashmail server fails.
    #[allow(unused_mut)]
    pub async fn ensure_connected(&mut self) -> Result<(), WsError> {
        if self.socket.is_some() {
            return Ok(());
        }
        let url = format!("wss://{}{}", self.addr, SEND_PATH);
        debug!(target: "lnd_rs::mailbox::ws", %url, "send connecting");
        #[allow(unused_mut)]
        let (mut ws, _) = match timeout(self.timeouts.connect, connect_async(&url)).await {
            Ok(Ok(tuple)) => tuple,
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
        // Log the stream_id to verify it's correct
        trace!(
            target: "lnd_rs::mailbox::ws",
            stream_id_b64 = %base64::engine::general_purpose::STANDARD.encode(&self.stream_id),
            "send target"
        );
        // For small control frames (e.g. SYN/SYNACK/ACK/NACK), log the full JSON payload.
        if payload.len() <= 8 {
            trace!(target: "lnd_rs::mailbox::ws", payload_json = %boxed, "send small payload");
        }
        let send_fut = socket.send(Message::Text(boxed));
        match timeout(self.timeouts.send, send_fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                debug!(target: "lnd_rs::mailbox::ws", error = %err, "send socket error; reconnecting");
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

#[derive(Deserialize)]
struct CipherBoxResp {
    #[serde(rename = "msg")]
    msg: String,
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

fn parse_cipher_box(inner: &str) -> Result<Vec<u8>, WsError> {
    let parsed: CipherBoxResp =
        serde_json::from_str(inner).map_err(|e| WsError::Decode(e.to_string()))?;
    STANDARD
        .decode(parsed.msg.as_bytes())
        .map_err(|e| WsError::Decode(e.to_string()))
}

fn strip_json_wrapper(wrapped: &str) -> Result<String, WsError> {
    let value: serde_json::Value =
        serde_json::from_str(wrapped).map_err(|e| WsError::Decode(e.to_string()))?;
    match value {
        serde_json::Value::Object(mut map) => {
            if let Some(result) = map.remove("result") {
                serde_json::to_string(&result).map_err(|e| WsError::Decode(e.to_string()))
            } else if let Some(err) = map.remove("error") {
                let err_str = err
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| serde_json::to_string(&err).ok())
                    .unwrap_or_else(|| "unknown mailbox error".to_string());
                Err(WsError::Server(err_str))
            } else {
                Err(WsError::Decode("missing result/error fields".into()))
            }
        }
        _ => Err(WsError::Decode("unexpected JSON envelope".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_wrapper_success() {
        let raw = r#"{"result":{"msg":"aGVsbG8="}}"#;
        let inner = strip_json_wrapper(raw).expect("unwrap");
        assert_eq!(inner, r#"{"msg":"aGVsbG8="}"#);
    }

    #[test]
    fn strip_wrapper_error() {
        let raw = r#"{"error":{"code":3,"message":"stream not found"}}"#;
        let err = strip_json_wrapper(raw).unwrap_err();
        match err {
            WsError::Server(msg) => assert!(msg.contains("stream not found")),
            other => panic!("unexpected error {other:?}"),
        }
    }
}
