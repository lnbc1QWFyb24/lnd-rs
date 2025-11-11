#![cfg(feature = "transport-mailbox")]

//! Core mailbox connection metadata shared by the WS/GBN layers.

use std::{fmt, sync::Arc, time::Duration};

use bytes::{BufMut, Bytes};
use parking_lot::Mutex;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time,
};
use tracing::{debug, trace};

use super::{
    gbn::{GoBackNConn, GoBackNConnError, GoBackNOptions},
    ws::{mailbox_pair, MailboxRecv, MailboxSend, WsError, WsTimeouts},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientStatus {
    #[default]
    NotConnected,
    SessionNotFound,
    SessionInUse,
    Connected,
}

impl fmt::Display for ClientStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientStatus::NotConnected => write!(f, "Not Connected"),
            ClientStatus::SessionNotFound => write!(f, "Session Not Found"),
            ClientStatus::SessionInUse => write!(f, "Session In Use"),
            ClientStatus::Connected => write!(f, "Connected"),
        }
    }
}

/// Control frames exchanged with the hashmail service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlMsg {
    pub version: u8,
    pub payload: Vec<u8>,
}

impl ControlMsg {
    /// Length of the payload expressed as a `u32`.
    ///
    /// # Panics
    /// Panics if the payload length exceeds `u32::MAX`.
    #[must_use]
    pub fn len(&self) -> u32 {
        let len = u32::try_from(self.payload.len());
        assert!(len.is_ok(), "control payload too large");
        len.unwrap()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + self.payload.len());
        buf.put_u8(self.version);
        buf.put_u32(self.len());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a control message that was emitted by [`ControlMsg::encode`].
    ///
    /// # Errors
    /// Returns an error when the buffer is shorter than five bytes or the embedded length does not
    /// match the payload size.
    pub fn decode(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 5 {
            return Err("control message too short".into());
        }
        let version = buf[0];
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len().saturating_sub(5) != len {
            return Err("control message length mismatch".into());
        }
        Ok(Self {
            version,
            payload: buf[5..].to_vec(),
        })
    }
}

/// Map a mailbox error string to the transport status per the Go client.
#[must_use]
pub fn status_from_error(err: &str) -> ClientStatus {
    let normalized = err.to_ascii_lowercase();
    if normalized.contains("stream not found") {
        ClientStatus::SessionNotFound
    } else if normalized.contains("stream occupied") {
        ClientStatus::SessionInUse
    } else {
        ClientStatus::NotConnected
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientConnError {
    #[error("gbn error: {0}")]
    Gbn(#[from] GoBackNConnError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("connection closed")]
    Closed,
}

/// Configuration used to build a [`ClientConn`].
pub struct ClientConnParams {
    /// Mailbox stream id used for inbound frames.
    pub recv_sid: [u8; 64],
    /// Mailbox stream id used for outbound frames.
    pub send_sid: [u8; 64],
    /// Go-Back-N tuning configured for the connection.
    pub gbn_opts: GoBackNOptions,
    /// Delay applied between websocket reconnect attempts.
    pub retry_wait: Duration,
    /// Websocket timeouts enforced on connect/send operations.
    pub timeouts: WsTimeouts,
}

pub struct ClientConn {
    gbn: Arc<GoBackNConn>,
    status: Arc<StatusHub>,
    shutdown: watch::Sender<bool>,
    send_task: JoinHandle<()>,
    recv_task: JoinHandle<()>,
}

impl ClientConn {
    /// Establish a mailbox transport using the provided stream identifiers.
    ///
    /// # Errors
    /// Returns a [`ClientConnError`] when the websocket, Go-Back-N, or task initialization fails.
    pub async fn connect(
        server_host: &str,
        params: ClientConnParams,
    ) -> Result<Self, ClientConnError> {
        let ClientConnParams {
            recv_sid,
            send_sid,
            gbn_opts,
            retry_wait,
            timeouts,
        } = params;
        debug!(
            target: "lnd_rs::mailbox::conn",
            host = server_host,
            recv_sid_prefix = %hex::encode(&recv_sid[..4]),
            send_sid_prefix = %hex::encode(&send_sid[..4]),
            "ClientConn::connect start"
        );
        let capacity = gbn_opts.window_size.max(1) as usize * 4;
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(capacity);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(capacity);

        let status = StatusHub::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let (mut recv_ws, send_ws) = mailbox_pair(
            server_host.to_string(),
            recv_sid.to_vec(),
            send_sid.to_vec(),
            timeouts,
        );

        // Ensure the receive stream is connected and initialized before any
        // outbound frames (like the initial GBN SYN) are sent. This mirrors
        // the Go client order and prevents a race where the server hasn't
        // yet created the receive stream, leading to "stream not found".
        if let Err(err) = recv_ws.ensure_connected().await {
            debug!(
                target: "lnd_rs::mailbox::conn",
                error = %err,
                hint = %err.status_hint(),
                "eager recv ensure_connected error"
            );
            // We'll proceed; the recv loop will keep retrying.
        } else {
            trace!(target: "lnd_rs::mailbox::conn", "eager recv ensure_connected ok");
        }

        let send_shutdown = shutdown_rx.clone();
        let send_status = status.clone();
        let send_retry_wait = retry_wait;
        let send_task = tokio::spawn(async move {
            trace!(target: "lnd_rs::mailbox::conn", "send_loop spawned");
            send_loop(
                send_ws,
                outbound_rx,
                send_status,
                send_shutdown,
                send_retry_wait,
            )
            .await;
            trace!(target: "lnd_rs::mailbox::conn", "send_loop exited");
        });

        let recv_shutdown = shutdown_rx.clone();
        let recv_status = status.clone();
        let recv_retry_wait = retry_wait;
        let recv_task = tokio::spawn(async move {
            trace!(target: "lnd_rs::mailbox::conn", "recv_loop spawned");
            recv_loop(
                recv_ws,
                inbound_tx,
                recv_status,
                recv_shutdown,
                recv_retry_wait,
            )
            .await;
            trace!(target: "lnd_rs::mailbox::conn", "recv_loop exited");
        });

        debug!(target: "lnd_rs::mailbox::conn", "WS tasks spawned; starting GBN handshake");

        // Now build the GBN connection which will send SYN immediately. The
        // send/recv loops are active to carry handshake frames.
        let gbn = match GoBackNConn::connect(gbn_opts, outbound_tx, inbound_rx).await {
            Ok(g) => g,
            Err(e) => {
                let _ = shutdown_tx.send(true);
                send_task.abort();
                recv_task.abort();
                return Err(ClientConnError::from(e));
            }
        };
        let gbn = Arc::new(gbn);

        debug!(target: "lnd_rs::mailbox::conn", "ClientConn::connect done (GBN ready)");
        Ok(Self {
            gbn,
            status,
            shutdown: shutdown_tx,
            send_task,
            recv_task,
        })
    }

    #[must_use]
    pub fn gbn(&self) -> Arc<GoBackNConn> {
        self.gbn.clone()
    }

    #[must_use]
    pub fn status(&self) -> ClientStatus {
        self.status.current()
    }

    #[must_use]
    pub fn subscribe_status(&self) -> watch::Receiver<ClientStatus> {
        self.status.subscribe()
    }

    pub fn set_send_timeout(&self, timeout: Option<Duration>) {
        self.gbn.set_send_timeout(timeout);
    }

    pub fn set_recv_timeout(&self, timeout: Option<Duration>) {
        self.gbn.set_recv_timeout(timeout);
    }

    /// Receive the next control message from the mailbox transport.
    ///
    /// # Errors
    /// Returns a [`ClientConnError`] when the underlying connection closes or the message cannot be
    /// decoded.
    pub async fn receive_control_msg(&self) -> Result<ControlMsg, ClientConnError> {
        let payload = self.gbn.recv().await.map_err(ClientConnError::from)?;
        ControlMsg::decode(&payload).map_err(ClientConnError::Protocol)
    }

    /// Send a control message to the remote mailbox peer.
    ///
    /// # Errors
    /// Returns a [`ClientConnError`] when the framed send fails.
    pub async fn send_control_msg(&self, msg: &ControlMsg) -> Result<(), ClientConnError> {
        self.gbn
            .send_frame(Bytes::from(msg.encode()))
            .await
            .map_err(ClientConnError::from)
    }

    pub async fn close(&self) {
        let _ = self.shutdown.send(true);
        let _ = self.gbn.close().await;
        self.send_task.abort();
        self.recv_task.abort();
    }
}

impl Drop for ClientConn {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.send_task.abort();
        self.recv_task.abort();
    }
}

#[derive(Debug)]
struct StatusHub {
    tx: watch::Sender<ClientStatus>,
    state: Mutex<ClientStatus>,
}

impl StatusHub {
    fn new() -> Arc<Self> {
        let (tx, _) = watch::channel(ClientStatus::NotConnected);
        Arc::new(Self {
            tx,
            state: Mutex::new(ClientStatus::NotConnected),
        })
    }

    fn set(&self, status: ClientStatus) {
        let mut guard = self.state.lock();
        if status == ClientStatus::NotConnected
            && matches!(
                *guard,
                ClientStatus::SessionInUse | ClientStatus::SessionNotFound
            )
        {
            return;
        }
        if *guard != status {
            *guard = status;
            let _ = self.tx.send(status);
            debug!(target: "lnd_rs::mailbox::conn", %status, "status updated");
        }
    }

    fn current(&self) -> ClientStatus {
        *self.state.lock()
    }

    fn subscribe(&self) -> watch::Receiver<ClientStatus> {
        self.tx.subscribe()
    }
}

async fn send_loop(
    mut socket: MailboxSend,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    status: Arc<StatusHub>,
    mut shutdown: watch::Receiver<bool>,
    retry_wait: Duration,
) {
    trace!(target: "lnd_rs::mailbox::conn", "send_loop ready (awaiting outbound)");
    while let Some(mut frame) = recv_with_shutdown(&mut outbound_rx, &mut shutdown).await {
        trace!(target: "lnd_rs::mailbox::conn", bytes = frame.len(), "send_loop got frame");
        loop {
            if *shutdown.borrow() {
                return;
            }
            if let Err(err) = socket.ensure_connected().await {
                debug!(target: "lnd_rs::mailbox::conn", error = %err, "send ensure_connected error");
                status.set(status_from_ws_error(&err));
                if wait_retry(&mut shutdown, retry_wait).await {
                    return;
                }
                continue;
            }

            match socket.send(&frame).await {
                Ok(()) => {
                    status.set(ClientStatus::Connected);
                    break;
                }
                Err(err) => {
                    debug!(target: "lnd_rs::mailbox::conn", error = %err, "send error");
                    let mapped = status_from_ws_error(&err);
                    status.set(mapped);
                    // Retry on all errors to mirror Go client behavior.
                    if wait_retry(&mut shutdown, retry_wait).await {
                        return;
                    }
                }
            }
        }
        frame.clear();
    }
}

async fn recv_loop(
    mut socket: MailboxRecv,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    status: Arc<StatusHub>,
    mut shutdown: watch::Receiver<bool>,
    retry_wait: Duration,
) {
    debug!(target: "lnd_rs::mailbox::conn", "recv_loop start");
    loop {
        if *shutdown.borrow() {
            return;
        }

        if !socket.is_connected() {
            trace!(target: "lnd_rs::mailbox::conn", "recv ensure_connected attempting");
            if let Err(err) = socket.ensure_connected().await {
                debug!(target: "lnd_rs::mailbox::conn", error = %err, hint = %err.status_hint(), "recv ensure_connected error");
                status.set(status_from_ws_error(&err));
                if wait_retry(&mut shutdown, retry_wait).await {
                    return;
                }
                continue;
            }
            trace!(target: "lnd_rs::mailbox::conn", "recv ensure_connected ok");
        }

        match socket.recv().await {
            Ok(frame) => {
                status.set(ClientStatus::Connected);
                trace!(target: "lnd_rs::mailbox::conn", bytes = frame.len(), "recv_loop got frame");
                if send_with_shutdown(&inbound_tx, frame, &mut shutdown)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(err) => {
                debug!(target: "lnd_rs::mailbox::conn", error = %err, hint = %err.status_hint(), "recv error");
                let mapped = status_from_ws_error(&err);
                status.set(mapped);
                // Always retry creating/connecting the receive stream; even
                // "stream not found" can be transient while the server sets up.
                if wait_retry(&mut shutdown, retry_wait).await {
                    return;
                }
            }
        }
    }
}

fn status_from_ws_error(err: &WsError) -> ClientStatus {
    match err {
        WsError::Server(msg) => status_from_error(msg),
        _ => ClientStatus::NotConnected,
    }
}

// Note: We intentionally don't special-case fatal statuses here; the WS loops
// retry on all errors similar to the Go client.

async fn recv_with_shutdown<T>(
    rx: &mut mpsc::Receiver<T>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<T> {
    tokio::select! {
        res = rx.recv() => res,
        _ = shutdown.changed() => None,
    }
}

async fn send_with_shutdown(
    tx: &mpsc::Sender<Vec<u8>>,
    data: Vec<u8>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    tokio::select! {
        res = tx.send(data) => res.map_err(|_| ()),
        _ = shutdown.changed() => Err(()),
    }
}

async fn wait_retry(shutdown: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        () = time::sleep(delay) => false,
        _ = shutdown.changed() => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_message_roundtrip() {
        let msg = ControlMsg {
            version: 2,
            payload: b"hello".to_vec(),
        };
        let enc = msg.encode();
        let dec = ControlMsg::decode(&enc).expect("decode");
        assert_eq!(dec, msg);
    }

    #[test]
    fn status_mapping() {
        assert_eq!(
            status_from_error("stream not found"),
            ClientStatus::SessionNotFound
        );
        assert_eq!(
            status_from_error("STREAM OCCUPIED"),
            ClientStatus::SessionInUse
        );
        assert_eq!(status_from_error("oops"), ClientStatus::NotConnected);
    }
}
