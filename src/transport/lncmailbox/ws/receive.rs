use super::super::receive_budget::ReceiveBudget;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tracing::debug;

use super::{build_desc, connect, envelope::decode_cipher_box, MailboxRecv, WsError, RECEIVE_PATH};

impl MailboxRecv {
    pub fn is_connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Establish the websocket connection if it is not already active.
    ///
    /// # Errors
    /// Returns a [`WsError`] when the underlying websocket connect or initialization fails.
    pub async fn ensure_connected(&mut self) -> Result<(), WsError> {
        if self.socket.is_some() {
            return Ok(());
        }
        let url = format!("wss://{}{}", self.addr, RECEIVE_PATH);
        debug!(target: "lnd_rs::mailbox::ws", "recv connecting");
        let mut ws = match timeout(
            self.timeouts.connect,
            connect::open(&url, self.resolved_address, self.tls_config.clone()),
        )
        .await
        {
            Ok(Ok(socket)) => socket,
            Ok(Err(e)) => return Err(WsError::Transport(e.to_string())),
            Err(_) => return Err(WsError::Transport("receive connect timeout".into())),
        };
        debug!(target: "lnd_rs::mailbox::ws", "recv connected");
        let _ = ws.get_mut();

        let init = build_desc(&self.stream_id)?;
        let _ = ws.get_mut();
        let send_fut = ws.send(Message::Text(init.into()));
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
        self.receive(None).await.map(|bytes| bytes.to_vec())
    }

    pub(in crate::transport::lncmailbox) async fn recv_budgeted(
        &mut self,
        budget: &ReceiveBudget,
    ) -> Result<Bytes, WsError> {
        self.receive(Some(budget)).await
    }

    async fn receive(&mut self, budget: Option<&ReceiveBudget>) -> Result<Bytes, WsError> {
        loop {
            let socket = self
                .socket
                .as_mut()
                .ok_or_else(|| WsError::Transport("receive socket not connected".into()))?;
            match socket.next().await {
                Some(Ok(Message::Text(txt))) => {
                    return match budget {
                        Some(budget) => super::envelope::decode_budgeted(&txt, budget),
                        None => decode_cipher_box(&txt).map(Bytes::from),
                    };
                }
                Some(Ok(Message::Binary(data))) => {
                    return match budget {
                        Some(budget) => {
                            let mut buffer = budget
                                .allocate(data.len())
                                .map_err(|()| WsError::ReceiveLimit)?;
                            buffer.as_mut_slice().copy_from_slice(&data);
                            Ok(buffer.finish(data.len()))
                        }
                        None => Ok(data),
                    };
                }
                Some(Ok(Message::Ping(payload))) => {
                    let _ = socket.send(Message::Pong(payload)).await;
                }
                Some(Ok(Message::Close(_))) | None => {
                    debug!(target: "lnd_rs::mailbox::ws", "recv socket closed; reconnecting");
                    self.socket = None;
                    return Err(WsError::Closed);
                }
                Some(Err(err)) => {
                    debug!(target: "lnd_rs::mailbox::ws", "recv socket error; reconnecting");
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
