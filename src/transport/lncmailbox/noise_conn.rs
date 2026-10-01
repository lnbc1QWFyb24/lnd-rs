#![cfg(feature = "transport-mailbox")]

use std::{
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, Mutex as AsyncMutex},
    task::JoinHandle,
};
use tracing::debug;

use super::{
    conn::{ClientConn, ClientConnError, ControlMsg},
    gbn::GoBackNConnError,
    noise_machine::{BrontideMachine, BrontideMachineConfig, NoiseError},
};

mod handshake;
mod reader;
use handshake::perform_handshake;
use reader::reader_loop;

const MAX_WRITE_CHUNK: usize = 32 * 1024;
const CONTROL_VERSION: u8 = 0;

#[derive(Debug, thiserror::Error)]
pub enum NoiseConnError {
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("noise error: {0}")]
    Noise(#[from] NoiseError),
    #[error("client error: {0}")]
    Client(#[from] ClientConnError),
}

pub struct NoiseConn {
    client: Arc<ClientConn>,
    machine: Arc<AsyncMutex<BrontideMachine>>,
    reader: mpsc::Receiver<Vec<u8>>,
    reader_task: JoinHandle<()>,
    reader_err: Arc<Mutex<Option<NoiseConnError>>>,
    read_buf: BytesMut,
    write_fut: Option<BoxFuture<'static, Result<usize, NoiseConnError>>>,
    shutdown_fut: Option<BoxFuture<'static, Result<(), NoiseConnError>>>,
}

impl Unpin for NoiseConn {}

impl NoiseConn {
    /// Build a `NoiseConn` around an existing mailbox client connection.
    ///
    /// # Errors
    /// Propagates [`NoiseConnError`] values when the Noise handshake or underlying transport setup
    /// fails.
    ///
    /// # Panics
    /// Panics if the reader error mutex is poisoned, which should never occur under normal
    /// operation.
    pub async fn connect(
        client: Arc<ClientConn>,
        cfg: BrontideMachineConfig,
    ) -> Result<Self, NoiseConnError> {
        debug!(target: "lnd_rs::noise", "building machine");
        let machine = BrontideMachine::new(cfg)?;
        debug!(target: "lnd_rs::noise", "starting handshake");
        // Apply a slightly generous handshake read timeout to avoid borderline timing.
        client.set_recv_timeout(Some(std::time::Duration::from_secs(10)));
        let handshake_res = perform_handshake(client.clone(), machine).await;
        // Reset timeout post-handshake attempt.
        client.set_recv_timeout(None);
        let machine = handshake_res.inspect_err(|_| {
            debug!(target: "lnd_rs::noise", "handshake failed");
        })?;
        debug!(target: "lnd_rs::noise", "handshake complete");
        Ok(Self::from_established(client, machine))
    }

    /// Start the owned reader after the machine's authenticated handshake.
    fn from_established(client: Arc<ClientConn>, machine: BrontideMachine) -> Self {
        let machine = Arc::new(AsyncMutex::new(machine));

        let (tx, rx) = mpsc::channel(32);
        let reader_err = Arc::new(Mutex::new(None));
        let reader_client = client.clone();
        let reader_machine = machine.clone();
        let reader_err_clone = reader_err.clone();
        let reader_task = tokio::spawn(async move {
            if let Err(err) = reader_loop(reader_client, reader_machine, tx).await {
                *reader_err_clone.lock() = Some(err);
            }
        });

        Self {
            client,
            machine,
            reader: rx,
            reader_task,
            reader_err,
            read_buf: BytesMut::new(),
            write_fut: None,
            shutdown_fut: None,
        }
    }

    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, NoiseConnError>> {
        if let Some(fut) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    self.write_fut = None;
                    Poll::Ready(res)
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }

    fn poll_shutdown_future(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), NoiseConnError>> {
        if let Some(fut) = self.shutdown_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    self.shutdown_fut = None;
                    Poll::Ready(res)
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_write(&mut self, chunk: Vec<u8>) {
        let client = self.client.clone();
        let machine = self.machine.clone();
        self.write_fut = Some(Box::pin(async move {
            let mut guard = machine.lock().await;
            guard.write_message(&chunk).map_err(NoiseConnError::Noise)?;
            let mut writer = VecWriter::default();
            guard.flush(&mut writer).map_err(NoiseConnError::Noise)?;
            drop(guard);

            let msg = ControlMsg {
                version: CONTROL_VERSION,
                payload: writer.into_inner().into(),
            };
            client.send_control_msg(&msg).await?;
            Ok(chunk.len())
        }));
    }
}

#[cfg(test)]
#[path = "noise_conn/read_tests.rs"]
mod read_tests;

impl AsyncRead for NoiseConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_buf.is_empty() {
            match Pin::new(&mut self.reader).poll_recv(cx) {
                Poll::Ready(Some(chunk)) => self.read_buf.extend_from_slice(&chunk),
                Poll::Ready(None) => {
                    if let Some(err) = self.reader_err.lock().take() {
                        return Poll::Ready(Err(io::Error::other(err.to_string())));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let available = self.read_buf.len().min(buf.remaining());
        if available == 0 {
            return Poll::Ready(Ok(()));
        }
        buf.put_slice(&self.read_buf.split_to(available));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for NoiseConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.write_fut.is_some() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                Poll::Ready(Err(err)) => {
                    self.write_fut = None;
                    return Poll::Ready(Err(io::Error::other(err.to_string())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk_len = buf.len().min(MAX_WRITE_CHUNK);
        self.start_write(buf[..chunk_len].to_vec());
        match self.poll_pending_write(cx) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => {
                self.write_fut = None;
                Poll::Ready(Err(io::Error::other(err.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.poll_pending_write(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => {
                self.write_fut = None;
                Poll::Ready(Err(io::Error::other(err.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.write_fut.is_some() {
            if let Poll::Ready(res) = self.poll_pending_write(cx) {
                if let Err(err) = res {
                    self.write_fut = None;
                    return Poll::Ready(Err(io::Error::other(err.to_string())));
                }
            } else {
                return Poll::Pending;
            }
        }

        if self.shutdown_fut.is_none() {
            let client = self.client.clone();
            self.shutdown_fut = Some(Box::pin(async move {
                client.close().await;
                Ok(())
            }));
        }

        match self.poll_shutdown_future(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for NoiseConn {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

#[derive(Default)]
struct VecWriter(Vec<u8>);

impl VecWriter {
    fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn to_io_error(err: ClientConnError) -> io::Error {
    match err {
        ClientConnError::Gbn(GoBackNConnError::Closed) => {
            io::Error::new(io::ErrorKind::UnexpectedEof, err.to_string())
        }
        other => io::Error::other(other.to_string()),
    }
}
