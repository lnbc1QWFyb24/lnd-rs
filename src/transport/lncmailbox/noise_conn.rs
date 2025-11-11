#![cfg(feature = "transport-mailbox")]

use std::{
    io::{self, Cursor, Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::Handle,
    sync::{mpsc, Mutex as AsyncMutex},
    task::JoinHandle,
};
use tracing::{debug, trace};

use super::{
    conn::{ClientConn, ClientConnError, ControlMsg},
    gbn::GoBackNConnError,
    noise_machine::{BrontideMachine, BrontideMachineConfig, NoiseError},
};

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
        let machine = handshake_res.map_err(|e| {
            debug!(target: "lnd_rs::noise", error = %e, "handshake failed");
            e
        })?;
        debug!(target: "lnd_rs::noise", "handshake complete");
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

        Ok(Self {
            client,
            machine,
            reader: rx,
            reader_task,
            reader_err,
            read_buf: BytesMut::new(),
            write_fut: None,
            shutdown_fut: None,
        })
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
                payload: writer.into_inner(),
            };
            client.send_control_msg(&msg).await?;
            Ok(chunk.len())
        }));
    }
}

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

async fn reader_loop(
    client: Arc<ClientConn>,
    machine: Arc<AsyncMutex<BrontideMachine>>,
    tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), NoiseConnError> {
    // Use a blocking IO adapter so the Noise machine can read across
    // multiple control messages as a contiguous stream, matching the Go
    // ProxyConn behavior. A single Noise ciphertext can span multiple
    // control frames at the mailbox layer.
    // Async reader that avoids holding the Noise machine lock while waiting on I/O.
    // We buffer ciphertext from control messages and only lock the machine when
    // decrypting headers/bodies. This prevents a read-side lock from blocking
    // write-side acks (e.g., HTTP/2 SETTINGS ACK) and eliminates deadlocks.
    const HDR_LEN: usize = super::noise_machine::ENC_HEADER_SIZE; // 2 + MAC(16)
    let mut cipher_buf = BytesMut::new();
    loop {
        // Ensure we have at least one full encrypted header in the buffer.
        while cipher_buf.len() < HDR_LEN {
            match client.receive_control_msg().await {
                Ok(msg) => {
                    trace!(target: "lnd_rs::noise::io", bytes = msg.payload.len(), "async read control msg");
                    cipher_buf.extend_from_slice(&msg.payload);
                }
                Err(ClientConnError::Gbn(GoBackNConnError::RecvTimeout)) => {
                    // Soft timeout: keep waiting for data.
                }
                Err(ClientConnError::Gbn(GoBackNConnError::Closed)) => return Ok(()),
                Err(err) => return Err(NoiseConnError::from(err)),
            }
        }

        // Decrypt the header to learn the body length. Hold the machine lock
        // only for the decrypt operation, not while we wait for more bytes.
        let pkt_len = {
            let mut guard = machine.lock().await;
            let mut cur = Cursor::new(&cipher_buf[..HDR_LEN]);
            guard.read_header(&mut cur)?
        } as usize;

        // Ensure we have the entire ciphertext body available.
        let total = HDR_LEN + pkt_len;
        while cipher_buf.len() < total {
            match client.receive_control_msg().await {
                Ok(msg) => {
                    trace!(target: "lnd_rs::noise::io", bytes = msg.payload.len(), "async read control msg");
                    cipher_buf.extend_from_slice(&msg.payload);
                }
                Err(ClientConnError::Gbn(GoBackNConnError::RecvTimeout)) => {}
                Err(ClientConnError::Gbn(GoBackNConnError::Closed)) => return Ok(()),
                Err(err) => return Err(NoiseConnError::from(err)),
            }
        }

        // Decrypt body with a short-lived lock, then emit plaintext upwards.
        let body_cipher = &cipher_buf[HDR_LEN..total];
        let plaintext = {
            let mut guard = machine.lock().await;
            let mut cur = Cursor::new(body_cipher);
            // read_body consumes from the reader into an owned buf to decrypt.
            let mut tmp = body_cipher.to_vec();
            guard.read_body(&mut cur, &mut tmp)?
        };

        // Consume the processed ciphertext (header + body).
        cipher_buf.advance(total);

        if tx.send(plaintext).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn perform_handshake(
    client: Arc<ClientConn>,
    machine: BrontideMachine,
) -> Result<BrontideMachine, NoiseConnError> {
    let handle = Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut io = BlockingControlIo::new(client, handle);
        let mut machine = machine;
        machine
            .do_handshake(&mut io)
            .map_err(|e| NoiseConnError::Handshake(e.to_string()))?;
        Ok::<_, NoiseConnError>(machine)
    })
    .await
    .map_err(|e| NoiseConnError::Handshake(e.to_string()))?
}

struct BlockingControlIo {
    client: Arc<ClientConn>,
    handle: Handle,
    buffer: Vec<u8>,
    offset: usize,
}

impl BlockingControlIo {
    fn new(client: Arc<ClientConn>, handle: Handle) -> Self {
        Self {
            client,
            handle,
            buffer: Vec::new(),
            offset: 0,
        }
    }

    fn fill_buffer(&mut self) -> io::Result<()> {
        // Keep attempting to read next control message; treat GBN RecvTimeout
        // as a soft timeout and continue waiting during handshake.
        loop {
            match self.handle.block_on(self.client.receive_control_msg()) {
                Ok(msg) => {
                    trace!(target: "lnd_rs::noise::io", bytes = msg.payload.len(), "read control msg");
                    self.buffer = msg.payload;
                    self.offset = 0;
                    return Ok(());
                }
                Err(ClientConnError::Gbn(GoBackNConnError::RecvTimeout)) => {
                    // Retry on receive timeout during handshake/transport.
                }
                Err(err) => return Err(to_io_error(err)),
            }
        }
    }
}

impl Read for BlockingControlIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.offset == self.buffer.len() {
            self.fill_buffer()?;
        }
        let remaining = self.buffer.len() - self.offset;
        let to_copy = remaining.min(buf.len());
        buf[..to_copy].copy_from_slice(&self.buffer[self.offset..self.offset + to_copy]);
        self.offset += to_copy;
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        }
        Ok(to_copy)
    }
}

impl Write for BlockingControlIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let msg = ControlMsg {
            version: CONTROL_VERSION,
            payload: buf.to_vec(),
        };
        trace!(target: "lnd_rs::noise::io", bytes = buf.len(), "write control msg");
        self.handle
            .block_on(self.client.send_control_msg(&msg))
            .map_err(to_io_error)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
