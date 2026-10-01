//! The synchronous Noise machine bridges bounded control messages into async I/O.

use std::{
    io::{self, Read, Write},
    sync::Arc,
};
use tokio::{runtime::Handle, sync::watch};

use super::{
    to_io_error, BrontideMachine, ClientConn, ClientConnError, ControlMsg, GoBackNConnError,
    NoiseConnError, CONTROL_VERSION,
};
use tracing::trace;

pub(super) async fn perform_handshake(
    client: Arc<ClientConn>,
    machine: BrontideMachine,
) -> Result<BrontideMachine, NoiseConnError> {
    let handle = Handle::current();
    let (cancellation, cancelled) = watch::channel(false);
    // This owner lives in the async future, not its blocking task. Dropping a
    // timed-out handshake wakes any bridge read/write before runtime shutdown.
    let _cancellation = CancelHandshake(cancellation);
    tokio::task::spawn_blocking(move || {
        let mut io = BlockingControlIo::new(client, handle, cancelled);
        let mut machine = machine;
        machine
            .do_handshake(&mut io)
            .map_err(|e| NoiseConnError::Handshake(e.to_string()))?;
        Ok::<_, NoiseConnError>(machine)
    })
    .await
    .map_err(|e| NoiseConnError::Handshake(e.to_string()))?
}

struct CancelHandshake(watch::Sender<bool>);

impl Drop for CancelHandshake {
    fn drop(&mut self) {
        // A completed worker has dropped its receiver; cancellation then has
        // nothing left to wake and its send failure is explicitly harmless.
        let _ = self.0.send(true);
    }
}

/// Wait for one control operation while the async handshake owner remains live.
/// Cancellation uses a watch wakeup and needs no runtime timer or socket progress.
fn wait_control<T>(
    handle: &Handle,
    cancelled: &mut watch::Receiver<bool>,
    operation: impl std::future::Future<Output = Result<T, ClientConnError>>,
) -> Result<T, ClientConnError> {
    if *cancelled.borrow() {
        return Err(ClientConnError::Closed);
    }
    handle.block_on(async {
        tokio::select! {
            biased;
            _ = cancelled.changed() => Err(ClientConnError::Closed),
            result = operation => result,
        }
    })
}

struct BlockingControlIo {
    client: Arc<ClientConn>,
    handle: Handle,
    cancelled: watch::Receiver<bool>,
    buffer: bytes::Bytes,
    offset: usize,
}

impl BlockingControlIo {
    fn new(client: Arc<ClientConn>, handle: Handle, cancelled: watch::Receiver<bool>) -> Self {
        Self {
            client,
            handle,
            cancelled,
            buffer: bytes::Bytes::new(),
            offset: 0,
        }
    }

    fn fill_buffer(&mut self) -> io::Result<()> {
        // Keep attempting to read next control message; treat GBN RecvTimeout
        // as a soft timeout and continue waiting during handshake.
        loop {
            match wait_control(
                &self.handle,
                &mut self.cancelled,
                self.client.receive_control_msg(),
            ) {
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
            payload: buf.to_vec().into(),
        };
        trace!(target: "lnd_rs::noise::io", bytes = buf.len(), "write control msg");
        wait_control(
            &self.handle,
            &mut self.cancelled,
            self.client.send_control_msg(&msg),
        )
        .map_err(to_io_error)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
