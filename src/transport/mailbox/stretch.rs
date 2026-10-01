//! Fixed-cost pairing work whose lifetime is independent of a caller runtime.
//!
//! One process-owned thread runs the existing AEZEED scrypt implementation; one
//! additional request may queue. Started work is not cancellable. A dropped
//! caller discards its result and queued work is skipped when its reply closes.
//! This avoids an uncancellable Tokio blocking task delaying runtime shutdown.

use std::{
    sync::{mpsc, OnceLock},
    thread::JoinHandle,
};

use tokio::sync::oneshot;

use crate::transport::{lncmailbox::crypto, TransportError};

const PAIRING_ENTROPY_BYTES: usize = 14;
const QUEUED_REQUESTS: usize = 1;

struct Request {
    entropy: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, String>>,
}

/// The static worker owns the thread until process exit; it never joins on drop.
struct Worker {
    sender: mpsc::SyncSender<Request>,
    _thread: JoinHandle<()>,
}

impl Worker {
    fn submit(
        &self,
        entropy: Vec<u8>,
    ) -> Result<oneshot::Receiver<Result<Vec<u8>, String>>, TransportError> {
        if entropy.len() != PAIRING_ENTROPY_BYTES {
            return Err(TransportError::connection_message(
                "invalid pairing entropy length",
            ));
        }
        let (reply, receiver) = oneshot::channel();
        self.sender
            .try_send(Request { entropy, reply })
            .map_err(|error| {
                let message = match error {
                    mpsc::TrySendError::Full(_) => "pairing worker busy",
                    mpsc::TrySendError::Disconnected(_) => "pairing worker unavailable",
                };
                TransportError::connection_message(message)
            })?;
        Ok(receiver)
    }
}

/// Start a concrete bounded queue and its processor on one owned thread.
/// The production caller always supplies the existing scrypt implementation.
fn spawn_worker(
    mut process: impl FnMut(&[u8]) -> Result<Vec<u8>, String> + Send + 'static,
) -> Result<Worker, ()> {
    let (sender, requests) = mpsc::sync_channel::<Request>(QUEUED_REQUESTS);
    let thread = std::thread::Builder::new()
        .name("lnc-pairing".into())
        .spawn(move || {
            while let Ok(request) = requests.recv() {
                if request.reply.is_closed() {
                    continue;
                }
                let result = process(&request.entropy);
                // Caller cancellation is explicit: a dropped reply must never
                // block the worker or turn the retained result into telemetry.
                let _ = request.reply.send(result);
            }
        })
        .map_err(|_| ())?;
    Ok(Worker {
        sender,
        _thread: thread,
    })
}

/// Stretch bounded entropy without creating runtime-owned blocking work.
///
/// Startup failure is retained for the process lifetime. Busy callers may retry
/// explicitly; dropping this future abandons its reply without waiting or join.
pub(super) async fn pairing_entropy(entropy: Vec<u8>) -> Result<Vec<u8>, TransportError> {
    static WORKER: OnceLock<Result<Worker, ()>> = OnceLock::new();
    let worker = WORKER
        .get_or_init(|| spawn_worker(crypto::scrypt_stretch))
        .as_ref()
        .map_err(|()| TransportError::connection_message("pairing worker startup failed"))?;
    worker
        .submit(entropy)?
        .await
        .map_err(|_| TransportError::connection_message("pairing worker unavailable"))?
        .map_err(|_| TransportError::connection_message("pairing entropy stretch failed"))
}

#[cfg(test)]
mod tests;
