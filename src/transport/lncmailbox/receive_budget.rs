//! Per-connection admission for receive-side retained allocations.
//!
//! This counts reserved byte capacity, not process RSS. One fixed reservation
//! covers tungstenite 0.29's 64-MiB message assembly, 16-MiB frame buffers and
//! serde's escaped-string scratch/copy (including geometric growth). Payload
//! owners, copies and assembly metadata share the remaining capacity. Admission
//! never waits: saturation shuts down this session, so queues cannot deadlock
//! while retaining the bytes needed by the next receive operation.

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use bytes::Bytes;
use tokio::sync::watch;

pub(super) const RECEIVE_CAPACITY: usize = 576 * 1024 * 1024;
pub(super) const SOCKET_SCRATCH: usize = 384 * 1024 * 1024;
const OWNER_BYTES: usize = 256;

#[derive(Clone)]
pub(super) struct ReceiveBudget(Arc<Inner>);

struct Inner {
    capacity: usize,
    used: AtomicUsize,
    exhausted: AtomicBool,
    shutdown: watch::Sender<bool>,
}

pub(super) struct Reservation {
    budget: ReceiveBudget,
    bytes: usize,
}

struct ReceiveAllocation {
    storage: Vec<u8>,
    _reservation: Reservation,
}

impl AsRef<[u8]> for ReceiveAllocation {
    fn as_ref(&self) -> &[u8] {
        &self.storage
    }
}

impl ReceiveBudget {
    pub(super) fn new(capacity: usize, shutdown: watch::Sender<bool>) -> Self {
        Self(Arc::new(Inner {
            capacity,
            used: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
            shutdown,
        }))
    }

    pub(super) fn reserve(&self, bytes: usize) -> Result<Reservation, ()> {
        if *self.0.shutdown.borrow() {
            return Err(());
        }
        let admitted = self
            .0
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.0.capacity)
            });
        if admitted.is_ok() {
            Ok(Reservation {
                budget: self.clone(),
                bytes,
            })
        } else {
            self.0.exhausted.store(true, Ordering::Release);
            self.0.shutdown.send_replace(true);
            Err(())
        }
    }

    /// Reserve before allocating; Bytes clones and slices retain this same lease.
    pub(super) fn allocate(&self, bytes: usize) -> Result<ReceiveBuffer, ()> {
        let reservation = self.reserve(bytes.checked_add(OWNER_BYTES).ok_or(())?)?;
        Ok(ReceiveBuffer {
            storage: vec![0; bytes],
            reservation,
        })
    }

    pub(super) async fn closed(&self) {
        let mut shutdown = self.0.shutdown.subscribe();
        if !*shutdown.borrow() {
            let _ = shutdown.changed().await;
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        *self.0.shutdown.borrow()
    }

    pub(super) fn exhausted(&self) -> bool {
        self.0.exhausted.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn used(&self) -> usize {
        self.0.used.load(Ordering::Acquire)
    }
}

pub(super) struct ReceiveBuffer {
    storage: Vec<u8>,
    reservation: Reservation,
}

impl ReceiveBuffer {
    pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage
    }

    pub(super) fn finish(mut self, length: usize) -> Bytes {
        self.storage.truncate(length);
        Bytes::from_owner(ReceiveAllocation {
            storage: self.storage,
            _reservation: self.reservation,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests;
