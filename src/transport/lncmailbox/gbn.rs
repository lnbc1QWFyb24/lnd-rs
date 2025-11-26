#![cfg(feature = "transport-mailbox")]

//! Minimal Go-Back-N connection manager built on top of wire primitives.
//! The wire-level opcodes and frame encoding/decoding live in `gbn_wire.rs`.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use tokio::{
    pin,
    sync::{mpsc, oneshot, Mutex, Notify},
    task::JoinHandle,
    time,
};
use tracing::{debug, trace};

pub use crate::transport::lncmailbox::gbn_wire::{
    Frame, GbnError, ACK, DATA, FIN, NACK, SYN, SYNACK,
};

const NO_TIMEOUT: u64 = u64::MAX;

// Re-export wire frame types so external paths remain stable.

fn encode_timeout(duration: Option<Duration>) -> u64 {
    match duration {
        Some(dur) => {
            let nanos = dur.as_nanos();
            if nanos >= u128::from(NO_TIMEOUT) {
                NO_TIMEOUT - 1
            } else {
                u64::try_from(nanos).expect("timeout less than NO_TIMEOUT")
            }
        }
        None => NO_TIMEOUT,
    }
}

fn decode_timeout(raw: u64) -> Option<Duration> {
    if raw == NO_TIMEOUT {
        None
    } else {
        Some(Duration::from_nanos(raw))
    }
}

/// Client-side tuning knobs for the Rust implementation. Matches the Go defaults.
#[derive(Clone, Debug)]
pub struct GoBackNOptions {
    pub resend_multiplier: u32,
    pub timeout_update_frequency: u32,
    pub handshake_timeout_ms: u64,
    pub keepalive_ping_ms: u64,
    pub pong_timeout_ms: u64,
    pub boost_percent: f32,
    pub window_size: u8,
    pub max_chunk_size: usize,
    pub send_timeout_ms: Option<u64>,
    pub recv_timeout_ms: Option<u64>,
}

impl Default for GoBackNOptions {
    fn default() -> Self {
        Self {
            resend_multiplier: 5,
            timeout_update_frequency: 200,
            handshake_timeout_ms: 2000,
            keepalive_ping_ms: 7000,
            pong_timeout_ms: 3000,
            boost_percent: 0.5,
            window_size: 16, // gbn.DefaultN in Go
            max_chunk_size: 32 * 1024,
            send_timeout_ms: None,
            recv_timeout_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedFrame {
    pub payload: Bytes,
    pub final_chunk: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GoBackNConnError {
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("connection closed")]
    Closed,
    #[error("send timed out")]
    SendTimeout,
    #[error("receive timed out")]
    RecvTimeout,
    #[error("transport closed")]
    TransportClosed,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    #[error("io error: {0}")]
    Io(String),
}

struct InFlight {
    seq: u8,
    frame: Frame,
    sent_at: Instant,
    attempts: u32,
}

struct SendState {
    next_seq: u8,
    inflight: VecDeque<InFlight>,
    fin_sent: bool,
}

struct RecvState {
    expected_seq: u8,
    remote_closed: bool,
}

struct PendingPing {
    seq: u8,
    sent_at: Instant,
}

struct Inner {
    opts: GoBackNOptions,
    outbound: mpsc::Sender<Vec<u8>>,
    send_state: Mutex<SendState>,
    recv_state: Mutex<RecvState>,
    recv_tx: mpsc::Sender<RecvEvent>,
    window: Notify,
    closed: AtomicBool,
    last_remote: Mutex<Instant>,
    timeout: Mutex<Duration>,
    handshake_complete: AtomicBool,
    ack_counter: AtomicU32,
    send_timeout_ns: AtomicU64,
    recv_timeout_ns: AtomicU64,
    pending_ping: Mutex<Option<PendingPing>>,
    non_ping_acked: AtomicBool,
    // Gate to hold back the first non-ping DATA immediately after sending
    // SYNACK until we observe any inbound frame or a short timeout. This
    // prevents early DATA from racing the server's handshake completion.
    post_synack_gate: Notify,
    gate_required: AtomicBool,
}

impl Inner {
    fn new(
        opts: GoBackNOptions,
        outbound: mpsc::Sender<Vec<u8>>,
        recv_tx: mpsc::Sender<RecvEvent>,
    ) -> Self {
        let send_timeout = opts.send_timeout_ms.map(Duration::from_millis);
        let recv_timeout = opts.recv_timeout_ms.map(Duration::from_millis);
        Self {
            opts,
            outbound,
            send_state: Mutex::new(SendState {
                next_seq: 0,
                inflight: VecDeque::new(),
                fin_sent: false,
            }),
            recv_state: Mutex::new(RecvState {
                expected_seq: 0,
                remote_closed: false,
            }),
            recv_tx,
            window: Notify::new(),
            closed: AtomicBool::new(false),
            last_remote: Mutex::new(Instant::now()),
            timeout: Mutex::new(Duration::from_millis(400)),
            handshake_complete: AtomicBool::new(false),
            ack_counter: AtomicU32::new(0),
            send_timeout_ns: AtomicU64::new(encode_timeout(send_timeout)),
            recv_timeout_ns: AtomicU64::new(encode_timeout(recv_timeout)),
            pending_ping: Mutex::new(None),
            non_ping_acked: AtomicBool::new(false),
            post_synack_gate: Notify::new(),
            gate_required: AtomicBool::new(false),
        }
    }

    fn enable_post_synack_gate(&self) {
        self.gate_required.store(true, Ordering::SeqCst);
        debug!(target: "lnd_rs::gbn", "post-synack gate enabled");
    }

    fn maybe_release_post_synack_gate(&self) {
        if self.handshake_complete.load(Ordering::SeqCst)
            && self.gate_required.swap(false, Ordering::SeqCst)
        {
            self.post_synack_gate.notify_waiters();
        }
    }

    async fn wait_post_synack_gate(&self, is_ping: bool) {
        if is_ping {
            return;
        }
        if !self.gate_required.load(Ordering::SeqCst) {
            return;
        }
        trace!(target: "lnd_rs::gbn", "post-synack gate waiting for inbound or timeout");
        let notified = self.post_synack_gate.notified();
        // Use a short fallback to avoid stalling upper-layer handshakes (e.g. HTTP/2 preface).
        let fallback = time::sleep(Duration::from_millis(200));
        tokio::select! {
            () = notified => { trace!(target: "lnd_rs::gbn", "post-synack gate released by inbound"); },
            () = fallback => { trace!(target: "lnd_rs::gbn", "post-synack gate released by timeout"); },
        }
    }

    async fn send_raw(&self, frame: Frame) -> Result<(), GoBackNConnError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(GoBackNConnError::Closed);
        }
        let encoded = frame.encode();
        match &frame {
            Frame::Data {
                is_ping, payload, ..
            } if !*is_ping => {
                // Log control-msg header preview if present: version + length.
                let pl = payload.as_ref();
                if pl.len() >= 5 {
                    let ver = pl[0];
                    let len = u32::from_be_bytes([pl[1], pl[2], pl[3], pl[4]]);
                    trace!(target: "lnd_rs::gbn::inner", ctl_ver = ver, ctl_len = len, payload_len = pl.len(), "send_raw DATA(non-ping)");
                } else {
                    trace!(target: "lnd_rs::gbn::inner", payload_len = pl.len(), "send_raw DATA(non-ping) short payload");
                }
            }
            _ => {
                trace!(target: "lnd_rs::gbn::inner", frame = ?frame, bytes = encoded.len(), "send_raw");
            }
        }
        self.outbound
            .send(encoded)
            .await
            .map_err(|_| GoBackNConnError::TransportClosed)
    }

    async fn update_rtt(&self, sample: Duration) {
        let mut timeout = self.timeout.lock().await;
        let blend = f64::from(self.opts.boost_percent.clamp(0.01, 0.99));
        let current = timeout.as_secs_f64();
        let updated = current * (1.0 - blend) + sample.as_secs_f64() * blend;
        let min_timeout = 0.05;
        let mut new_timeout = Duration::from_secs_f64(updated);
        if new_timeout.as_secs_f64() < min_timeout {
            new_timeout = Duration::from_secs_f64(min_timeout);
        }
        let scaled = new_timeout.mul_f64(f64::from(self.opts.resend_multiplier));
        *timeout = scaled;
    }

    async fn retransmit_candidates(&self) -> Vec<Frame> {
        let timeout = { *self.timeout.lock().await };
        let now = Instant::now();
        let mut frames = Vec::new();
        let mut send = self.send_state.lock().await;
        for entry in &mut send.inflight {
            if now.duration_since(entry.sent_at) >= timeout {
                entry.sent_at = now;
                entry.attempts += 1;
                frames.push(entry.frame.clone());
            }
        }
        frames
    }

    async fn handle_ack(&self, ack: u8) {
        let mut send = self.send_state.lock().await;
        let mut to_remove = 0usize;
        let mut rtt_sample = None;
        for entry in &send.inflight {
            if seq_lte(entry.seq, ack) {
                to_remove += 1;
                rtt_sample = Some(Instant::now().saturating_duration_since(entry.sent_at));
            } else {
                break;
            }
        }
        for _ in 0..to_remove {
            if let Some(entry) = send.inflight.pop_front() {
                if let Frame::Data { is_ping, .. } = entry.frame {
                    if !is_ping {
                        self.non_ping_acked.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        if to_remove > 0 {
            self.window.notify_waiters();
        }
        drop(send);
        if let Some(sample) = rtt_sample {
            self.ack_counter.fetch_add(1, Ordering::SeqCst);
            self.update_rtt(sample).await;
        }
        let mut ping = self.pending_ping.lock().await;
        if let Some(p) = ping.as_ref() {
            if seq_lte(p.seq, ack) {
                *ping = None;
            }
        }
    }

    async fn handle_nack(&self, seq: u8) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut send = self.send_state.lock().await;
        for entry in &mut send.inflight {
            if entry.seq == seq {
                entry.sent_at = Instant::now();
                entry.attempts += 1;
                frames.push(entry.frame.clone());
                break;
            }
        }
        frames
    }

    async fn handle_data(
        &self,
        seq: u8,
        final_chunk: bool,
        is_ping: bool,
        payload: Bytes,
    ) -> Option<RecvEvent> {
        let mut recv = self.recv_state.lock().await;
        let expected = recv.expected_seq;
        if seq == expected {
            recv.expected_seq = recv.expected_seq.wrapping_add(1);
            drop(recv);
            let _ = self.send_raw(Frame::Ack { seq }).await;
            if is_ping {
                return None;
            }
            return Some(RecvEvent::Payload(ReceivedFrame {
                payload,
                final_chunk,
            }));
        }
        if seq_lte(seq, expected.wrapping_sub(1)) {
            drop(recv);
            let _ = self.send_raw(Frame::Ack { seq }).await;
            return None;
        }
        drop(recv);
        let _ = self.send_raw(Frame::Nack { seq: expected }).await;
        None
    }

    async fn mark_remote_closed(&self) {
        {
            let mut recv = self.recv_state.lock().await;
            recv.remote_closed = true;
        }
        let _ = self.recv_tx.send(RecvEvent::Fin).await;
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn set_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.window.notify_waiters();
    }

    async fn register_ping(&self, seq: u8) {
        let mut ping = self.pending_ping.lock().await;
        *ping = Some(PendingPing {
            seq,
            sent_at: Instant::now(),
        });
    }

    async fn pending_ping_expired(&self) -> bool {
        let timeout = Duration::from_millis(self.opts.pong_timeout_ms);
        let ping = self.pending_ping.lock().await;
        if let Some(p) = ping.as_ref() {
            return p.sent_at.elapsed() > timeout;
        }
        false
    }

    async fn time_since_remote(&self) -> Duration {
        let last = self.last_remote.lock().await;
        last.elapsed()
    }

    async fn update_remote_activity(&self) {
        let mut last = self.last_remote.lock().await;
        *last = Instant::now();
    }
}

enum RecvEvent {
    Payload(ReceivedFrame),
    Fin,
}

fn seq_lte(a: u8, b: u8) -> bool {
    b.wrapping_sub(a) < 128
}

pub struct GoBackNConn {
    inner: Arc<Inner>,
    data_rx: Mutex<mpsc::Receiver<RecvEvent>>,
    reader: JoinHandle<()>,
    resend_task: JoinHandle<()>,
    keepalive_task: JoinHandle<()>,
}

impl GoBackNConn {
    pub fn set_send_timeout(&self, timeout: Option<Duration>) {
        self.inner.set_send_timeout(timeout);
    }

    pub fn set_recv_timeout(&self, timeout: Option<Duration>) {
        self.inner.set_recv_timeout(timeout);
    }

    /// Build a Go-Back-N connection around the provided outbound/inbound channels.
    ///
    /// Handshake is performed synchronously to mirror the Go client:
    /// send SYN, wait for SYN from server, send SYNACK. Only then are
    /// background tasks (reader/resend/keepalive) spawned.
    ///
    /// # Errors
    /// Returns a [`GoBackNConnError`] when the handshake fails or the transport closes.
    pub async fn connect(
        opts: GoBackNOptions,
        outbound: mpsc::Sender<Vec<u8>>,
        mut inbound: mpsc::Receiver<Vec<u8>>,
    ) -> Result<Self, GoBackNConnError> {
        let (recv_tx, recv_rx) = mpsc::channel::<RecvEvent>(opts.window_size as usize * 4);
        let inner = Arc::new(Inner::new(opts.clone(), outbound.clone(), recv_tx));
        let data_rx = Mutex::new(recv_rx);

        // Synchronous client handshake: SYN -> wait SYN <- then -> SYNACK.
        debug!(target: "lnd_rs::gbn", window = opts.window_size, "-> SYN");
        inner
            .send_raw(Frame::Syn {
                window: opts.window_size,
            })
            .await?;

        let handshake_deadline = Duration::from_millis(opts.handshake_timeout_ms);
        loop {
            // Wait for the server's SYN within the deadline. If timeout, resend SYN.
            match time::timeout(handshake_deadline, inbound.recv()).await {
                Ok(Some(raw)) => {
                    match Frame::decode(&raw) {
                        Ok(Frame::Syn { window }) => {
                            inner.update_remote_activity().await;
                            debug!(target: "lnd_rs::gbn", window, "<- SYN");
                            if window != opts.window_size {
                                return Err(GoBackNConnError::Protocol("window mismatch"));
                            }
                            // Respond with SYNACK, mark handshake complete.
                            inner.send_raw(Frame::SynAck).await?;
                            debug!(target: "lnd_rs::gbn", "-> SYNACK");
                            inner.handshake_complete.store(true, Ordering::SeqCst);
                            inner.enable_post_synack_gate();
                            break;
                        }
                        Ok(Frame::SynAck) => {
                            // Some servers may send SYNACK to ack our SYN.
                            // Treat as liveness during handshake and continue waiting for SYN.
                            debug!(target: "lnd_rs::gbn", "<- SYNACK (waiting for SYN)");
                            inner.update_remote_activity().await;
                        }
                        Ok(other) => {
                            // Ignore non-handshake frames until handshake completes.
                            trace!(target: "lnd_rs::gbn", frame = ?other, "(handshake) ignoring");
                        }
                        Err(_) => {
                            // Ignore undecodable frames.
                        }
                    }
                }
                Ok(None) => return Err(GoBackNConnError::TransportClosed),
                Err(_) => {
                    if inner.is_closed() {
                        return Err(GoBackNConnError::Closed);
                    }
                    debug!(target: "lnd_rs::gbn", window = opts.window_size, "handshake timeout, resending SYN");
                    inner
                        .send_raw(Frame::Syn {
                            window: opts.window_size,
                        })
                        .await?;
                }
            }
        }

        // Only spawn runtime tasks after handshake is complete.
        let reader_inner = inner.clone();
        let reader = tokio::spawn(async move {
            GoBackNConn::reader_loop(reader_inner, inbound, None).await;
        });

        let resend_inner = inner.clone();
        let resend_task = tokio::spawn(async move { GoBackNConn::resend_loop(resend_inner).await });

        let keepalive_inner = inner.clone();
        let keepalive_task = tokio::spawn(async move {
            GoBackNConn::keepalive_loop(keepalive_inner).await;
        });

        Ok(Self {
            inner,
            data_rx,
            reader,
            resend_task,
            keepalive_task,
        })
    }

    async fn reader_loop(
        inner: Arc<Inner>,
        mut inbound: mpsc::Receiver<Vec<u8>>,
        mut handshake: Option<oneshot::Sender<Result<(), GoBackNConnError>>>,
    ) {
        while let Some(raw) = inbound.recv().await {
            match Frame::decode(&raw) {
                Ok(Frame::Syn { window }) => {
                    debug!(target: "lnd_rs::gbn", window, "<- SYN");
                    inner.update_remote_activity().await;
                    let handshake_done = inner.handshake_complete.load(Ordering::SeqCst);
                    if handshake_done {
                        // Ignore stray SYN received after handshake completion.
                        // Some peers may re-initiate due to races; we only treat as activity.
                        continue;
                    }

                    if window != inner.opts.window_size {
                        if let Some(tx) = handshake.take() {
                            let _ = tx.send(Err(GoBackNConnError::Protocol("window mismatch")));
                        }
                        continue;
                    }

                    // When we receive a SYN during handshake, send SYNACK
                    if let Err(err) = inner.send_raw(Frame::SynAck).await {
                        if let Some(tx) = handshake.take() {
                            let _ = tx.send(Err(err));
                        }
                        break;
                    }
                    debug!(target: "lnd_rs::gbn", "-> SYNACK");

                    if !inner.handshake_complete.swap(true, Ordering::SeqCst) {
                        if let Some(tx) = handshake.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }
                }
                Ok(Frame::SynAck) => {
                    // Some servers send SYNACK redundantly; treat as activity.
                    debug!(target: "lnd_rs::gbn", "<- SYNACK");
                    inner.update_remote_activity().await;
                    inner.maybe_release_post_synack_gate();
                }
                Ok(Frame::Ack { seq }) => {
                    trace!(target: "lnd_rs::gbn", seq, "<- ACK");
                    inner.update_remote_activity().await;
                    inner.maybe_release_post_synack_gate();
                    inner.handle_ack(seq).await;
                }
                Ok(Frame::Nack { seq }) => {
                    trace!(target: "lnd_rs::gbn", seq, "<- NACK");
                    inner.update_remote_activity().await;
                    inner.maybe_release_post_synack_gate();
                    let frames = inner.handle_nack(seq).await;
                    for frame in frames {
                        let _ = inner.send_raw(frame).await;
                    }
                }
                Ok(Frame::Data {
                    seq,
                    final_chunk,
                    is_ping,
                    payload,
                }) => {
                    trace!(target: "lnd_rs::gbn", seq, final = final_chunk, ping = is_ping, len = payload.len(), "<- DATA");
                    inner.update_remote_activity().await;
                    inner.maybe_release_post_synack_gate();
                    if let Some(ev) = inner.handle_data(seq, final_chunk, is_ping, payload).await {
                        let _ = inner.recv_tx.send(ev).await;
                    }
                }
                Ok(Frame::Fin) => {
                    debug!(target: "lnd_rs::gbn", "<- FIN");
                    inner.update_remote_activity().await;
                    inner.maybe_release_post_synack_gate();
                    inner.mark_remote_closed().await;
                }
                Err(_) => break,
            }
        }
        if let Some(tx) = handshake {
            let _ = tx.send(Err(GoBackNConnError::TransportClosed));
        }
        inner.set_closed();
    }

    async fn resend_loop(inner: Arc<Inner>) {
        let mut interval = time::interval(Duration::from_millis(u64::from(
            inner.opts.timeout_update_frequency,
        )));
        while !inner.is_closed() {
            interval.tick().await;
            let frames = inner.retransmit_candidates().await;
            for frame in frames {
                let _ = inner.send_raw(frame).await;
            }
        }
    }

    async fn keepalive_loop(inner: Arc<Inner>) {
        let mut interval = time::interval(Duration::from_millis(inner.opts.keepalive_ping_ms));
        while !inner.is_closed() {
            interval.tick().await;
            if inner.is_closed() {
                break;
            }
            if !inner.handshake_complete.load(Ordering::SeqCst) {
                continue;
            }
            if inner.pending_ping_expired().await {
                debug!(target: "lnd_rs::gbn", "keepalive ping expired; closing connection");
                let _ = inner.recv_tx.send(RecvEvent::Fin).await;
                inner.set_closed();
                break;
            }
            let idle = inner.time_since_remote().await;
            let idle_budget =
                Duration::from_millis(inner.opts.keepalive_ping_ms + inner.opts.pong_timeout_ms);
            if idle > idle_budget {
                debug!(
                    target: "lnd_rs::gbn",
                    idle_ms = idle.as_millis(),
                    budget_ms = idle_budget.as_millis(),
                    "keepalive idle budget exceeded; closing connection"
                );
                let _ = inner.recv_tx.send(RecvEvent::Fin).await;
                inner.set_closed();
                break;
            }
            // Defer pings until at least one non-ping data frame has been
            // acknowledged by the remote to avoid interference with early
            // handshake/control messages.
            if !inner.non_ping_acked.load(Ordering::SeqCst) {
                trace!(
                    target: "lnd_rs::gbn",
                    "skipping keepalive ping; no non-ping ack observed yet"
                );
                continue;
            }
            if !inner.has_send_window_capacity().await {
                trace!(
                    target: "lnd_rs::gbn",
                    "skipping keepalive ping; send window is full"
                );
                continue;
            }
            let need_ping = {
                let ping = inner.pending_ping.lock().await;
                ping.is_none()
            };
            if need_ping {
                let send_ping = inner.send_data(Bytes::new(), true, true);
                let budget = Duration::from_millis(inner.opts.pong_timeout_ms);
                match time::timeout(budget, send_ping).await {
                    Ok(Ok(seq)) => inner.register_ping(seq).await,
                    Ok(Err(err)) => {
                        debug!(
                            target: "lnd_rs::gbn",
                            error = %err,
                            "keepalive ping send failed; closing connection"
                        );
                        let _ = inner.recv_tx.send(RecvEvent::Fin).await;
                        inner.set_closed();
                        break;
                    }
                    Err(_) => {
                        debug!(
                            target: "lnd_rs::gbn",
                            "keepalive ping send stalled; closing connection"
                        );
                        let _ = inner.recv_tx.send(RecvEvent::Fin).await;
                        inner.set_closed();
                        break;
                    }
                }
            }
        }
    }

    /// Send a logical frame, chunking it according to the negotiated window.
    ///
    /// # Errors
    /// Returns a [`GoBackNConnError`] when the connection is closed before the send completes.
    pub async fn send_frame(&self, payload: Bytes) -> Result<(), GoBackNConnError> {
        let chunk_size = self.inner.opts.max_chunk_size;
        if chunk_size == 0 || payload.len() <= chunk_size {
            self.inner.send_data(payload, true, false).await?;
            return Ok(());
        }

        let mut offset = 0;
        while offset < payload.len() {
            let end = (offset + chunk_size).min(payload.len());
            let chunk = payload.slice(offset..end);
            let final_chunk = end == payload.len();
            self.inner.send_data(chunk, final_chunk, false).await?;
            offset = end;
        }
        Ok(())
    }

    /// Receive the next framed payload from the transport.
    ///
    /// # Errors
    /// Returns a [`GoBackNConnError`] when the peer closes the connection or the receive times out.
    pub async fn recv_frame(&self) -> Result<ReceivedFrame, GoBackNConnError> {
        let timeout = self.inner.current_recv_timeout();
        let mut rx = self.data_rx.lock().await;
        let recv_fut = rx.recv();
        pin!(recv_fut);
        let item = if let Some(duration) = timeout {
            match time::timeout(duration, recv_fut).await {
                Ok(v) => v,
                Err(_) => return Err(GoBackNConnError::RecvTimeout),
            }
        } else {
            recv_fut.await
        };

        match item {
            Some(RecvEvent::Payload(data)) => Ok(data),
            Some(RecvEvent::Fin) | None => Err(GoBackNConnError::Closed),
        }
    }

    /// Receive and assemble a complete message that may span multiple frames.
    ///
    /// # Errors
    /// Returns a [`GoBackNConnError`] when the connection closes mid-transfer.
    pub async fn recv(&self) -> Result<Bytes, GoBackNConnError> {
        let mut buf = BytesMut::new();
        loop {
            let part = self.recv_frame().await?;
            if !part.payload.is_empty() {
                buf.extend_from_slice(&part.payload);
            }
            if part.final_chunk {
                return Ok(buf.freeze());
            }
        }
    }

    /// Gracefully close the connection by sending `FIN` once.
    ///
    /// # Errors
    /// Returns a [`GoBackNConnError`] when the underlying send fails.
    pub async fn close(&self) -> Result<(), GoBackNConnError> {
        {
            let mut send = self.inner.send_state.lock().await;
            if send.fin_sent {
                return Ok(());
            }
            send.fin_sent = true;
        }
        self.inner.send_raw(Frame::Fin).await
    }
}

impl Inner {
    async fn next_seq(&self) -> u8 {
        let mut send = self.send_state.lock().await;
        let seq = send.next_seq;
        send.next_seq = send.next_seq.wrapping_add(1);
        seq
    }

    async fn send_data(
        &self,
        payload: Bytes,
        final_chunk: bool,
        is_ping: bool,
    ) -> Result<u8, GoBackNConnError> {
        // Defer the first non-ping DATA after SYNACK until we observe any inbound
        // frame (or a short timeout). This reduces early DATA races with the server
        // finishing its handshake.
        self.wait_post_synack_gate(is_ping).await;
        let seq = self.next_seq().await;
        let frame = Frame::Data {
            seq,
            final_chunk,
            is_ping,
            payload,
        };
        self.queue_frame(frame).await?;
        Ok(seq)
    }

    async fn queue_frame(&self, frame: Frame) -> Result<(), GoBackNConnError> {
        loop {
            if self.is_closed() {
                return Err(GoBackNConnError::Closed);
            }
            {
                let mut send = self.send_state.lock().await;
                if send.inflight.len() < self.opts.window_size as usize {
                    let seq = match &frame {
                        Frame::Data { seq, .. } => *seq,
                        _ => 0,
                    };
                    send.inflight.push_back(InFlight {
                        seq,
                        frame: frame.clone(),
                        sent_at: Instant::now(),
                        attempts: 1,
                    });
                    drop(send);
                    self.send_raw(frame).await?;
                    return Ok(());
                }
            }
            self.wait_for_window().await?;
        }
    }

    fn current_send_timeout(&self) -> Option<Duration> {
        decode_timeout(self.send_timeout_ns.load(Ordering::SeqCst))
    }

    fn current_recv_timeout(&self) -> Option<Duration> {
        decode_timeout(self.recv_timeout_ns.load(Ordering::SeqCst))
    }

    fn set_send_timeout(&self, timeout: Option<Duration>) {
        self.send_timeout_ns
            .store(encode_timeout(timeout), Ordering::SeqCst);
    }

    fn set_recv_timeout(&self, timeout: Option<Duration>) {
        self.recv_timeout_ns
            .store(encode_timeout(timeout), Ordering::SeqCst);
    }

    async fn wait_for_window(&self) -> Result<(), GoBackNConnError> {
        if let Some(timeout) = self.current_send_timeout() {
            let notified = self.window.notified();
            pin!(notified);
            time::timeout(timeout, notified)
                .await
                .map_err(|_| GoBackNConnError::SendTimeout)?;
            Ok(())
        } else {
            self.window.notified().await;
            Ok(())
        }
    }

    async fn has_send_window_capacity(&self) -> bool {
        let send = self.send_state.lock().await;
        send.inflight.len() < self.opts.window_size as usize
    }
}

impl Drop for GoBackNConn {
    fn drop(&mut self) {
        self.reader.abort();
        self.resend_task.abort();
        self.keepalive_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::{sync::mpsc, time};

    #[test]
    fn frame_roundtrip_syn() {
        let frame = Frame::Syn { window: 42 };
        let enc = frame.encode();
        assert_eq!(Frame::decode(&enc).unwrap(), frame);
    }

    #[test]
    fn frame_roundtrip_data() {
        let frame = Frame::Data {
            seq: 9,
            final_chunk: true,
            is_ping: false,
            payload: Bytes::from_static(b"hello"),
        };
        let enc = frame.encode();
        assert_eq!(Frame::decode(&enc).unwrap(), frame);
    }

    #[test]
    fn decode_rejects_unknown_opcode() {
        let err = Frame::decode(&[0xff]).unwrap_err();
        assert!(matches!(err, GbnError::UnknownOpcode(0xff)));
    }

    proptest! {
        #[test]
        fn data_frame_roundtrip_prop(seq in any::<u8>(), final_chunk in any::<bool>(), is_ping in any::<bool>(), payload in proptest::collection::vec(any::<u8>(), 0..256)) {
            let frame = Frame::Data {
                seq,
                final_chunk,
                is_ping,
                payload: Bytes::from(payload.clone()),
            };
            let enc = frame.encode();
            let decoded = Frame::decode(&enc).expect("decode");
            if let Frame::Data { seq: d_seq, final_chunk: d_final, is_ping: d_ping, payload: d_payload } = decoded {
                assert_eq!(d_seq, seq);
                assert_eq!(d_final, final_chunk);
                assert_eq!(d_ping, is_ping);
                assert_eq!(d_payload.as_ref(), payload.as_slice());
                assert_eq!(enc.len(), 4 + payload.len());
            } else {
                panic!("decoded non-data frame");
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gbn_data_roundtrip() {
        let (client_to_server_tx, mut client_to_server_rx) = mpsc::channel::<Vec<u8>>(32);
        let (server_to_client_tx, server_to_client_rx) = mpsc::channel::<Vec<u8>>(32);

        tokio::spawn(async move {
            let mut server_seq = 0u8;
            while let Some(raw) = client_to_server_rx.recv().await {
                let frame = Frame::decode(&raw).expect("decode frame");
                match frame {
                    Frame::Syn { window } => {
                        // Mirror server behavior: after receiving client's SYN, send our SYN.
                        let _ = server_to_client_tx
                            .send(Frame::Syn { window }.encode())
                            .await;
                    }
                    Frame::Data {
                        seq,
                        final_chunk,
                        payload,
                        ..
                    } => {
                        let _ = server_to_client_tx.send(Frame::Ack { seq }.encode()).await;
                        let echo = Frame::Data {
                            seq: server_seq,
                            final_chunk,
                            is_ping: false,
                            payload,
                        };
                        server_seq = server_seq.wrapping_add(1);
                        let _ = server_to_client_tx.send(echo.encode()).await;
                    }
                    Frame::Fin => {
                        let _ = server_to_client_tx.send(Frame::Fin.encode()).await;
                        break;
                    }
                    _ => {}
                }
            }
        });

        let conn = GoBackNConn::connect(
            GoBackNOptions::default(),
            client_to_server_tx,
            server_to_client_rx,
        )
        .await
        .expect("connect");

        conn.send_frame(Bytes::from_static(b"hello"))
            .await
            .expect("send");
        let recv = conn.recv().await.expect("recv");
        assert_eq!(recv, Bytes::from_static(b"hello"));
        conn.close().await.expect("close");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gbn_drops_ping_from_remote() {
        let (client_to_server_tx, mut client_to_server_rx) = mpsc::channel::<Vec<u8>>(32);
        let (server_to_client_tx, server_to_client_rx) = mpsc::channel::<Vec<u8>>(32);

        tokio::spawn(async move {
            let mut sent_data = false;
            while let Some(raw) = client_to_server_rx.recv().await {
                let frame = Frame::decode(&raw).expect("decode");
                match frame {
                    Frame::Syn { window } => {
                        // Server sends its own SYN back to client.
                        let _ = server_to_client_tx
                            .send(Frame::Syn { window }.encode())
                            .await;
                    }
                    Frame::SynAck => {
                        // After seeing client's SYNACK, send a ping frame first.
                        let ping = Frame::Data {
                            seq: 0,
                            final_chunk: true,
                            is_ping: true,
                            payload: Bytes::new(),
                        };
                        let _ = server_to_client_tx.send(ping.encode()).await;
                    }
                    Frame::Ack { seq } if seq == 0 && !sent_data => {
                        let data = Frame::Data {
                            seq: 1,
                            final_chunk: true,
                            is_ping: false,
                            payload: Bytes::from_static(b"pong"),
                        };
                        let _ = server_to_client_tx.send(data.encode()).await;
                        sent_data = true;
                    }
                    Frame::Fin => {
                        let _ = server_to_client_tx.send(Frame::Fin.encode()).await;
                        break;
                    }
                    _ => {}
                }
            }
        });

        let conn = GoBackNConn::connect(
            GoBackNOptions::default(),
            client_to_server_tx,
            server_to_client_rx,
        )
        .await
        .expect("connect");
        // First recv skips ping and returns actual payload.
        let recv = conn.recv().await.expect("recv");
        assert_eq!(recv, Bytes::from_static(b"pong"));
        conn.close().await.expect("close");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn keepalive_closes_when_window_full_and_remote_silent() {
        let (client_to_server_tx, mut client_to_server_rx) = mpsc::channel::<Vec<u8>>(32);
        let (server_to_client_tx, server_to_client_rx) = mpsc::channel::<Vec<u8>>(32);

        tokio::spawn(async move {
            let mut first_ack_sent = false;
            while let Some(raw) = client_to_server_rx.recv().await {
                let frame = Frame::decode(&raw).expect("decode frame");
                match frame {
                    Frame::Syn { window } => {
                        let _ = server_to_client_tx
                            .send(Frame::Syn { window }.encode())
                            .await;
                    }
                    Frame::Data { seq, .. } if !first_ack_sent => {
                        let _ = server_to_client_tx.send(Frame::Ack { seq }.encode()).await;
                        first_ack_sent = true;
                    }
                    Frame::Fin => break,
                    _ => {}
                }
            }
        });

        let opts = GoBackNOptions {
            window_size: 2,
            keepalive_ping_ms: 200,
            pong_timeout_ms: 200,
            ..GoBackNOptions::default()
        };

        let conn = GoBackNConn::connect(opts, client_to_server_tx, server_to_client_rx)
            .await
            .expect("connect");

        conn.send_frame(Bytes::from_static(b"one"))
            .await
            .expect("send one");
        time::sleep(Duration::from_millis(10)).await;
        conn.send_frame(Bytes::from_static(b"two"))
            .await
            .expect("send two");
        conn.send_frame(Bytes::from_static(b"three"))
            .await
            .expect("send three");

        let res = time::timeout(Duration::from_millis(500), conn.recv()).await;

        match res {
            Ok(Err(GoBackNConnError::Closed)) => {}
            Ok(other) => panic!("expected closed connection, got {other:?}"),
            Err(err) => panic!("keepalive did not close stalled connection: {err}"),
        }
    }
}
