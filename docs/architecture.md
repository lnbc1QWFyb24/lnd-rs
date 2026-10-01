# Architecture Overview

This crate provides connectors for interacting with LND over either direct gRPC or the Lightning
Node Connect (LNC) mailbox transport. The core client orchestration lives in `src/client.rs`, and
transports are exposed via the `transport` module. The default build enables the `transport-direct`
feature which talks directly to an LND node over gRPC. The `transport-mailbox` feature enables the
full LNC mailbox transport stack.

## Mailbox Transport Pipeline

The mailbox transport mirrors the Go reference stack:

1. **AEZEED parsing / SID derivation** (`transport::lncmailbox::aezeed`, `sid`): the pairing token
   is stretched into entropy, then hashed into inbound/outbound stream identifiers.
2. **Websocket streams** (`transport::lncmailbox::ws`): paired send/receive streams connect to the
   hashmail HTTP endpoints with per-stage timeouts.
3. **Go-Back-N framing** (`transport::lncmailbox::gbn`): the duplex websocket streams are framed and
   retransmitted for reliability. The defaults match the Go client but are configurable via
   `MailboxTransport::with_mailbox_config`.
4. **Noise handshake** (`transport::lncmailbox::noise_machine`): xx/kk patterns are negotiated and
   SPAKE2-masked static keys are exchanged. The resulting Noise transport encrypts HTTP/2 frames.
5. **HTTP/2 prior-knowledge channel** (`transport::mailbox::Http2Channel`): tonic clients talk to an
   in-memory HTTP/2 channel backed by the Noise transport and get metadata injected via
   `LncInterceptor`.

Each stage is decoupled so it can be unit-tested in isolation (see `tests/` and the
`transport::lncmailbox::*::tests` modules), and all blocking work happens on background tasks to
respect Tokio's async runtime.

## Configuration

`config::LncConfig` stores the server-host fallback and mailbox tuning. Passing
it to `Lnc::with_config` does not configure an already constructed transport;
`namespace` is reserved and currently unapplied. Explicitly supply
`config.mailbox` to `MailboxTransport::with_mailbox_config` before constructing
the high-level client. This configures websocket connect/send deadlines, retry
delays, a separate timeout for each WS/GBN, Noise and HTTP/2 establishment stage,
`GoBackNOptions` and HTTP/2 keepalive:

```rust
use lnd_rs::{config::LncConfig, transport::mailbox::MailboxTransport, Lnc};

let mut config = LncConfig::default();
config.mailbox.session_timeout = std::time::Duration::from_secs(5);
let transport = MailboxTransport::with_mailbox_config(
    config.server_host.clone(), config.mailbox.clone(),
);
let client = Lnc::with_config(transport, config);
```

`with_resolved_address` lets the caller resolve DNS before entering an async
runtime. Both streams and reconnects use that numeric address while preserving
the original authority for TLS verification, SNI and HTTP Host. `with_tls_config`
supplies one caller-owned certificate policy to both streams; otherwise bundled
Web PKI remains in use. Pairing preparation precedes the stage timeouts. Callers
own whole-operation deadlines, including DNS and pairing preparation, and refresh.

## Receive ownership and cancellation

Each `ClientConn` has a 576-MiB receive-retention admission budget. A fixed
384-MiB reservation covers the pinned WebSocket/JSON parser's buffers, capacity
growth and escaped-string scratch for the socket lifetime. This is a conservative
engineering allowance, not a measured RSS or allocator ceiling. The remaining
192 MiB admits raw frames, DATA/control slices, fragment handles and assembly
copies while originals remain live. `Bytes` owners retain reservations through
queues, clones and slices until the last owner drops. Saturation terminates both
streams and drains internal queues without waiting for admission or reconnecting.
Explicit close releases queued data; returned payloads remain owned by callers.

The 16-MiB WebSocket frame, 64-MiB message/control and 65,536-fragment limits
remain independent protocol bounds. Noise retains leased controls and copies
only an 18-byte encrypted header and one ciphertext record of at most 65,551
bytes. Its working records and 32-record plaintext queue (at most 65,535 bytes
per record) have separate bounds. Caller-supplied queues for the public
Go-Back-N constructor are outside the `ClientConn` retention claim.

Partially established socket tasks remain owned during cancellation. Dropping
the async handshake wakes its blocking Noise I/O bridge before runtime shutdown.
Entropy stretching uses one process-owned worker with one active and one queued
request; dropping a caller does not wait for that worker to finish. Transport
diagnostics omit pairing values, authentication payloads and remote frame bodies.

## Pairing identity

`validate_pairing_material` and `pairing_commitment` use the same bounded pure
parsers as connection setup, without KDF, randomness or network access. The
commitment binds a caller-validated canonical authority and semantic pairing
inputs; it must not be logged. An XX commitment identifies the pairing capability
and requires a separate authenticated peer binding for safe resumed operations.
`Transport::remote_key_hint` exposes the learned public peer after a successful
Noise handshake. Applications also own validation of the handshake's macaroon
authority before they request an RPC service.
