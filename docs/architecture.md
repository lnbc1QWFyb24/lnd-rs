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
   `LncConfig::mailbox`.
4. **Noise handshake** (`transport::lncmailbox::noise_machine`): xx/kk patterns are negotiated and
   SPAKE2-masked static keys are exchanged. The resulting Noise transport encrypts HTTP/2 frames.
5. **HTTP/2 prior-knowledge channel** (`transport::mailbox::Http2Channel`): tonic clients talk to an
   in-memory HTTP/2 channel backed by the Noise transport and get metadata injected via
   `LncInterceptor`.

Each stage is decoupled so it can be unit-tested in isolation (see `tests/` and the
`transport::lncmailbox::*::tests` modules), and all blocking work happens on background tasks to
respect Tokio's async runtime.

## Configuration

`config::LncConfig` holds the high-level settings (server host, namespace, and mailbox tuning). The
mailbox portion allows adjusting websocket connect/send deadlines, mailbox retry delays, the HTTP/2
session timeout, and the underlying `GoBackNOptions`. `MailboxTransport::with_mailbox_config` wires
the configuration through `ClientConn`, `WsTimeouts`, and the Noise handshake so tests can lower
timeouts for deterministic behavior.
