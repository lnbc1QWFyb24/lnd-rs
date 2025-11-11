lnd-rs
======

Rust crate for connecting to and interacting with LND over either:

- Direct gRPC (tonic/HTTP2)
- Lightning Node Connect (LNC) mailbox transport

Core capabilities
- Pair with a node and return credentials to persist (`pair_node`)
- Establish a connection and call LND `lnrpc` methods (e.g., `GetInfo`)
- Cleanly disconnect

Transports are pluggable via `transport::Transport`. Use direct gRPC for local development or
reachable servers; use the LNC mailbox transport to reach nodes behind NAT or without public RPC.

Installation
- This crate is feature‑gated. Enable only the transport(s) you need.
- If consuming from a workspace, add a path dependency; otherwise use your preferred source control.

Cargo.toml (example)

```
[dependencies]
# Direct gRPC only
lnd-rs = { path = "../lnd-rs", default-features = false, features = ["transport-direct"] }

# Or: LNC mailbox
# lnd-rs = { path = "../lnd-rs", default-features = false, features = ["transport-mailbox"] }

# Optional for dev-only insecure TLS with direct transport
# lnd-rs = { path = "../lnd-rs", default-features = false, features = ["transport-direct", "dangerous-insecure-tls"] }
```

Tokio runtime
- All APIs are async and require a Tokio runtime (`rt-multi-thread` + `macros`).

Feature flags
- `transport-direct` (default): direct TLS gRPC via tonic.
- `transport-mailbox`: full LNC mailbox stack (Noise + WSS + HTTP/2).
- `dangerous-insecure-tls`: allow invalid certs in direct gRPC (dev only).

Directory structure
- `scripts/` – update and manage proto files
- `protos/` – fetched LND protos grouped by release tag
- `build.rs` – compiles protos via `tonic_build`
- `src/` – library sources
- `docs/` – conceptual docs and guides

Protos (required before build)
- Fetch LND `lnrpc` protos for a specific tag, then build.
- Example:
  - `scripts/update_protos.sh v0.17.5-beta`
  - `cargo build`
- `build.rs` selects `protos/lnd/$LND_TAG` if `LND_TAG` is set, otherwise the last tag directory.

Usage: direct gRPC

```rust
use lnd_rs::transport::direct::DirectGrpc;
use lnd_rs::Lnc;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let addr = "https://127.0.0.1:10009".to_string();
let macaroon_hex = None; // or Some(hex::encode(fs::read("~/.lnd/.../admin.macaroon").await?))
let tls_ca = None;       // or Some(fs::read("~/.lnd/tls.cert").await?)

let transport = DirectGrpc::new(addr, macaroon_hex, tls_ca);
let mut lnc = Lnc::new(transport);
lnc.connect().await?;
let info = lnc.get_info().await?;
println!("{info:?}");
lnc.disconnect().await?;
Ok(())
# }
```

Usage: LNC mailbox (pair + connect)

```rust
use lnd_rs::transport::mailbox::MailboxTransport;
use lnd_rs::{config::LncConfig, Lnc};

# async fn demo(pairing_phrase: &str) -> Result<(), Box<dyn std::error::Error>> {
let transport = MailboxTransport::new(None);
let lnc = Lnc::with_config(transport, LncConfig::default());
let mut lnc = lnc; // mutable for connect/pair flows

// Pair once to obtain credentials; persist them for reuse.
let creds = lnc.pair_node(pairing_phrase).await?;
println!("Paired with {}", creds.server_host);

// Subsequent runs: restore creds in your CredentialStore and call connect() directly.
lnc.disconnect().await?;
Ok(())
# }
```

Notes for mailbox transport
- Enable feature `transport-mailbox`.
- Ensure `resources/aezeed_words_english.txt` contains the 2048‑word English list (BIP39/aezeed).
- See examples `pair_save` and `connect_saved` for a complete save/restore flow.

Examples
- List and run:
  - `cargo run --example getinfo --features transport-direct -- \
     --addr https://127.0.0.1:10009 --macaroon ~/.lnd/.../admin.macaroon --tls-cert ~/.lnd/tls.cert`
  - `cargo run --example pair_save --features transport-mailbox -- "<10-word pairing phrase>"`
  - `cargo run --example connect_saved --features transport-mailbox -- ./lnd_saved_creds.json`

Security
- The `dangerous-insecure-tls` feature allows skipping TLS verification for direct gRPC.
  Do not enable in production. For local self‑signed nodes (Polar/regtest), pass `--insecure` to the
  `getinfo` example after enabling the feature.

API quick ref
- `pair_node(&str) -> PairingCredentials` (pairs and captures remote key + macaroon)
- `connect()` / `disconnect()`
- `get_info()` calls `lnrpc.Lightning.GetInfo`
- `lightning_client_with_service(service)` returns a tonic client with transport metadata applied

Further reading
- `docs/getting-started.md` – step‑by‑step setup and code
- `docs/architecture.md` – transport pipeline and configuration
- `examples/` – runnable end‑to‑end flows
