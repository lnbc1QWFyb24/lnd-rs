# Getting Started

This guide covers the minimal steps to call `lnrpc` from Rust using either direct gRPC or the
Lightning Node Connect (LNC) mailbox transport.

Prerequisites
- Rust stable and `cargo` installed
- Tokio runtime in your binary (`rt-multi-thread`, `macros`)
- Bundled LND `v0.21.3-beta` protos (included in this crate)

1) Build with the bundled LND protos

```
cargo build
```

`build.rs` compiles the bundled `lightning.proto`, `signer.proto`, and `walletkit.proto`.
To use another LND release, run `scripts/update_protos.sh <LND_TAG>` first. Set `LND_TAG`
to select a specific local tag directory; otherwise the last directory under `protos/lnd/`
is used.

2) Choose a transport and enable features

Cargo.toml examples

```toml
[dependencies]
# Direct gRPC
lnd-rs = { path = "../lnd-rs", default-features = false, features = ["transport-direct"] }

# LNC mailbox
# lnd-rs = { path = "../lnd-rs", default-features = false, features = ["transport-mailbox"] }
```

3) Direct gRPC example

```rust
use lnd_rs::transport::direct::DirectGrpc;
use lnd_rs::Lnc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "https://127.0.0.1:10009".to_string();
    let macaroon_hex = None; // or Some(hex::encode(tokio::fs::read("~/.lnd/.../admin.macaroon").await?))
    let tls_ca = None;       // or Some(tokio::fs::read("~/.lnd/tls.cert").await?)

    let transport = DirectGrpc::new(addr, macaroon_hex, tls_ca);
    let mut lnc = Lnc::new(transport);
    lnc.connect().await?;
    let info = lnc.get_info().await?;
    println!("{info:?}");
    lnc.disconnect().await?;
    Ok(())
}
```

Dev-only insecure TLS: enable the `dangerous-insecure-tls` feature and pass `--insecure` in the
`getinfo` example when connecting to self-signed local nodes.

4) LNC mailbox pairing + reuse

```rust
use lnd_rs::transport::mailbox::MailboxTransport;
use lnd_rs::{
    config::LncConfig,
    credentials::{CredentialStore, InMemoryCredentialStore},
    Lnc,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pairing_phrase = std::env::args().nth(1).expect("pass 10-word pairing phrase");

    let config = LncConfig::default();
    let transport = MailboxTransport::with_mailbox_config(
        config.server_host.clone(), config.mailbox.clone(),
    );
    let mut lnc = Lnc::with_config(transport, config);

    // First run: pair and persist
    let creds = lnc.pair_node(&pairing_phrase).await?;
    println!("Paired with {}", creds.server_host);

    // Save creds (macaroon included) for later reuse
    let json = serde_json::to_vec_pretty(&creds)?;
    tokio::fs::write("lnd_saved_creds.json", json).await?;

    // Next run: restore into a store and connect
    let mut store = InMemoryCredentialStore::default();
    store.set_server_host(creds.server_host);
    store.set_pairing_phrase(creds.pairing_phrase);
    store.set_local_key(creds.local_key);
    store.set_remote_key(creds.remote_key);
    let mut lnc = Lnc::with_store(MailboxTransport::new(None), Box::new(store));

    lnc.connect().await?;
    let info = lnc.get_info_retry().await?;
    println!("{info:?}");
    lnc.disconnect().await?;
    Ok(())
}
```

Mailbox notes
- Requires `resources/aezeed_words_english.txt` (included here) for the AEZEED dictionary.
- Pairing performs Noise + WSS + HTTP/2 handshakes. AEZEED scrypt uses one
  process-owned worker with one queued request; caller cancellation skips queued
  work and discards active results. The blocking Noise I/O bridge runs on the
  caller's Tokio blocking pool and cancels its reads/writes when the async
  handshake owner is dropped.

Troubleshooting
- Proto build not running: ensure a `protos/lnd/<tag>/lightning.proto` exists or set `LND_TAG`.
- `Unavailable`/`Unknown` on first RPC: use `get_info_retry()` which reconnects once if auth
  metadata was not captured, or call `connect()` again after clearing any stale state.
