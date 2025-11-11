# Getting Started

This guide covers the minimal steps to call `lnrpc` from Rust using either direct gRPC or the
Lightning Node Connect (LNC) mailbox transport.

Prerequisites
- Rust stable and `cargo` installed
- Tokio runtime in your binary (`rt-multi-thread`, `macros`)
- LND protos prepared (see below)

1) Fetch LND protos

```
scripts/update_protos.sh v0.17.5-beta
cargo build
```

`build.rs` compiles `lightning.proto` for the selected tag. Set `LND_TAG` to force a specific tag;
otherwise the newest directory under `protos/lnd/` is used.

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
use lnd_rs::{config::LncConfig, credentials::InMemoryCredentialStore, Lnc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pairing_phrase = std::env::args().nth(1).expect("pass 10-word pairing phrase");

    let transport = MailboxTransport::new(None);
    let mut lnc = Lnc::with_config(transport, LncConfig::default());

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
- Pairing performs Noise + WSS + HTTP/2 handshakes; expensive steps are offloaded via
  `tokio::task::spawn_blocking` to avoid blocking the runtime.

Troubleshooting
- Proto build not running: ensure a `protos/lnd/<tag>/lightning.proto` exists or set `LND_TAG`.
- `Unavailable`/`Unknown` on first RPC: use `get_info_retry()` which reconnects once if auth
  metadata was not captured, or call `connect()` again after clearing any stale state.

