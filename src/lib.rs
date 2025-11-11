#![deny(unsafe_code)]

//! LND client toolkit for Rust applications.
//!
//! Provides pluggable transports for connecting to LND over either direct gRPC
//! (tonic/HTTP2) or Lightning Node Connect (LNC) mailbox. Use [`client::Lnc`]
//! to pair (LNC), connect, and call `lnrpc` methods.
//!
//! Features
//! - `transport-direct` (default): direct TLS gRPC via tonic
//! - `transport-mailbox`: LNC mailbox (Noise + WSS + HTTP/2)
//! - `dangerous-insecure-tls`: dev-only, skip TLS validation in direct gRPC
//!
//! Protos
//! - Run `scripts/update_protos.sh <LND_TAG>` and then `cargo build` to generate
//!   `lnrpc` client types used by this crate.
//!
//! Example (direct gRPC)
//! ```no_run
//! use lnd_rs::transport::direct::DirectGrpc;
//! use lnd_rs::Lnc;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let addr = "https://127.0.0.1:10009".to_string();
//! let transport = DirectGrpc::new(addr, None, None);
//! let mut lnc = Lnc::new(transport);
//! lnc.connect().await?;
//! let info = lnc.get_info().await?;
//! println!("{info:?}");
//! lnc.disconnect().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Example (mailbox pairing)
//! ```no_run
//! use lnd_rs::transport::mailbox::MailboxTransport;
//! use lnd_rs::{config::LncConfig, Lnc};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pairing_phrase = "abandon ability able about above absent absorb abstract absurd abuse";
//! let transport = MailboxTransport::new(None);
//! let mut lnc = Lnc::with_config(transport, LncConfig::default());
//! let creds = lnc.pair_node(pairing_phrase).await?;
//! println!("Paired with {}", creds.server_host);
//! lnc.disconnect().await?;
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod config;
pub mod credentials;
pub mod proto;
pub mod transport;

pub use client::{Lnc, LncError, PairingCredentials, Result};
