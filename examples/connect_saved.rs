use lnd_rs::config::DEFAULT_SERVER_HOST;
use lnd_rs::transport::mailbox::MailboxTransport;
use lnd_rs::{Lnc, PairingCredentials};
use std::env;
use tokio::fs;

/// Demonstrates reconnecting to an LND node using previously saved credentials.
///
/// Usage: cargo run --example `connect_saved` --features `transport-mailbox` [creds-path]
///
/// The credentials file should be JSON produced by the `pair_save` example.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "lnd_saved_creds.json".to_string());

    let data = fs::read(&path).await?;
    let creds: PairingCredentials = serde_json::from_slice(&data)?;
    let transport = MailboxTransport::new(Some(DEFAULT_SERVER_HOST.into()));
    let mut lnc = Lnc::from_credentials(transport, creds);

    lnc.connect().await?;

    let info = lnc.get_info_retry().await?;
    println!("Connected with saved credentials.");
    println!("GetInfoResponse: {info:?}");

    lnc.disconnect().await?;

    Ok(())
}
