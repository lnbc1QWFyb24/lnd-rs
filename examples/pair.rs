use std::time::Duration;

use lnd_rs::config::DEFAULT_SERVER_HOST;
use lnd_rs::transport::mailbox::MailboxTransport;
use lnd_rs::{config::LncConfig, Lnc};
use tokio::time::timeout;
use tracing::debug;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    let pairing_phrase = std::env::args()
        .nth(1)
        .expect("Must provide pairing phrase");
    #[cfg(feature = "transport-mailbox")]
    let config = LncConfig {
        server_host: Some(DEFAULT_SERVER_HOST.into()),
        namespace: None,
        ..LncConfig::default()
    };
    #[cfg(not(feature = "transport-mailbox"))]
    let config = LncConfig {
        server_host: Some(DEFAULT_SERVER_HOST.into()),
        namespace: None,
    };
    debug!(server_host = ?config.server_host, "using server host");
    let transport = MailboxTransport::new(None);
    let mut lnc = Lnc::with_config(transport, config);

    let creds = match timeout(Duration::from_secs(60), lnc.pair_node(&pairing_phrase)).await {
        Ok(res) => res?,
        Err(_) => return Err("pairing timed out".into()),
    };
    println!("{}", serde_json::to_string_pretty(&creds)?);

    let info = match timeout(Duration::from_secs(30), lnc.get_info()).await {
        Ok(res) => res?,
        Err(_) => return Err("get_info timed out".into()),
    };
    println!("GetInfoResponse: {info:?}");
    lnc.disconnect().await?;
    Ok(())
}
