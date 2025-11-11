use lnd_rs::config::DEFAULT_SERVER_HOST;
use lnd_rs::credentials::{CredentialStore, InMemoryCredentialStore};
use lnd_rs::transport::mailbox::MailboxTransport;
use lnd_rs::{Lnc, PairingCredentials};
use std::env;
use tokio::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "lnd_saved_creds.json".to_string());
    let data = fs::read(&path).await?;
    let creds: PairingCredentials = serde_json::from_slice(&data)?;

    let mut store = InMemoryCredentialStore::default();
    store.set_server_host(creds.server_host.clone());
    store.set_pairing_phrase(creds.pairing_phrase.clone());
    store.set_local_key(creds.local_key.clone());
    store.set_remote_key(creds.remote_key.clone());

    let mut lnc = Lnc::with_store(
        MailboxTransport::new(Some(DEFAULT_SERVER_HOST.into())),
        Box::new(store),
    );

    lnc.connect().await?;
    let info = lnc.get_info_retry().await?;
    println!("Connected with saved credentials.");
    println!("GetInfoResponse: {info:?}");
    lnc.disconnect().await?;

    Ok(())
}
