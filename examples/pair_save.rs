use lnd_rs::transport::mailbox::MailboxTransport;
use lnd_rs::Lnc;
use std::{env, path::PathBuf};
use tokio::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pairing_phrase = env::args()
        .nth(1)
        .expect("usage: cargo run --example pair_save -- <pairing phrase> [creds-path]");
    let output_path = env::args()
        .nth(2)
        .unwrap_or_else(|| "lnd_saved_creds.json".to_string());
    let transport = MailboxTransport::new(None);
    let mut lnc = Lnc::new(transport);

    // Pair with the provided phrase and capture the authenticated credentials.
    let creds = lnc.pair_node(&pairing_phrase).await?;
    let path = PathBuf::from(output_path);
    fs::write(&path, serde_json::to_vec_pretty(&creds)?).await?;

    println!("Pairing succeeded with server {}", creds.server_host);
    println!("Credentials stored at {}", path.display());
    println!(
        "Next: cargo run --example connect_saved -- {}",
        path.display()
    );

    Ok(())
}
