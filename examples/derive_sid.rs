use base64::{engine::general_purpose::STANDARD, Engine as _};
use k256::{PublicKey, SecretKey};

use lnd_rs::transport::lncmailbox::{aezeed, sid};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "artefact morning piano photo consider light".to_string());
    let words: Vec<String> = phrase.split_whitespace().map(str::to_string).collect();
    let entropy = aezeed::mnemonic_to_entropy(&words)?;
    let local_sk = SecretKey::random(&mut rand::thread_rng());

    // XX pattern (no remote)
    let sid_xx = sid::derive_sid(&entropy, &local_sk, None);
    let (srv_xx, cli_xx) = sid::sid_stream_ids(sid_xx);
    println!(
        "XX recv(streamId): {}\nXX send(streamId): {}",
        STANDARD.encode(srv_xx),
        STANDARD.encode(cli_xx)
    );

    // If remote hex passed in arg2, compute KK as well.
    if let Some(remote_hex) = std::env::args().nth(2) {
        if !remote_hex.is_empty() {
            let bytes = hex::decode(remote_hex)?;
            let remote = PublicKey::from_sec1_bytes(&bytes)?;
            let sid_kk = sid::derive_sid(&entropy, &local_sk, Some(&remote));
            let (srv_kk, cli_kk) = sid::sid_stream_ids(sid_kk);
            println!(
                "KK recv(streamId): {}\nKK send(streamId): {}",
                STANDARD.encode(srv_kk),
                STANDARD.encode(cli_kk)
            );
        }
    }
    Ok(())
}
