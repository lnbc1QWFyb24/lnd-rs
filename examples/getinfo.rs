use lnd_rs::transport::direct::DirectGrpc;
use lnd_rs::Lnc;
use tokio::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let addr = flag_value(&args, "--addr").unwrap_or_else(|| "https://127.0.0.1:10009".to_string());

    let macaroon = match flag_value(&args, "--macaroon") {
        Some(path) => Some(hex::encode(fs::read(path).await?)),
        None => None,
    };
    let tls = match flag_value(&args, "--tls-cert") {
        Some(path) => Some(fs::read(path).await?),
        None => None,
    };
    let insecure = args.iter().any(|a| a == "--insecure");

    let transport = {
        let base = DirectGrpc::new(addr, macaroon, tls);
        #[cfg(feature = "dangerous-insecure-tls")]
        {
            base.dangerous_accept_invalid_certs(insecure)
        }
        #[cfg(not(feature = "dangerous-insecure-tls"))]
        {
            if insecure {
                eprintln!("warning: --insecure requires the `dangerous-insecure-tls` feature; continuing with TLS verification enabled.");
            }
            base
        }
    };
    let mut lnc = Lnc::new(transport);
    lnc.connect().await?;
    let info = lnc.get_info().await?;
    println!("{info:?}");
    lnc.disconnect().await?;
    Ok(())
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}
