//! Websocket construction with optional caller-owned DNS resolution.

use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config, connect_async_tls_with_config,
    tungstenite::{protocol::WebSocketConfig, Error},
    Connector, MaybeTlsStream, WebSocketStream,
};

/// Existing upstream limits, made explicit rather than inherited implicitly.
/// These are encrypted mailbox-frame bounds, independent of decoded RPC limits.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Connect without replacing the URL hostname by the resolved numeric address.
/// The TLS helper derives SNI and verification from the unchanged request URL.
pub(super) async fn open(
    url: &str,
    resolved_address: Option<SocketAddr>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
    let config = WebSocketConfig::default()
        .max_frame_size(Some(MAX_FRAME_BYTES))
        .max_message_size(Some(MAX_MESSAGE_BYTES));
    let connector = tls_config.map(Connector::Rustls);
    let (socket, _) = match resolved_address {
        Some(address) => {
            let stream = TcpStream::connect(address).await?;
            client_async_tls_with_config(url, stream, Some(config), connector).await?
        }
        None => connect_async_tls_with_config(url, Some(config), false, connector).await?,
    };
    Ok(socket)
}

#[cfg(test)]
mod tests;
