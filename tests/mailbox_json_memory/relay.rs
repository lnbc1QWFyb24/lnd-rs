use std::{net::SocketAddr, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rustls::{
    crypto::aws_lc_rs::default_provider,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_tungstenite::tungstenite::{
    handshake::server::{Callback, ErrorResponse, Request, Response},
    Message,
};

const WATCHDOG: Duration = Duration::from_secs(5);
const CA: &[u8] =
    include_bytes!("../../src/transport/lncmailbox/ws/connect/tests/fixtures/test-ca.pem");
const CERTIFICATE: &[u8] =
    include_bytes!("../../src/transport/lncmailbox/ws/connect/tests/fixtures/server.pem");
const KEY: &[u8] =
    include_bytes!("../../src/transport/lncmailbox/ws/connect/tests/fixtures/server-key.pem");

pub struct Fixture {
    pub authority: String,
    pub address: SocketAddr,
    pub client_tls: Arc<ClientConfig>,
    pub acknowledged: oneshot::Receiver<()>,
    pub server: JoinHandle<Result<(), String>>,
    pub frames: std::sync::mpsc::Sender<Vec<Vec<u8>>>,
    pub emitted: oneshot::Receiver<usize>,
}

struct ObservePath<'a>(&'a mut bool);

impl Callback for ObservePath<'_> {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        *self.0 = request.uri().path().ends_with("/receive");
        Ok(response)
    }
}

impl Fixture {
    pub async fn new(ignored_elements: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client_tls, server_tls) = tls_configs();
        let body = ignored_field_envelope(ignored_elements);
        let (frames, frames_rx) = std::sync::mpsc::channel::<Vec<Vec<u8>>>();
        let frames_rx = Arc::new(std::sync::Mutex::new(Some(frames_rx)));
        let (emitted_tx, emitted) = oneshot::channel();
        let emitted_tx = Arc::new(std::sync::Mutex::new(Some(emitted_tx)));
        let (acknowledged_tx, acknowledged) = oneshot::channel();
        let acknowledged_tx = Arc::new(std::sync::Mutex::new(Some(acknowledged_tx)));
        let server = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (stream, _) = tokio::time::timeout(WATCHDOG, listener.accept())
                    .await
                    .map_err(|_| "relay accept timeout")?
                    .map_err(|_| "relay accept failed")?;
                let stream = stream.into_std().map_err(|_| "stream conversion")?;
                stream
                    .set_nonblocking(false)
                    .map_err(|_| "blocking socket")?;
                stream
                    .set_read_timeout(Some(WATCHDOG))
                    .map_err(|_| "read watchdog")?;
                stream
                    .set_write_timeout(Some(WATCHDOG))
                    .map_err(|_| "write watchdog")?;
                let tls = Arc::clone(&server_tls);
                let body = Arc::clone(&body);
                let ack = Arc::clone(&acknowledged_tx);
                let commands = Arc::clone(&frames_rx);
                let emitted = Arc::clone(&emitted_tx);
                tasks.push(tokio::task::spawn_blocking(move || {
                    let mut receiving = false;
                    let session = ServerConnection::new(tls).map_err(|_| "server TLS")?;
                    let mut socket = tokio_tungstenite::tungstenite::accept_hdr(
                        StreamOwned::new(session, stream),
                        ObservePath(&mut receiving),
                    )
                    .map_err(|_| "server websocket")?;
                    if receiving {
                        socket.read().map_err(|_| "receive initialization")?;
                        socket
                            .send(Message::Text(body.as_str().to_owned().into()))
                            .map_err(|_| "send valid peer SYN")?;
                        // The client completes its public handshake before the
                        // test releases controlled DATA. Dropping the sender
                        // preserves the original JSON-only fixture.
                        let command = commands.lock().unwrap().take().unwrap();
                        if let Ok(frames) = command.recv_timeout(WATCHDOG) {
                            let mut sent = 0;
                            for frame in frames {
                                if socket.send(Message::Binary(frame.into())).is_err() {
                                    break;
                                }
                                sent += 1;
                            }
                            if let Some(sender) = emitted.lock().unwrap().take() {
                                let _ = sender.send(sent);
                            }
                        }
                        observe_close(&mut socket)?;
                    } else {
                        for expected in [&[1, 2][..], &[6][..]] {
                            let text = socket
                                .read()
                                .map_err(|_| "outbound handshake frame")?
                                .into_text()
                                .map_err(|_| "text frame")?;
                            let envelope: serde_json::Value =
                                serde_json::from_str(&text).map_err(|_| "outbound envelope")?;
                            let encoded = envelope["msg"].as_str().ok_or("outbound msg")?;
                            if STANDARD.decode(encoded).map_err(|_| "outbound base64")? != expected
                            {
                                return Err("unexpected handshake identity".into());
                            }
                        }
                        if let Some(sender) = ack.lock().unwrap().take() {
                            let _ = sender.send(());
                        }
                        observe_close(&mut socket)?;
                    }
                    Ok::<(), String>(())
                }));
            }
            join_relays(tasks).await
        });
        Self {
            authority: format!("localhost:{}", address.port()),
            address,
            client_tls,
            acknowledged,
            server,
            frames,
            emitted,
        }
    }
}

fn tls_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let provider = Arc::new(default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA).unwrap())
        .unwrap();
    let client_tls = Arc::new(
        ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_tls = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(CERTIFICATE).unwrap()],
                PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            )
            .unwrap(),
    );
    (client_tls, server_tls)
}

fn ignored_field_envelope(ignored_elements: usize) -> Arc<String> {
    let mut body = String::with_capacity(ignored_elements * 2 + 128);
    body.push_str(r#"{"result":{"msg":"AQI=","ignored":["#);
    for index in 0..ignored_elements {
        if index != 0 {
            body.push(',');
        }
        body.push('0');
    }
    body.push_str("]}}");
    Arc::new(body)
}

/// A watchdog expiration is a fixture failure, never evidence of task shutdown.
fn observe_close(
    socket: &mut tokio_tungstenite::tungstenite::WebSocket<
        StreamOwned<ServerConnection, std::net::TcpStream>,
    >,
) -> Result<(), String> {
    use std::io::ErrorKind;
    use tokio_tungstenite::tungstenite::{error::ProtocolError, Error};
    loop {
        match socket.read() {
            Ok(Message::Close(_))
            | Err(
                Error::ConnectionClosed
                | Error::AlreadyClosed
                | Error::Protocol(ProtocolError::ResetWithoutClosingHandshake),
            ) => return Ok(()),
            Err(Error::Io(error))
                if matches!(
                    error.kind(),
                    ErrorKind::UnexpectedEof
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(())
            }
            Err(Error::Io(error))
                if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
            {
                return Err("relay read watchdog expired".into())
            }
            Ok(_) => {}
            Err(_) => return Err("relay did not observe connection closure".into()),
        }
    }
}

async fn join_relays(tasks: Vec<JoinHandle<Result<(), String>>>) -> Result<(), String> {
    let mut first_error = None;
    for task in tasks {
        let failure = match task.await {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some("relay task failed".to_owned()),
        };
        if first_error.is_none() {
            first_error = failure;
        }
    }
    first_error.map_or(Ok(()), Err)
}
