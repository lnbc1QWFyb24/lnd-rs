use super::super::open;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use rustls::{
    crypto::aws_lc_rs::default_provider,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

const WATCHDOG: Duration = Duration::from_secs(5);
const CA: &[u8] = include_bytes!("fixtures/test-ca.pem");
const CERTIFICATE: &[u8] = include_bytes!("fixtures/server.pem");
const KEY: &[u8] = include_bytes!("fixtures/server-key.pem");

struct CountRequest {
    expected_authority: String,
    requests: Arc<AtomicUsize>,
}

impl Callback for CountRequest {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.headers()["host"], self.expected_authority);
        Ok(response)
    }
}

fn tls_client() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA).expect("public test CA"))
        .expect("valid root");
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocols")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn server(expected_host: &str) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let expected_authority = format!("{expected_host}:{}", address.port());
    let requests = Arc::new(AtomicUsize::new(0));
    let observed_requests = requests.clone();
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("default protocols")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(CERTIFICATE).expect("test certificate")],
            PrivateKeyDer::from_pem_slice(KEY).expect("public test key"),
        )
        .expect("test server credentials");
    let task = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(WATCHDOG, listener.accept())
            .await
            .expect("client must connect")
            .expect("accept client");
        let stream = stream.into_std().expect("convert loopback stream");
        stream
            .set_nonblocking(false)
            .expect("blocking server stream");
        stream.set_read_timeout(Some(WATCHDOG)).expect("read bound");
        stream
            .set_write_timeout(Some(WATCHDOG))
            .expect("write bound");
        tokio::task::spawn_blocking(move || {
            let tls = StreamOwned::new(
                ServerConnection::new(Arc::new(config)).expect("server session"),
                stream,
            );
            let result = tokio_tungstenite::tungstenite::accept_hdr(
                tls,
                CountRequest {
                    expected_authority,
                    requests: observed_requests,
                },
            );
            result
                .ok()
                .and_then(|socket| socket.get_ref().conn.server_name().map(str::to_owned))
        })
        .await
        .expect("join bounded TLS server")
    });
    (address, requests, task)
}

/// The certificate has only DNS:localhost. Rewriting the URL to 127.0.0.1
/// would fail, even though that numeric address is the actual TCP destination.
#[tokio::test]
async fn explicit_address_preserves_tls_name_sni_and_http_authority() {
    let (address, requests, task) = server("localhost").await;
    let result = tokio::time::timeout(
        WATCHDOG,
        open(
            &format!("wss://localhost:{}/mailbox", address.port()),
            Some(address),
            Some(tls_client()),
        ),
    )
    .await;
    let accepted = matches!(&result, Ok(Ok(_)));
    drop(result);
    let observed_name = task.await.expect("join owned server");
    assert!(accepted, "trusted localhost mailbox must connect");
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(observed_name.as_deref(), Some("localhost"));
}

/// Changing only the URL name must reject the same trusted certificate before
/// any HTTP request; the numeric address cannot supply certificate authority.
#[tokio::test]
async fn explicit_address_cannot_replace_certificate_hostname_authority() {
    let (address, requests, task) = server("mailbox.invalid").await;
    let result = tokio::time::timeout(
        WATCHDOG,
        open(
            &format!("wss://mailbox.invalid:{}/mailbox", address.port()),
            Some(address),
            Some(tls_client()),
        ),
    )
    .await;
    let rejected = matches!(&result, Ok(Err(_)));
    drop(result);
    let observed_name = task.await.expect("join owned server");
    assert!(rejected, "wrong TLS name must fail without reaching HTTP");
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(observed_name, None);
}
