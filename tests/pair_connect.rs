use async_trait::async_trait;
use lnd_rs::config::DEFAULT_SERVER_HOST;
use lnd_rs::transport::{Transport, TransportError};
use lnd_rs::{Lnc, PairingCredentials};
use tonic::transport::Channel;

const REMOTE_KEY: &str = "02feedface42";
const LOCAL_KEY: &str = "01abcd";
const MACAROON: &str = "ff00";

struct MockTransport {
    metadata: Vec<(String, String)>,
    connected: bool,
    last_connect_args: std::sync::Arc<std::sync::Mutex<Option<ConnectArgs>>>,
}

#[derive(Clone, Debug)]
struct ConnectArgs {
    server_host: String,
    pairing_phrase: String,
    local_key: String,
    remote_key: String,
}

impl MockTransport {
    fn new() -> Self {
        Self {
            metadata: vec![("macaroon".to_string(), MACAROON.to_string())],
            connected: false,
            last_connect_args: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    type Svc = Channel;
    async fn pair(
        &mut self,
        server_host: &str,
        pairing_phrase: &str,
    ) -> Result<PairingCredentials, TransportError> {
        self.connected = false;
        Ok(PairingCredentials {
            server_host: server_host.to_string(),
            pairing_phrase: pairing_phrase.to_string(),
            local_key: LOCAL_KEY.to_string(),
            remote_key: String::new(),
            macaroon_hex: None,
        })
    }

    async fn connect(
        &mut self,
        server_host: &str,
        pairing_phrase: &str,
        local_key: &str,
        remote_key: &str,
    ) -> Result<(), TransportError> {
        *self.last_connect_args.lock().unwrap() = Some(ConnectArgs {
            server_host: server_host.to_string(),
            pairing_phrase: pairing_phrase.to_string(),
            local_key: local_key.to_string(),
            remote_key: remote_key.to_string(),
        });
        self.connected = true;
        Ok(())
    }

    async fn service(&self) -> Result<Self::Svc, TransportError> {
        Err(TransportError::NotImplemented)
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        self.connected = false;
        Ok(())
    }

    fn metadata(&self) -> Vec<(String, String)> {
        self.metadata.clone()
    }

    fn remote_key_hint(&self) -> Option<String> {
        if self.connected {
            Some(REMOTE_KEY.to_string())
        } else {
            None
        }
    }
}

#[tokio::test]
async fn pair_node_returns_credentials_with_remote_key() {
    let transport = MockTransport::new();
    let mut lnc = Lnc::new(transport);
    let creds = lnc
        .pair_node("arrive fun zebra ribbon mom")
        .await
        .expect("pair");

    assert_eq!(creds.server_host, DEFAULT_SERVER_HOST);
    assert_eq!(creds.local_key, LOCAL_KEY);
    assert_eq!(creds.remote_key, REMOTE_KEY);
    assert_eq!(creds.macaroon_hex.as_deref(), Some(MACAROON));
    assert!(lnc.is_connected());
    assert_eq!(
        lnc.credentials_store().remote_key().as_deref(),
        Some(REMOTE_KEY)
    );
}

#[tokio::test]
async fn connect_syncs_remote_key_from_transport() {
    let transport = MockTransport::new();
    let mut lnc = Lnc::new(transport);
    {
        let store = lnc.credentials_store_mut();
        store.set_server_host(DEFAULT_SERVER_HOST.to_string());
        store.set_pairing_phrase("arrive fun zebra ribbon mom".to_string());
        store.set_local_key(LOCAL_KEY.to_string());
    }

    lnc.connect().await.expect("connect");
    assert_eq!(
        lnc.credentials_store().remote_key().as_deref(),
        Some(REMOTE_KEY)
    );
}

#[tokio::test]
async fn from_credentials_populates_store_correctly() {
    let creds = PairingCredentials {
        server_host: "test.host:443".to_string(),
        pairing_phrase: "arrive fun zebra ribbon mom".to_string(),
        local_key: LOCAL_KEY.to_string(),
        remote_key: REMOTE_KEY.to_string(),
        macaroon_hex: Some(MACAROON.to_string()),
    };

    let transport = MockTransport::new();
    let lnc = Lnc::from_credentials(transport, creds);

    let store = lnc.credentials_store();
    assert_eq!(store.server_host().as_deref(), Some("test.host:443"));
    assert_eq!(
        store.pairing_phrase().as_deref(),
        Some("arrive fun zebra ribbon mom")
    );
    assert_eq!(store.local_key().as_deref(), Some(LOCAL_KEY));
    assert_eq!(store.remote_key().as_deref(), Some(REMOTE_KEY));
}

#[tokio::test]
async fn from_credentials_then_connect_passes_correct_args() {
    let creds = PairingCredentials {
        server_host: "test.host:443".to_string(),
        pairing_phrase: "arrive fun zebra ribbon mom".to_string(),
        local_key: LOCAL_KEY.to_string(),
        remote_key: REMOTE_KEY.to_string(),
        macaroon_hex: Some(MACAROON.to_string()),
    };

    let transport = MockTransport::new();
    let args_ref = transport.last_connect_args.clone();
    let mut lnc = Lnc::from_credentials(transport, creds);

    lnc.connect().await.expect("connect");

    let args = args_ref
        .lock()
        .unwrap()
        .clone()
        .expect("connect was called");
    assert_eq!(args.server_host, "test.host:443");
    assert_eq!(args.pairing_phrase, "arrive fun zebra ribbon mom");
    assert_eq!(args.local_key, LOCAL_KEY);
    assert_eq!(args.remote_key, REMOTE_KEY);
}
