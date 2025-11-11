#[cfg(feature = "dangerous-insecure-tls")]
use std::{error::Error as StdError, sync::Arc};

use async_trait::async_trait;
#[cfg(feature = "dangerous-insecure-tls")]
use http::{uri::Scheme, Uri};
#[cfg(feature = "dangerous-insecure-tls")]
use hyper_rustls::HttpsConnectorBuilder;
#[cfg(feature = "dangerous-insecure-tls")]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(feature = "dangerous-insecure-tls")]
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    DigitallySignedStruct, SignatureScheme,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
#[cfg(feature = "dangerous-insecure-tls")]
use tower::service_fn;
#[cfg(feature = "dangerous-insecure-tls")]
use tower::Service;

#[cfg(feature = "dangerous-insecure-tls")]
type BoxError = Box<dyn StdError + Send + Sync>;

use super::{Transport, TransportError};
use crate::PairingCredentials;

/// Direct gRPC connection (not LNC). Useful for testing the API surface without the mailbox stack.
///
/// The optional `dangerous-insecure-tls` feature enables `dangerous_accept_invalid_certs`, matching
/// the Go client's `InsecureSkipVerify` developer path. Keep that feature disabled in production
/// builds.
pub struct DirectGrpc {
    addr: String,
    macaroon_hex: Option<String>,
    tls_ca_cert: Option<Vec<u8>>, // DER/PEM
    #[cfg(feature = "dangerous-insecure-tls")]
    dangerous_accept_invalid_certs: bool,
}

impl DirectGrpc {
    #[must_use]
    pub fn new(addr: String, macaroon_hex: Option<String>, tls_ca_cert: Option<Vec<u8>>) -> Self {
        Self {
            addr,
            macaroon_hex,
            tls_ca_cert,
            #[cfg(feature = "dangerous-insecure-tls")]
            dangerous_accept_invalid_certs: false,
        }
    }

    /// Allow invalid/unsigned TLS certificates (dev/test only).
    ///
    /// Mirrors the Go client's `InsecureSkipVerify` path so local Polar/LND
    /// instances can be reached even when they present CA:TRUE self-signed certs.
    /// This method is a no-op unless the `dangerous-insecure-tls` Cargo feature is enabled.
    #[cfg(feature = "dangerous-insecure-tls")]
    #[must_use]
    pub fn dangerous_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.dangerous_accept_invalid_certs = accept;
        self
    }

    #[cfg(not(feature = "dangerous-insecure-tls"))]
    #[must_use]
    pub fn dangerous_accept_invalid_certs(self, _accept: bool) -> Self {
        self
    }
}

#[async_trait]
impl Transport for DirectGrpc {
    type Svc = Channel;
    async fn pair(
        &mut self,
        _server_host: &str,
        _pairing_phrase: &str,
    ) -> Result<PairingCredentials, TransportError> {
        Err(TransportError::NotImplemented)
    }

    async fn connect(
        &mut self,
        _server_host: &str,
        _pairing_phrase: &str,
        _local_key: &str,
        _remote_key: &str,
    ) -> Result<(), TransportError> {
        // Direct connector has nothing to pre-connect; service() performs lazy connect.
        Ok(())
    }

    async fn service(&self) -> Result<Self::Svc, TransportError> {
        #[cfg(feature = "dangerous-insecure-tls")]
        if self.dangerous_accept_invalid_certs {
            return self.connect_with_insecure_tls().await;
        }
        let mut ep = Endpoint::from_shared(self.addr.clone())
            .map_err(|e| TransportError::connection("invalid gRPC endpoint", e))?;
        if let Some(ca) = &self.tls_ca_cert {
            let ca = Certificate::from_pem(ca.clone());
            let tls = ClientTlsConfig::new().ca_certificate(ca);
            ep = ep
                .tls_config(tls)
                .map_err(|e| TransportError::connection("invalid TLS client config", e))?;
        }
        let channel = ep
            .connect()
            .await
            .map_err(|e| TransportError::connection("direct transport connect failed", e))?;
        Ok(channel)
    }

    async fn disconnect(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    fn metadata(&self) -> Vec<(String, String)> {
        match &self.macaroon_hex {
            Some(m) => vec![("macaroon".to_string(), m.clone())],
            None => Vec::new(),
        }
    }
}

impl DirectGrpc {
    #[cfg(feature = "dangerous-insecure-tls")]
    async fn connect_with_insecure_tls(&self) -> Result<Channel, TransportError> {
        let original_uri: Uri = self
            .addr
            .parse()
            .map_err(|e| TransportError::connection("invalid endpoint URI", e))?;
        let mut http_parts = original_uri.clone().into_parts();
        http_parts.scheme = Some(Scheme::HTTP);
        let http_uri = Uri::from_parts(http_parts)
            .map_err(|e| TransportError::connection("invalid http URI", e))?;

        let ep = Endpoint::from_shared(http_uri.to_string())
            .map_err(|e| TransportError::connection("invalid insecure endpoint", e))?;

        let connector = Self::build_insecure_https_connector();
        let svc = service_fn(move |uri: Uri| {
            let mut inner = connector.clone();
            async move {
                let mut parts = uri.into_parts();
                parts.scheme = Some(Scheme::HTTPS);
                let https_target_uri =
                    Uri::from_parts(parts).map_err(|e| -> BoxError { BoxError::from(e) })?;
                inner
                    .call(https_target_uri)
                    .await
                    .map_err(|e| -> BoxError { BoxError::from(e) })
            }
        });

        ep.connect_with_connector(svc)
            .await
            .map_err(|e| TransportError::connection("direct insecure connect failed", e))
    }

    #[cfg(feature = "dangerous-insecure-tls")]
    fn build_insecure_https_connector(
    ) -> hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> {
        if CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(AcceptAnyCertVerifier);
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http2()
            .build()
    }
}

#[cfg(feature = "dangerous-insecure-tls")]
#[derive(Debug)]
struct AcceptAnyCertVerifier;

#[cfg(feature = "dangerous-insecure-tls")]
impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
