use super::{connect::MailboxConnectContext, MailboxTransport};
use crate::test_support::trace_capture;
use base64::Engine as _;

#[tokio::test(flavor = "current_thread")]
async fn pairing_and_authentication_values_never_reach_trace_output() {
    let (dispatch, bytes) = trace_capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let phrase = "abandon ability able about above absent absorb abstract absurd abuse";
    let local_key = "11".repeat(32);
    let remote_key = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
    for remote in [remote_key, ""] {
        let ctx = MailboxConnectContext::new_async(
            "private-mailbox.example:443",
            phrase,
            &local_key,
            remote,
        )
        .await
        .expect("valid public test credentials");
        ctx.auth_capture.lock().extend_from_slice(
            b"macaroon: macaroon-canary-SECRET\r\nx-private: metadata-canary-SECRET\r\n",
        );
        let (metadata, _) = MailboxTransport::capture_session_state(&ctx);
        assert_eq!(metadata.len(), 2);
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("transport.connect"),
            "trace capture must be active"
        );
        let secrets = [
            phrase.to_owned(),
            local_key.clone(),
            remote_key.to_owned(),
            "private-mailbox.example".to_owned(),
            "macaroon-canary-SECRET".to_owned(),
            "metadata-canary-SECRET".to_owned(),
            base64::engine::general_purpose::STANDARD.encode(ctx.recv_sid),
            base64::engine::general_purpose::STANDARD.encode(ctx.send_sid),
            hex::encode(&*ctx.builder.build().passphrase_entropy),
        ];
        for secret in secrets {
            assert!(
                !output.contains(&secret),
                "sensitive fixture reached tracing"
            );
        }
    }
}

#[tokio::test]
async fn dropping_http2_driver_releases_its_owned_task() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (released_tx, released_rx) = tokio::sync::oneshot::channel::<()>();
    let driver = super::state::Http2Driver(tokio::spawn(async move {
        let _resource = released_tx;
        started_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    }));
    started_rx.await.unwrap();
    drop(driver);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), released_rx)
            .await
            .expect("task must terminate")
            .is_err()
    );
}
