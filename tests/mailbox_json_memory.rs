#![cfg(feature = "transport-mailbox")]

#[path = "mailbox_json_memory/mod.rs"]
mod support;

use std::{sync::Arc, time::Duration};

use lnd_rs::transport::lncmailbox::{
    conn::{ClientConn, ClientConnParams},
    gbn::GoBackNOptions,
    ws::WsTimeouts,
};
use support::{allocation, relay};

#[global_allocator]
static ALLOCATOR: allocation::Meter = allocation::Meter;

/// Exercises the public pre-Noise connection, rather than a detached JSON helper.
/// A two-MiB ignored array must not allocate one Value per numeric element.
#[tokio::test(flavor = "current_thread")]
async fn ignored_mailbox_fields_have_bounded_pre_authentication_allocation() {
    for ignored_elements in [0, 1_048_576] {
        let fixture = relay::Fixture::new(ignored_elements).await;
        let limits = WsTimeouts::new(Duration::from_secs(5), Duration::from_secs(5));
        allocation::begin();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            ClientConn::connect(
                &fixture.authority,
                ClientConnParams {
                    recv_sid: [1; 64],
                    send_sid: [2; 64],
                    gbn_opts: GoBackNOptions {
                        window_size: 2,
                        ..GoBackNOptions::default()
                    },
                    retry_wait: Duration::from_millis(10),
                    timeouts: limits,
                    resolved_address: Some(fixture.address),
                    tls_config: Some(Arc::clone(&fixture.client_tls)),
                },
            ),
        )
        .await;
        let connected = outcome.as_ref().is_ok_and(Result::is_ok);
        let acknowledged = tokio::time::timeout(Duration::from_secs(5), fixture.acknowledged).await;
        // Dispose the actual connection before joining every bounded server task.
        drop(outcome);
        drop(fixture.frames);
        drop(fixture.emitted);
        let joined = tokio::time::timeout(Duration::from_secs(10), fixture.server).await;
        let additional_peak = allocation::finish();
        println!("ignored_elements={ignored_elements} additional_peak_bytes={additional_peak}");

        assert!(connected, "the valid GBN handshake must complete");
        assert!(
            matches!(acknowledged, Ok(Ok(()))),
            "SYN and SYNACK reached the relay"
        );
        assert!(
            matches!(joined, Ok(Ok(Ok(())))),
            "both relay streams joined"
        );
        assert!(
            additional_peak < 16 * 1024 * 1024,
            "pre-authentication allocations exceeded the independent 16-MiB bound: {additional_peak}"
        );
    }
}
