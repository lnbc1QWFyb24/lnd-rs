use super::*;

#[tokio::test(flavor = "current_thread")]
async fn ignored_handshake_data_does_not_log_payload() {
    const CANARY: &[u8] = b"raw-handshake-canary-SECRET";
    let (dispatch, captured) = crate::test_support::trace_capture();
    let _scope = tracing::dispatcher::set_default(&dispatch);
    let (outbound, mut wire) = mpsc::channel(8);
    let (inbound, received) = mpsc::channel(2);
    inbound
        .send(
            Frame::Data {
                seq: 0,
                final_chunk: true,
                is_ping: false,
                payload: Bytes::from_static(CANARY),
            }
            .encode(),
        )
        .await
        .unwrap();
    inbound
        .send(Frame::Syn { window: 2 }.encode())
        .await
        .unwrap();
    let connection = GoBackNConn::connect(
        GoBackNOptions {
            window_size: 2,
            ..GoBackNOptions::default()
        },
        outbound,
        received,
    )
    .await
    .unwrap();

    let first = Frame::decode(&wire.recv().await.unwrap()).unwrap();
    let second = Frame::decode(&wire.recv().await.unwrap()).unwrap();
    connection.close().await.unwrap();
    drop(connection);
    drop(inbound);

    assert_eq!(first, Frame::Syn { window: 2 });
    assert_eq!(second, Frame::SynAck);
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("(handshake) ignoring"));
    assert!(!logs.contains(std::str::from_utf8(CANARY).unwrap()));
}
