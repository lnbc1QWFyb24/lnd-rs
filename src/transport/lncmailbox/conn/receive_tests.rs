use super::*;
use crate::transport::lncmailbox::gbn::Frame;

use crate::test_support::mailbox_relay as relay;

const WATCHDOG: Duration = Duration::from_secs(20);
const CONTROL_BYTES: usize = 64 * 1024 * 1024;
const FRAME_BYTES: usize = 16 * 1024 * 1024;

async fn connect(fixture: &relay::Fixture) -> ClientConn {
    time::timeout(
        WATCHDOG,
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
                timeouts: WsTimeouts::new(WATCHDOG, WATCHDOG),
                resolved_address: Some(fixture.address),
                tls_config: Some(fixture.client_tls.clone()),
            },
        ),
    )
    .await
    .unwrap()
    .unwrap()
}

fn frames(control: &[u8]) -> Vec<Vec<u8>> {
    let parts = control.chunks(FRAME_BYTES - 4);
    let count = parts.len();
    parts
        .enumerate()
        .map(|(index, part)| {
            Frame::Data {
                seq: u8::try_from(index % 3).unwrap(),
                final_chunk: index + 1 == count,
                is_ping: false,
                payload: Bytes::copy_from_slice(part),
            }
            .encode()
        })
        .collect()
}

#[tokio::test]
async fn real_mailbox_accepts_maximum_control_and_last_clone_holds_its_lease() {
    let fixture = relay::Fixture::new(0).await;
    let connection = connect(&fixture).await;
    let budget = connection.gbn.receive_reservation().unwrap();
    time::timeout(WATCHDOG, fixture.acknowledged)
        .await
        .unwrap()
        .unwrap();
    let mut control = vec![42; CONTROL_BYTES];
    control[0] = 0;
    control[1..5].copy_from_slice(&u32::try_from(CONTROL_BYTES - 5).unwrap().to_be_bytes());
    control[CONTROL_BYTES - 1] = 17;
    fixture.frames.send(frames(&control)).unwrap();
    drop(control);
    let received = time::timeout(WATCHDOG, connection.receive_control_msg()).await;
    let emitted = time::timeout(WATCHDOG, fixture.emitted).await;
    connection.close().await;
    drop(connection);
    drop(fixture.frames);
    let joined = time::timeout(WATCHDOG, fixture.server).await;
    // Always release/join the real fixture before asserting its outcome.
    let message = received.unwrap().unwrap();
    assert_eq!(message.version, 0);
    assert_eq!(message.payload.len(), CONTROL_BYTES - 5);
    assert_eq!(message.payload[0], 42);
    assert_eq!(message.payload[CONTROL_BYTES - 6], 17);
    assert!(message.payload[..CONTROL_BYTES - 6]
        .iter()
        .all(|byte| *byte == 42));
    assert_eq!(emitted.unwrap().unwrap(), 5);
    assert!(matches!(joined, Ok(Ok(Ok(())))));
    assert_eq!(budget.used(), CONTROL_BYTES + 256);
    let clone = message.payload.clone();
    let tail = message.payload.slice(message.payload.len() - 1..);
    drop(message);
    drop(clone);
    assert_eq!(budget.used(), CONTROL_BYTES + 256);
    assert_eq!(tail.as_ref(), &[17]);
    drop(tail);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn stalled_public_consumer_saturates_and_stops_both_mailbox_streams() {
    let fixture = relay::Fixture::new(0).await;
    let connection = connect(&fixture).await;
    let budget = connection.gbn.receive_reservation().unwrap();
    time::timeout(WATCHDOG, fixture.acknowledged)
        .await
        .unwrap()
        .unwrap();
    let flood = (0..20)
        .map(|index| {
            Frame::Data {
                seq: u8::try_from(index % 3).unwrap(),
                final_chunk: true,
                is_ping: false,
                payload: Bytes::from(vec![42; FRAME_BYTES - 4]),
            }
            .encode()
        })
        .collect();
    fixture.frames.send(flood).unwrap();
    // No receive call drains either queue before the real producer saturates.
    let stopped = time::timeout(WATCHDOG, budget.closed()).await;
    let exhausted = budget.exhausted();
    let held = budget.used();
    let received = time::timeout(WATCHDOG, connection.receive_control_msg()).await;
    let emitted = time::timeout(WATCHDOG, fixture.emitted).await;
    // Saturation itself must stop both sockets and release internal queues.
    // Manual close below is cleanup after this independent observation.
    let joined = time::timeout(WATCHDOG, fixture.server).await;
    let released = budget.used();
    connection.close().await;
    drop(connection);
    drop(fixture.frames);
    assert!(stopped.is_ok());
    assert!(
        exhausted,
        "the real queues exceeded the aggregate admission bound"
    );
    assert!(held <= RECEIVE_CAPACITY);
    assert!(matches!(
        received,
        Ok(Err(ClientConnError::Gbn(GoBackNConnError::Protocol(
            "receive retention budget exceeded"
        ))))
    ));
    assert!(emitted.unwrap().unwrap() < 20);
    assert!(matches!(joined, Ok(Ok(Ok(())))));
    assert_eq!(released, 0);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn a_held_open_mailbox_is_not_reported_as_closed_on_watchdog_expiry() {
    let fixture = relay::Fixture::new(0).await;
    let connection = connect(&fixture).await;
    time::timeout(WATCHDOG, fixture.acknowledged)
        .await
        .unwrap()
        .unwrap();
    fixture.frames.send(Vec::new()).unwrap();
    let emitted = time::timeout(WATCHDOG, fixture.emitted).await;
    // Keep the real connection alive until the relay's socket-read watchdog
    // expires. Treating any read error as EOF would incorrectly report success.
    let joined = time::timeout(WATCHDOG, fixture.server).await;
    connection.close().await;
    drop(connection);
    drop(fixture.frames);
    assert_eq!(emitted.unwrap().unwrap(), 0);
    assert_eq!(
        joined.unwrap().unwrap().unwrap_err(),
        "relay read watchdog expired"
    );
}
