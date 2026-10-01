use super::*;
use crate::transport::lncmailbox::gbn::{GoBackNOptions, Inner, ReceivedFrame, RecvEvent};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Supply already-decoded control frames at the owning reassembly operation.
fn receiver(parts: Vec<ReceivedFrame>) -> GoBackNConn {
    let (events, event_receiver) = mpsc::channel(parts.len().max(1));
    for part in parts {
        events.try_send(RecvEvent::Payload(part)).unwrap();
    }
    let (outbound, _outbound_receiver) = mpsc::channel(1);
    GoBackNConn {
        inner: Arc::new(Inner::new(GoBackNOptions::default(), outbound, events)),
        data_rx: Arc::new(Mutex::new(event_receiver)),
        reader: tokio::spawn(std::future::pending()),
        resend_task: tokio::spawn(std::future::pending()),
        keepalive_task: tokio::spawn(std::future::pending()),
    }
}

fn part(payload: &'static [u8], final_chunk: bool) -> ReceivedFrame {
    ReceivedFrame {
        payload: Bytes::from_static(payload),
        final_chunk,
    }
}

#[tokio::test]
async fn reassembled_bytes_accept_the_limit_and_reject_one_extra_byte() {
    let accepted = receiver(vec![part(b"abcd", false), part(b"efgh", true)]);
    assert_eq!(
        accepted.recv_with_limits(8, 2).await.unwrap(),
        b"abcdefgh"[..]
    );
    let rejected = receiver(vec![part(b"abcd", false), part(b"efghi", true)]);
    assert!(matches!(
        rejected.recv_with_limits(8, 2).await,
        Err(GoBackNConnError::Protocol(
            "received message exceeds byte limit"
        ))
    ));
}

#[tokio::test]
async fn empty_fragments_consume_work_before_a_final_payload() {
    let accepted = receiver(vec![part(b"", false), part(b"ok", true)]);
    assert_eq!(accepted.recv_with_limits(8, 2).await.unwrap(), b"ok"[..]);
    let rejected = receiver(vec![part(b"", false), part(b"", false), part(b"ok", true)]);
    assert!(matches!(
        rejected.recv_with_limits(8, 2).await,
        Err(GoBackNConnError::Protocol(
            "received message exceeds fragment limit"
        ))
    ));
}

#[tokio::test]
async fn public_receive_enforces_the_actual_message_byte_ceiling() {
    for (bytes, accepted) in [(MAX_MESSAGE_BYTES, true), (MAX_MESSAGE_BYTES + 1, false)] {
        let connection = receiver(vec![ReceivedFrame {
            payload: Bytes::from(vec![42; bytes]),
            final_chunk: true,
        }]);
        let outcome = connection.recv().await;
        if accepted {
            assert_eq!(outcome.unwrap().len(), MAX_MESSAGE_BYTES);
        } else {
            assert!(matches!(
                outcome,
                Err(GoBackNConnError::Protocol(
                    "received message exceeds byte limit"
                ))
            ));
        }
    }
}

#[tokio::test]
async fn public_receive_enforces_the_actual_empty_fragment_ceiling() {
    for (count, accepted) in [
        (MAX_MESSAGE_FRAGMENTS, true),
        (MAX_MESSAGE_FRAGMENTS + 1, false),
    ] {
        let parts = (0..count)
            .map(|index| part(b"", index + 1 == count))
            .collect();
        let connection = receiver(parts);
        let outcome = connection.recv().await;
        if accepted {
            assert!(outcome.unwrap().is_empty());
        } else {
            assert!(matches!(
                outcome,
                Err(GoBackNConnError::Protocol(
                    "received message exceeds fragment limit"
                ))
            ));
        }
    }
}

#[tokio::test]
async fn cancelling_partial_public_receive_releases_fragment_and_assembly_reservations() {
    use crate::transport::lncmailbox::receive_budget::ReceiveBudget;
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let budget = ReceiveBudget::new(1024, shutdown);
    let (events, event_receiver) = mpsc::channel(1);
    let mut buffer = budget.allocate(4).unwrap();
    buffer.as_mut_slice().copy_from_slice(b"abcd");
    events
        .send(RecvEvent::Payload(ReceivedFrame {
            payload: buffer.finish(4),
            final_chunk: false,
        }))
        .await
        .unwrap();
    let (outbound, _outbound_receiver) = mpsc::channel(1);
    let mut inner = Inner::new(GoBackNOptions::default(), outbound, events.clone());
    inner.receive_budget = Some(budget.clone());
    let connection = Arc::new(GoBackNConn {
        inner: Arc::new(inner),
        data_rx: Arc::new(Mutex::new(event_receiver)),
        reader: tokio::spawn(std::future::pending()),
        resend_task: tokio::spawn(std::future::pending()),
        keepalive_task: tokio::spawn(std::future::pending()),
    });
    let receiving = connection.clone();
    let task = tokio::spawn(async move { receiving.recv_with_limits(8, 2).await });
    // This permit becomes available only after the owning receive consumes the
    // first non-final fragment; no second fragment can complete the operation.
    let permit = tokio::time::timeout(std::time::Duration::from_secs(5), events.reserve())
        .await
        .unwrap()
        .unwrap();
    assert!(!task.is_finished());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(permit);
    drop(connection);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn assembly_admits_copy_while_original_fragments_remain_reserved() {
    use crate::transport::lncmailbox::receive_budget::ReceiveBudget;
    for (capacity, accepted) in [(848, true), (847, false)] {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let budget = ReceiveBudget::new(capacity, shutdown);
        let pieces = [b"abcd", b"efgh"]
            .into_iter()
            .enumerate()
            .map(|(index, contents)| {
                let mut buffer = budget.allocate(4).unwrap();
                buffer.as_mut_slice().copy_from_slice(contents);
                ReceivedFrame {
                    payload: buffer.finish(4),
                    final_chunk: index == 1,
                }
            })
            .collect();
        let mut connection = receiver(pieces);
        Arc::get_mut(&mut connection.inner).unwrap().receive_budget = Some(budget.clone());
        let outcome = connection.recv_with_limits(8, 2).await;
        if accepted {
            let received = outcome.unwrap();
            assert_eq!(received.as_ref(), b"abcdefgh");
            assert_eq!(budget.used(), 264);
            drop(received);
        } else {
            assert!(matches!(
                outcome,
                Err(GoBackNConnError::Protocol(
                    "receive retention budget exceeded"
                ))
            ));
            assert!(budget.exhausted());
        }
        assert_eq!(budget.used(), 0);
    }
}
