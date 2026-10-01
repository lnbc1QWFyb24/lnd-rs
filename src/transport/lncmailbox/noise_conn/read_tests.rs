use super::*;
use crate::transport::lncmailbox::{
    conn::ClientConnParams,
    gbn::{Frame, GoBackNOptions},
    noise::HANDSHAKE_VERSION2,
    noise_machine::PatternRef,
    ws::WsTimeouts,
};
use bytes::Bytes;
use k256::SecretKey;
use std::{net::TcpListener, time::Duration};
use tokio::io::AsyncReadExt;

use crate::test_support::mailbox_relay as relay;

const WATCHDOG: Duration = Duration::from_secs(10);

fn configured_machine(initiator: bool) -> BrontideMachine {
    let local = SecretKey::from_slice(&[if initiator { 0x11 } else { 0x22 }; 32]).unwrap();
    let remote = SecretKey::from_slice(&[if initiator { 0x22 } else { 0x11 }; 32]).unwrap();
    let remote = remote.public_key();
    BrontideMachine::new(BrontideMachineConfig {
        initiator,
        pattern: PatternRef::Kk,
        min_handshake_version: HANDSHAKE_VERSION2,
        max_handshake_version: HANDSHAKE_VERSION2,
        local_static: Arc::new(local),
        remote_static: Some(remote),
        passphrase_entropy: Arc::new(vec![3; 14]),
        auth_payload: None,
        on_remote_static: None,
        on_auth_data: None,
    })
    .unwrap()
}

/// Complete the real machine handshake on bounded local synchronous sockets.
fn authenticated_machines() -> (BrontideMachine, BrontideMachine) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut outbound =
        std::net::TcpStream::connect_timeout(&listener.local_addr().unwrap(), WATCHDOG).unwrap();
    let (mut inbound, _) = listener.accept().unwrap();
    for socket in [&outbound, &inbound] {
        socket.set_read_timeout(Some(WATCHDOG)).unwrap();
        socket.set_write_timeout(Some(WATCHDOG)).unwrap();
    }
    let responder = std::thread::spawn(move || {
        let mut machine = configured_machine(false);
        let handshake = machine.do_handshake(&mut inbound);
        (machine, handshake)
    });
    let mut initiator = configured_machine(true);
    let handshake = initiator.do_handshake(&mut outbound);
    let (responder, response_handshake) = responder.join().unwrap();
    handshake.unwrap();
    response_handshake.unwrap();
    (initiator, responder)
}

#[test]
fn authenticated_empty_record_does_not_hide_the_following_bytes_as_eof() {
    const EXPECTED: &[u8] = b"record-after-authenticated-empty";
    let (read_machine, mut write_machine) = authenticated_machines();
    let mut ciphertext = Vec::new();
    write_machine.write_message(b"").unwrap();
    write_machine.flush(&mut ciphertext).unwrap();
    write_machine.write_message(EXPECTED).unwrap();
    write_machine.flush(&mut ciphertext).unwrap();
    let control = ControlMsg {
        version: 0,
        payload: ciphertext.into(),
    };
    let frame = Frame::Data {
        seq: 0,
        final_chunk: true,
        is_ping: false,
        payload: Bytes::from(control.encode()),
    }
    .encode();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (received, plaintext, emitted, joined) = runtime.block_on(async {
        let fixture = relay::Fixture::new(0).await;
        let client = tokio::time::timeout(
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
        .unwrap();
        let client = Arc::new(client);
        tokio::time::timeout(WATCHDOG, fixture.acknowledged)
            .await
            .unwrap()
            .unwrap();
        let mut noise = NoiseConn::from_established(client.clone(), read_machine);
        fixture.frames.send(vec![frame]).unwrap();
        let mut plaintext = vec![0; EXPECTED.len()];
        let received = tokio::time::timeout(WATCHDOG, noise.read_exact(&mut plaintext)).await;
        let emitted = tokio::time::timeout(WATCHDOG, fixture.emitted).await;
        drop(noise);
        client.close().await;
        drop(client);
        drop(fixture.frames);
        let joined = tokio::time::timeout(WATCHDOG, fixture.server).await;
        (received, plaintext, emitted, joined)
    });
    drop(runtime);
    assert!(matches!(joined, Ok(Ok(Ok(())))));
    assert_eq!(emitted.unwrap().unwrap(), 1);
    assert!(
        matches!(received, Ok(Ok(_))),
        "{:?}",
        received
            .as_ref()
            .map(|result| result.as_ref().map_err(std::io::Error::kind))
    );
    assert_eq!(plaintext, EXPECTED);
}
