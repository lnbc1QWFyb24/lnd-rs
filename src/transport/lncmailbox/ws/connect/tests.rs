use super::*;
mod tls;
use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::{Callback, ErrorResponse, Request, Response},
        Message,
    },
};

struct CheckAuthority(String);

impl Callback for CheckAuthority {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        assert_eq!(request.headers()["host"], self.0);
        assert_eq!(request.uri().path(), "/mailbox");
        Ok(response)
    }
}

/// A hostname that cannot resolve still reaches the explicit local address, and
/// the HTTP authority remains the original hostname rather than the numeric IP.
#[tokio::test]
async fn explicit_address_preserves_original_http_authority() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let authority = format!("mailbox.invalid:{}", address.port());
    let expected_authority = authority.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let socket = accept_hdr_async(stream, CheckAuthority(expected_authority))
            .await
            .unwrap();
        drop(socket);
    });
    let socket = open(&format!("ws://{authority}/mailbox"), Some(address), None)
        .await
        .unwrap();
    drop(socket);
    server.await.unwrap();
}

/// Exercise the configured receive bound through an actual websocket frame,
/// including its valid adjacent case, rather than inspecting configuration.
#[tokio::test]
async fn explicit_address_keeps_the_upstream_frame_ceiling() {
    use futures_util::SinkExt;
    for (bytes, accepted) in [(MAX_FRAME_BYTES, true), (MAX_FRAME_BYTES + 1, false)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            // A rejected frame may close while the server is writing its body.
            let result = socket.send(Message::Binary(vec![42; bytes].into())).await;
            if accepted {
                result.unwrap();
            }
        });
        let mut socket = open("ws://mailbox.invalid/", Some(address), None)
            .await
            .unwrap();
        let result = socket.next().await.unwrap();
        if accepted {
            assert_eq!(result.unwrap().into_data().len(), MAX_FRAME_BYTES);
        } else {
            assert!(matches!(result, Err(Error::Capacity(_))));
        }
        drop(socket);
        server.await.unwrap();
    }
}
