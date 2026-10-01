//! Retain leased controls and gather only one bounded Noise record at a time.

use std::{collections::VecDeque, io::Cursor, sync::Arc};

use bytes::{Buf, Bytes};
use tokio::sync::{mpsc, Mutex};

use super::{BrontideMachine, ClientConn, ClientConnError, GoBackNConnError, NoiseConnError};

pub(super) async fn reader_loop(
    client: Arc<ClientConn>,
    machine: Arc<Mutex<BrontideMachine>>,
    tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), NoiseConnError> {
    let mut ciphertext = Ciphertext::default();
    loop {
        let Some(header) = ciphertext
            .take(&client, super::super::noise_machine::ENC_HEADER_SIZE)
            .await?
        else {
            return Ok(());
        };
        // Never hold the machine lock while waiting for transport bytes: writes
        // (including HTTP/2 SETTINGS acknowledgements) use the same machine.
        let length = {
            let mut guard = machine.lock().await;
            guard.read_header(&mut Cursor::new(&header))?
        } as usize;
        // read_header obtains a u16 plaintext length and adds the 16-byte MAC.
        // At most one 65,551-byte ciphertext is copied, not a 64-MiB control.
        let Some(body) = ciphertext.take(&client, length).await? else {
            return Ok(());
        };
        let plaintext = {
            let mut guard = machine.lock().await;
            let mut temporary = vec![0; length];
            guard.read_body(&mut Cursor::new(&body), &mut temporary)?
        };
        if plaintext.is_empty() {
            // Authenticate even empty records so cipher nonces advance. They
            // carry no stream bytes and must not make AsyncRead report EOF.
            // Yield explicitly for a buffered run of empty records while still
            // observing shutdown; the ordinary plaintext queue cannot do it.
            tokio::select! {
                biased;
                () = client.wait_for_shutdown() => return Ok(()),
                () = tokio::task::yield_now() => {},
            }
            continue;
        }
        // The plaintext queue is independently bounded to 32 u16-sized records.
        tokio::select! {
            biased;
            () = client.wait_for_shutdown() => return Ok(()),
            result = tx.send(plaintext) => if result.is_err() { return Ok(()); },
        }
    }
}

#[derive(Default)]
struct Ciphertext {
    chunks: VecDeque<Bytes>,
}

impl Ciphertext {
    async fn take(
        &mut self,
        client: &ClientConn,
        length: usize,
    ) -> Result<Option<Vec<u8>>, NoiseConnError> {
        let mut record = vec![0; length];
        let mut offset = 0;
        while offset < length {
            if let Some(chunk) = self.chunks.front_mut() {
                let amount = chunk.len().min(length - offset);
                record[offset..offset + amount].copy_from_slice(&chunk[..amount]);
                chunk.advance(amount);
                offset += amount;
                if chunk.is_empty() {
                    self.chunks.pop_front();
                }
                continue;
            }
            match client.receive_control_msg().await {
                Ok(message) if !message.payload.is_empty() => {
                    self.chunks.push_back(message.payload);
                }
                Ok(_) | Err(ClientConnError::Gbn(GoBackNConnError::RecvTimeout)) => {}
                Err(ClientConnError::Gbn(GoBackNConnError::Closed)) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Some(record))
    }
}
