//! Bounds reassembly independently of websocket frame and queue capacities.

use bytes::Bytes;

use super::{GoBackNConn, GoBackNConnError};

/// Same generous byte ceiling as the websocket message limit, applied to the
/// complete control message even when GBN splits it across multiple messages.
pub(super) const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// Empty fragments consume work too. Normal 32 KiB chunks need only 2,048
/// fragments at the byte ceiling; this allows substantial smaller fragmentation.
pub(super) const MAX_MESSAGE_FRAGMENTS: usize = 65_536;

impl GoBackNConn {
    /// Consume at most the caller's byte and fragment budget for one message.
    /// The private limits permit deterministic small-budget contract tests;
    /// the public receive operation always uses the fixed bounds above.
    pub(super) async fn recv_with_limits(
        &self,
        max_bytes: usize,
        max_fragments: usize,
    ) -> Result<Bytes, GoBackNConnError> {
        if max_bytes == 0 || max_fragments == 0 {
            return Err(GoBackNConnError::Protocol("invalid receive limits"));
        }
        // Account for every possible Bytes handle while retaining fragments.
        // Allocation owners keep their own leases until coalescing has finished.
        let _metadata = self
            .inner
            .receive_budget
            .as_ref()
            .map(|budget| {
                budget.reserve(max_fragments.saturating_mul(std::mem::size_of::<Bytes>()))
            })
            .transpose()
            .map_err(|()| self.inner.receive_closed_error())?;
        let mut fragments = Vec::with_capacity(max_fragments);
        let mut length = 0usize;
        for _ in 0..max_fragments {
            let part = self.recv_frame().await?;
            if part.payload.len() > max_bytes.saturating_sub(length) {
                return Err(GoBackNConnError::Protocol(
                    "received message exceeds byte limit",
                ));
            }
            length += part.payload.len();
            fragments.push(part.payload);
            if part.final_chunk {
                if fragments.len() == 1 {
                    return Ok(fragments.remove(0));
                }
                if let Some(budget) = &self.inner.receive_budget {
                    let mut buffer = budget
                        .allocate(length)
                        .map_err(|()| self.inner.receive_closed_error())?;
                    copy_fragments(&fragments, buffer.as_mut_slice());
                    return Ok(buffer.finish(length));
                }
                let mut buffer = vec![0; length];
                copy_fragments(&fragments, &mut buffer);
                return Ok(Bytes::from(buffer));
            }
        }
        Err(GoBackNConnError::Protocol(
            "received message exceeds fragment limit",
        ))
    }
}

fn copy_fragments(fragments: &[Bytes], buffer: &mut [u8]) {
    let mut offset = 0;
    for fragment in fragments {
        let end = offset + fragment.len();
        buffer[offset..end].copy_from_slice(fragment);
        offset = end;
    }
}

#[cfg(test)]
mod tests;
