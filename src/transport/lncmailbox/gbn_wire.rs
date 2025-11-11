#![cfg(feature = "transport-mailbox")]

//! Go-Back-N wire primitives: opcodes and frame encoding/decoding.

use bytes::Bytes;

#[derive(Debug, thiserror::Error)]
pub enum GbnError {
    #[error("frame too short for opcode {0:#x}")]
    FrameTooShort(u8),
    #[error("unknown opcode {0:#x}")]
    UnknownOpcode(u8),
}

pub const SYN: u8 = 0x01;
pub const DATA: u8 = 0x02;
pub const ACK: u8 = 0x03;
pub const NACK: u8 = 0x04;
pub const FIN: u8 = 0x05;
pub const SYNACK: u8 = 0x06;

const FALSE: u8 = 0x00;
const TRUE: u8 = 0x01;

/// Wire-level representation of the Go-Back-N control/data packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Syn {
        window: u8,
    },
    SynAck,
    Ack {
        seq: u8,
    },
    Nack {
        seq: u8,
    },
    Fin,
    Data {
        seq: u8,
        final_chunk: bool,
        is_ping: bool,
        payload: Bytes,
    },
}

impl Frame {
    /// Encode this frame into a new owned buffer.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Syn { window } => vec![SYN, *window],
            Frame::SynAck => vec![SYNACK],
            Frame::Ack { seq } => vec![ACK, *seq],
            Frame::Nack { seq } => vec![NACK, *seq],
            Frame::Fin => vec![FIN],
            Frame::Data {
                seq,
                final_chunk,
                is_ping,
                payload,
            } => {
                let mut out = Vec::with_capacity(4 + payload.len());
                out.push(DATA);
                out.push(*seq);
                out.push(if *final_chunk { TRUE } else { FALSE });
                out.push(if *is_ping { TRUE } else { FALSE });
                out.extend_from_slice(payload);
                out
            }
        }
    }

    /// Decode a serialized Go-Back-N frame.
    ///
    /// # Errors
    /// Returns [`GbnError`] when the frame is shorter than required or the opcode is unknown.
    pub fn decode(raw: &[u8]) -> Result<Frame, GbnError> {
        if raw.is_empty() {
            return Err(GbnError::FrameTooShort(0));
        }
        match raw[0] {
            SYN => {
                if raw.len() < 2 {
                    return Err(GbnError::FrameTooShort(SYN));
                }
                Ok(Frame::Syn { window: raw[1] })
            }
            SYNACK => Ok(Frame::SynAck),
            ACK => {
                if raw.len() < 2 {
                    return Err(GbnError::FrameTooShort(ACK));
                }
                Ok(Frame::Ack { seq: raw[1] })
            }
            NACK => {
                if raw.len() < 2 {
                    return Err(GbnError::FrameTooShort(NACK));
                }
                Ok(Frame::Nack { seq: raw[1] })
            }
            FIN => Ok(Frame::Fin),
            DATA => {
                if raw.len() < 4 {
                    return Err(GbnError::FrameTooShort(DATA));
                }
                Ok(Frame::Data {
                    seq: raw[1],
                    final_chunk: raw[2] == TRUE,
                    is_ping: raw[3] == TRUE,
                    payload: Bytes::copy_from_slice(&raw[4..]),
                })
            }
            other => Err(GbnError::UnknownOpcode(other)),
        }
    }
}
