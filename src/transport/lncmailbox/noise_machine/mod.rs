#![cfg(feature = "transport-mailbox")]

//! Noise protocol machine for LNC, split into focused modules.

pub mod cipher_state;
pub mod machine;
pub mod symmetric_state;

pub use super::noise_pattern::PatternRef;
pub use machine::{
    BrontideMachine, BrontideMachineConfig, ENC_HEADER_SIZE, LENGTH_HEADER_SIZE, MAC_SIZE,
};

#[derive(thiserror::Error, Debug)]
pub enum NoiseError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
}
