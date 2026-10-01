//! Typed receive-envelope decoding skips unneeded remote JSON values.
use std::borrow::Cow;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

use super::super::receive_budget::ReceiveBudget;
use super::WsError;
use bytes::Bytes;

#[derive(Deserialize)]
struct CipherBoxResp<'a> {
    #[serde(rename = "msg")]
    #[serde(borrow)]
    msg: Cow<'a, str>,
}

#[derive(Deserialize)]
struct ReceiveEnvelope<'a> {
    #[serde(borrow)]
    result: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    error: Option<&'a serde_json::value::RawValue>,
}

pub(super) fn decode_cipher_box(wrapped: &str) -> Result<Vec<u8>, WsError> {
    STANDARD
        .decode(ciphertext(wrapped)?.as_bytes())
        .map_err(|e| WsError::Decode(e.to_string()))
}

pub(super) fn decode_budgeted(wrapped: &str, budget: &ReceiveBudget) -> Result<Bytes, WsError> {
    let encoded = ciphertext(wrapped)?;
    let maximum = encoded
        .len()
        .div_ceil(4)
        .checked_mul(3)
        .ok_or(WsError::ReceiveLimit)?;
    let mut buffer = budget
        .allocate(maximum)
        .map_err(|()| WsError::ReceiveLimit)?;
    let length = STANDARD
        .decode_slice(encoded.as_bytes(), buffer.as_mut_slice())
        .map_err(|e| WsError::Decode(e.to_string()))?;
    Ok(buffer.finish(length))
}

fn ciphertext(wrapped: &str) -> Result<Cow<'_, str>, WsError> {
    if !wrapped.trim_start().starts_with('{') {
        return Err(WsError::Decode("unexpected JSON envelope".into()));
    }
    // Borrow raw envelope fields. Typed result decoding skips unknown fields
    // without materializing arbitrary JSON trees or serializing result again.
    let envelope: ReceiveEnvelope<'_> =
        serde_json::from_str(wrapped).map_err(|e| WsError::Decode(e.to_string()))?;
    if let Some(result) = envelope.result {
        let parsed: CipherBoxResp<'_> =
            serde_json::from_str(result.get()).map_err(|e| WsError::Decode(e.to_string()))?;
        return Ok(parsed.msg);
    }
    if let Some(error) = envelope.error {
        // Keep the existing status classifier's text without allocating a
        // generic tree for structured remote errors.
        let message =
            serde_json::from_str::<String>(error.get()).unwrap_or_else(|_| error.get().to_owned());
        return Err(WsError::Server(message));
    }
    Err(WsError::Decode("missing result/error fields".into()))
}
