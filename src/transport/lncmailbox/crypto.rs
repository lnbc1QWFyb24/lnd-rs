#![cfg(feature = "transport-mailbox")]

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Compute `HMAC-SHA256(key, msg)` and return the raw 32-byte digest.
///
/// # Panics
/// Panics if `key` does not meet the HMAC requirements, which indicates a programming error.
#[must_use]
pub fn hmac256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    assert!(!key.is_empty(), "HMAC key must not be empty");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut out_arr = [0u8; 32];
    out_arr.copy_from_slice(&out);
    out_arr
}

/// Stretch the pairing entropy using the standard AEZEED scrypt parameters.
///
/// # Errors
/// Returns an error when the scrypt parameters are invalid or the derivation fails.
pub fn scrypt_stretch(entropy: &[u8]) -> Result<Vec<u8>, String> {
    // scrypt params from Go: N=1<<16, r=8, p=1, len=32
    let mut out = [0u8; 32];
    scrypt::scrypt(
        entropy,
        entropy,
        &scrypt::Params::new(16, 8, 1, 32).map_err(|e| e.to_string())?,
        &mut out,
    )
    .map_err(|e| e.to_string())?;
    Ok(out.to_vec())
}
