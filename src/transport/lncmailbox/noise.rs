#![cfg(feature = "transport-mailbox")]

use k256::{
    elliptic_curve::ops::Reduce, FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey, U256,
};
#[cfg(test)]
use parking_lot::Mutex;
#[cfg(test)]
use rand::{rngs::StdRng, SeedableRng};
#[cfg(test)]
use std::sync::LazyLock;

// Protocol constants
pub const PROTOCOL_NAME: &str = "XXeke_secp256k1+SPAKE2_CHACHAPOLY1305_SHA256";
pub const HANDSHAKE_VERSION0: u8 = 0;
pub const HANDSHAKE_VERSION1: u8 = 1;
pub const HANDSHAKE_VERSION2: u8 = 2;
pub const ACT_TWO_PAYLOAD_SIZE: usize = 500;

// N: SPAKE2 generator point for LNC, compressed form from Go reference
const N_COMPRESSED: &str = "0254a58cd0f31c008fd0bc9b2dd5ba586144933829f6da33ac4130b555fb5ea32c";

fn point_n() -> ProjectivePoint {
    let bytes = hex::decode(N_COMPRESSED);
    assert!(bytes.is_ok(), "invalid N constant hex");
    let bytes = bytes.unwrap();
    let pk = PublicKey::from_sec1_bytes(&bytes);
    assert!(pk.is_ok(), "failed to parse N constant");
    let pk = pk.unwrap();
    ProjectivePoint::from(pk)
}

fn scalar_from_entropy(entropy: &[u8]) -> Scalar {
    let mut pw_bytes = [0u8; 32];
    let copy_len = entropy.len().min(32);
    pw_bytes[32 - copy_len..].copy_from_slice(&entropy[entropy.len() - copy_len..]);
    let field_bytes = FieldBytes::from(pw_bytes);
    <Scalar as Reduce<U256>>::reduce_bytes(&field_bytes)
}

/// SPAKE2 masking: me = e + N*pw
///
/// # Panics
/// Panics if the resulting point cannot be converted into a [`PublicKey`], which should never
/// happen with a valid secp256k1 point.
#[must_use]
pub fn spake2_mask(ephemeral_pub: &PublicKey, passphrase_entropy: &[u8]) -> PublicKey {
    // Passphrase entropy is 32 bytes after scrypt stretch; callers should pass stretched value.
    // If shorter, left-pad.
    let pw = scalar_from_entropy(passphrase_entropy);

    let n = point_n();
    let pw_n = n * pw;
    let e = ProjectivePoint::from(*ephemeral_pub);
    let result = e + pw_n;
    let out = PublicKey::from_affine(result.to_affine());
    assert!(out.is_ok(), "SPAKE2 mask produced invalid point");
    out.unwrap()
}

/// SPAKE2 unmasking: e = me - N*pw
///
/// # Panics
/// Panics if the resulting point cannot be converted into a [`PublicKey`], which should never
/// happen with a valid secp256k1 point.
#[must_use]
pub fn spake2_unmask(masked_pub: &PublicKey, passphrase_entropy: &[u8]) -> PublicKey {
    let pw = scalar_from_entropy(passphrase_entropy);

    let n = point_n();
    let pw_n = n * pw;
    let me = ProjectivePoint::from(*masked_pub);
    let result = me - pw_n;
    let out = PublicKey::from_affine(result.to_affine());
    assert!(out.is_ok(), "SPAKE2 unmask produced invalid point");
    out.unwrap()
}

/// Generate a fresh ephemeral key pair.
#[must_use]
pub fn gen_ephemeral() -> (SecretKey, PublicKey) {
    #[cfg(test)]
    {
        if let Some(rng) = TEST_EPHEMERAL_RNG.lock().as_mut() {
            let sk = SecretKey::random(rng);
            let pk = PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());
            return (sk, pk);
        }
    }
    let sk = SecretKey::random(&mut rand::thread_rng());
    let pk = PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());
    (sk, pk)
}

#[cfg(test)]
static TEST_EPHEMERAL_RNG: LazyLock<Mutex<Option<StdRng>>> = LazyLock::new(|| Mutex::new(None));

#[cfg(test)]
/// Seed the deterministic RNG used by `gen_ephemeral` during tests.
///
/// Tests using this function should be marked with `#[serial]` to prevent
/// concurrent access to the shared RNG state.
pub fn seed_ephemeral_rng(seed: u64) {
    *TEST_EPHEMERAL_RNG.lock() = Some(StdRng::seed_from_u64(seed));
}

#[cfg(test)]
/// Clear the deterministic RNG. Call at end of tests that use `seed_ephemeral_rng`.
pub fn clear_ephemeral_rng() {
    *TEST_EPHEMERAL_RNG.lock() = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};

    #[test]
    fn spake2_mask_roundtrip() {
        let (_sk, pk) = gen_ephemeral();
        let pass = Sha256::digest(b"top secret passphrase");
        let masked = spake2_mask(&pk, pass.as_ref());
        assert_ne!(masked.to_encoded_point(false), pk.to_encoded_point(false));

        let recovered = spake2_unmask(&masked, pass.as_ref());
        assert_eq!(
            recovered.to_encoded_point(false),
            pk.to_encoded_point(false)
        );
    }
}
