#![cfg(feature = "transport-mailbox")]

use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, PublicKey, SecretKey};
use sha2::{Digest, Sha512};

use super::crypto::hmac256;

#[must_use]
pub fn derive_sid(entropy: &[u8], local: &SecretKey, remote_opt: Option<&PublicKey>) -> [u8; 64] {
    let source: Vec<u8> = if let Some(remote) = remote_opt {
        let shared = ecdh(local, remote);
        let mix = hmac256(&shared, b"mailbox");
        mix.to_vec()
    } else {
        entropy.to_vec()
    };
    let mut hasher = Sha512::new();
    hasher.update(&source);
    let out = hasher.finalize();
    let mut sid = [0u8; 64];
    sid.copy_from_slice(&out);
    sid
}

fn ecdh(local: &SecretKey, remote: &PublicKey) -> [u8; 32] {
    // Match Go reference: use sha256(compressed shared point) as DH output.
    let nz = local.to_nonzero_scalar();
    let p = ProjectivePoint::from(*remote) * *nz.as_ref();
    let pk = PublicKey::from_affine(p.to_affine());
    assert!(pk.is_ok(), "ECDH point conversion failed");
    let pk = pk.unwrap();
    let enc = pk.to_encoded_point(true);
    let mut out = [0u8; 32];
    let digest = sha2::Sha256::digest(enc.as_bytes());
    out.copy_from_slice(&digest);
    out
}

#[must_use]
pub fn sid_stream_ids(sid: [u8; 64]) -> ([u8; 64], [u8; 64]) {
    // server->client is sid unchanged; client->server flips last bit
    let mut client_to_server = sid;
    client_to_server[63] ^= 0x01;
    (sid, client_to_server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn fixed_secret(byte: u8) -> SecretKey {
        let mut raw = [byte; 32];
        // Ensure we don't end up with zero which would be invalid.
        if byte == 0 {
            raw[31] = 1;
        }
        SecretKey::from_slice(&raw).expect("secret key")
    }

    #[test]
    fn derive_sid_xx_matches_sha512_entropy() {
        let entropy: Vec<u8> = (0u8..14u8).collect();
        let local = fixed_secret(1);
        let sid = derive_sid(&entropy, &local, None);
        let mut hasher = Sha512::new();
        hasher.update(&entropy);
        let digest = hasher.finalize();
        let mut expected = [0u8; 64];
        expected.copy_from_slice(&digest);
        assert_eq!(sid, expected);
    }

    #[test]
    fn derive_sid_kk_matches_hmac_mix() {
        let entropy: Vec<u8> = (0u8..14u8).collect();
        let local = fixed_secret(2);
        let remote_secret = fixed_secret(3);
        let remote_pub = PublicKey::from_secret_scalar(&remote_secret.to_nonzero_scalar());

        let sid = derive_sid(&entropy, &local, Some(&remote_pub));

        let shared = super::ecdh(&local, &remote_pub);
        let mix = hmac256(&shared, b"mailbox");
        let mut hasher = Sha512::new();
        hasher.update(mix);
        let digest = hasher.finalize();
        let mut expected = [0u8; 64];
        expected.copy_from_slice(&digest);

        assert_eq!(sid, expected);
    }

    #[test]
    fn stream_ids_flip_last_bit() {
        let sid = [0x55u8; 64];
        let (srv, cli) = sid_stream_ids(sid);
        assert_eq!(sid, srv);
        let mut expected = sid;
        expected[63] ^= 0x01;
        assert_eq!(cli, expected);
    }
}
