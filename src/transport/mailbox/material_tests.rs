use super::MailboxTransport;

const PHRASE: &str = "abandon ability able about above absent absorb abstract absurd abuse";
const LOCAL: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const REMOTE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// Pure preflight must work outside any runtime, including XX and the upstream
// generate-local-on-connect input. Actual handshake/context tests remain separate.
#[test]
fn pairing_preflight_accepts_valid_inputs_without_a_runtime() {
    MailboxTransport::validate_pairing_material(PHRASE, LOCAL, REMOTE).unwrap();
    MailboxTransport::validate_pairing_material(PHRASE, LOCAL, "").unwrap();
    MailboxTransport::validate_pairing_material(PHRASE, "", "").unwrap();
}

#[test]
fn pairing_preflight_rejects_invalid_material_without_echoing_input() {
    MailboxTransport::validate_pairing_material(PHRASE, LOCAL, REMOTE).unwrap();
    let invalid_phrase = PHRASE.replacen("abandon", "private-canary", 1);
    let zero_scalar = "0".repeat(64);
    let invalid_curve_point = format!("02{}", "ff".repeat(32));
    for (phrase, local, remote, error) in [
        (
            invalid_phrase.as_str(),
            LOCAL,
            REMOTE,
            "invalid pairing phrase",
        ),
        (PHRASE, "private-canary", REMOTE, "invalid local key hex"),
        (
            PHRASE,
            zero_scalar.as_str(),
            REMOTE,
            "invalid local key bytes",
        ),
        (PHRASE, LOCAL, "private-canary", "invalid remote key hex"),
        (
            PHRASE,
            LOCAL,
            invalid_curve_point.as_str(),
            "invalid remote key bytes",
        ),
    ] {
        let result =
            MailboxTransport::validate_pairing_material(phrase, local, remote).unwrap_err();
        let display = result.to_string();
        assert!(display.contains(error), "{display}");
        assert!(!display.contains("private-canary"));
    }
}

#[test]
fn pairing_preflight_enforces_its_field_byte_ceiling() {
    // Exactly the byte limit remains a valid ten-word phrase with legal padding.
    let at_limit = format!("{PHRASE}{}", " ".repeat(4096 - PHRASE.len()));
    MailboxTransport::validate_pairing_material(&at_limit, LOCAL, REMOTE).unwrap();
    let over_limit = format!("{at_limit} ");
    for (phrase, local, remote) in [
        (over_limit.as_str(), LOCAL, REMOTE),
        (PHRASE, over_limit.as_str(), REMOTE),
        (PHRASE, LOCAL, over_limit.as_str()),
    ] {
        let result =
            MailboxTransport::validate_pairing_material(phrase, local, remote).unwrap_err();
        assert!(result
            .to_string()
            .contains("pairing material field exceeds byte limit"));
    }
}

#[test]
fn semantic_pairing_identity_matches_independent_length_framed_vectors() {
    // Python hashlib reference: literal AEZEED entropy from the published word
    // indices 0..9, scalar1, compressed secp256k1 generator, big-endian u64 lengths.
    let expected_kk = "a711e79ba71c0635ee4969b89449d24b5e754d9d976288cf91dba3244d2ead6c";
    let expected_xx = "197d1c724b7ab55e6e8d5faf2f2db6ff601268dae606573ee3bbb8fd83fbae7d";
    let authority = "mailbox.example:443";
    assert_eq!(
        hex::encode(
            MailboxTransport::pairing_commitment(authority, PHRASE, LOCAL, REMOTE).unwrap()
        ),
        expected_kk
    );
    assert_eq!(
        hex::encode(MailboxTransport::pairing_commitment(authority, PHRASE, LOCAL, "").unwrap()),
        expected_xx
    );
    let padded_phrase = PHRASE.replace(' ', "\t  ");
    let uncompressed_generator = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    assert_eq!(
        hex::encode(
            MailboxTransport::pairing_commitment(
                authority,
                &padded_phrase,
                &LOCAL.to_uppercase(),
                uncompressed_generator
            )
            .unwrap()
        ),
        expected_kk
    );
    assert!(MailboxTransport::pairing_commitment(authority, PHRASE, "", REMOTE).is_err());
    let scalar_ten_lower = format!("{}a", "0".repeat(63));
    for local in [&scalar_ten_lower, &scalar_ten_lower.to_uppercase()] {
        assert_eq!(
            hex::encode(
                MailboxTransport::pairing_commitment(authority, PHRASE, local, REMOTE).unwrap()
            ),
            "58f9e2b37502428fb259eb774617308e832065d85a99445e4dc5c18bbd5e3485"
        );
    }
    for (host, phrase, local, remote) in [
        (
            "mailbox.example:444",
            PHRASE.to_owned(),
            LOCAL.to_owned(),
            REMOTE.to_owned(),
        ),
        (
            authority,
            PHRASE.replacen("abuse", "abandon", 1),
            LOCAL.to_owned(),
            REMOTE.to_owned(),
        ),
        (
            authority,
            PHRASE.to_owned(),
            format!("{}2", "0".repeat(63)),
            REMOTE.to_owned(),
        ),
        (
            authority,
            PHRASE.to_owned(),
            LOCAL.to_owned(),
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".to_owned(),
        ),
    ] {
        assert_ne!(
            hex::encode(
                MailboxTransport::pairing_commitment(host, &phrase, &local, &remote).unwrap()
            ),
            expected_kk
        );
    }
}
