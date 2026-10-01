use lnd_rs::{credentials::InMemoryCredentialStore, PairingCredentials};

#[test]
fn public_credential_debug_never_exposes_supplied_values() {
    const CANARY: &str = "credential-debug-private-canary";
    let credentials = PairingCredentials {
        server_host: CANARY.into(),
        pairing_phrase: CANARY.into(),
        local_key: CANARY.into(),
        remote_key: CANARY.into(),
        macaroon_hex: Some(CANARY.into()),
    };
    let store = InMemoryCredentialStore {
        password: Some(CANARY.into()),
        server_host: Some(CANARY.into()),
        pairing_phrase: Some(CANARY.into()),
        local_key: Some(CANARY.into()),
        remote_key: Some(CANARY.into()),
    };
    for diagnostic in [
        format!("{credentials:?}"),
        format!("{credentials:#?}"),
        format!("{store:?}"),
        format!("{store:#?}"),
    ] {
        assert!(!diagnostic.contains(CANARY));
        assert!(diagnostic.contains("[redacted]"));
    }
}
