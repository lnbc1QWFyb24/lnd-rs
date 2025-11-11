use std::sync::Arc;

use tokio::sync::watch;

use crate::transport::lncmailbox::conn::{ClientConn, ClientStatus};

use super::http2::Http2Channel;

pub(crate) struct MailboxState {
    pub(crate) client: Arc<ClientConn>,
    pub(crate) svc: Http2Channel,
    pub(crate) metadata: Arc<[(String, String)]>,
    pub(crate) status_rx: watch::Receiver<ClientStatus>,
}

pub fn parse_auth_metadata(raw: &[u8]) -> Vec<(String, String)> {
    if raw.is_empty() {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return Vec::new();
    };
    text.split("\r\n")
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            line.split_once(": ")
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_auth_metadata;

    #[test]
    fn metadata_parsing() {
        let raw = b"macaroon: abc\r\nx-custom: value\r\n";
        let parsed = parse_auth_metadata(raw);
        assert_eq!(
            parsed,
            vec![
                ("macaroon".to_string(), "abc".to_string()),
                ("x-custom".to_string(), "value".to_string())
            ]
        );
    }
}
