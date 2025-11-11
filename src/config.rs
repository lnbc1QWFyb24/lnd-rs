#[cfg(feature = "transport-mailbox")]
use std::time::Duration;

#[cfg(feature = "transport-mailbox")]
use crate::transport::lncmailbox::gbn::GoBackNOptions;

/// Default Lightning Node Connect mailbox host.
pub const DEFAULT_SERVER_HOST: &str = "mailbox.terminal.lightning.today:443";

/// Global configuration applied to a [`crate::client::Lnc`] instance.
#[derive(Clone, Debug, Default)]
pub struct LncConfig {
    /// Override the default server host used when the credential store is empty.
    pub server_host: Option<String>,
    /// Optional namespace suffix to scope mailbox sessions.
    pub namespace: Option<String>,
    #[cfg(feature = "transport-mailbox")]
    /// Mailbox transport tuning parameters (timeouts, window sizes, etc.).
    pub mailbox: MailboxConfig,
}

#[cfg(feature = "transport-mailbox")]
#[derive(Clone, Debug)]
pub struct MailboxConfig {
    /// Timeout applied to the overall connect sequence (WS + Noise + HTTP/2).
    pub session_timeout: Duration,
    /// Delay before retrying websocket send/recv loops after an error.
    pub retry_wait: Duration,
    /// Timeout used when establishing a websocket connection.
    pub ws_connect_timeout: Duration,
    /// Timeout applied to websocket send/init frames.
    pub ws_send_timeout: Duration,
    /// Low-level Go-Back-N tuning knobs.
    pub gbn: GoBackNOptions,
}

#[cfg(feature = "transport-mailbox")]
impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(30),
            retry_wait: Duration::from_millis(2_000),
            ws_connect_timeout: Duration::from_secs(10),
            ws_send_timeout: Duration::from_millis(1_000),
            gbn: GoBackNOptions::default(),
        }
    }
}
