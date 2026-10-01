#[cfg(feature = "transport-mailbox")]
use std::time::Duration;

#[cfg(feature = "transport-mailbox")]
use crate::transport::lncmailbox::gbn::GoBackNOptions;

/// HTTP/2 keepalive configuration to prevent idle connection timeouts.
#[cfg(feature = "transport-mailbox")]
#[derive(Clone, Debug)]
pub struct Http2KeepaliveConfig {
    /// Interval between HTTP/2 PING frames. None to disable. Default: disabled.
    pub interval: Option<Duration>,
    /// Timeout for PING acknowledgement. Default: 20s.
    pub timeout: Duration,
    /// Send pings even when no streams are active. Default: true.
    pub while_idle: bool,
}

#[cfg(feature = "transport-mailbox")]
impl Default for Http2KeepaliveConfig {
    fn default() -> Self {
        Self {
            interval: None,
            timeout: Duration::from_secs(20),
            while_idle: true,
        }
    }
}

/// Default Lightning Node Connect mailbox host.
pub const DEFAULT_SERVER_HOST: &str = "mailbox.terminal.lightning.today:443";

/// High-level configuration stored by a [`crate::client::Lnc`] instance.
/// Transport tuning must also be supplied to the selected transport itself.
#[derive(Clone, Debug, Default)]
pub struct LncConfig {
    /// Override the default server host used when the credential store is empty.
    pub server_host: Option<String>,
    /// Reserved namespace; the high-level client does not apply it to sessions.
    pub namespace: Option<String>,
    #[cfg(feature = "transport-mailbox")]
    /// Mailbox tuning; explicitly pass this to
    /// [`crate::transport::mailbox::MailboxTransport::with_mailbox_config`].
    pub mailbox: MailboxConfig,
}

#[cfg(feature = "transport-mailbox")]
#[derive(Clone, Debug)]
pub struct MailboxConfig {
    /// Timeout applied separately to WS/GBN establishment, the Noise handshake,
    /// and the HTTP/2 handshake. Pairing preparation precedes these stages;
    /// callers must enforce a deadline for the whole operation.
    pub session_timeout: Duration,
    /// Delay before retrying websocket send/recv loops after an error.
    pub retry_wait: Duration,
    /// Timeout used when establishing a websocket connection.
    pub ws_connect_timeout: Duration,
    /// Timeout applied to websocket send/init frames.
    pub ws_send_timeout: Duration,
    /// Low-level Go-Back-N tuning knobs.
    pub gbn: GoBackNOptions,
    /// HTTP/2 keepalive configuration to prevent idle connection timeouts.
    pub http2_keepalive: Http2KeepaliveConfig,
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
            http2_keepalive: Http2KeepaliveConfig::default(),
        }
    }
}
