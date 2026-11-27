//! Audit sinks: where the audit log is forwarded.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    /// RFC 5424 syslog over UDP, TCP or TLS.
    Syslog,
    /// Splunk HTTP Event Collector.
    SplunkHec,
    /// A JSON array POSTed to any HTTPS endpoint.
    Http,
}

impl SinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SinkKind::Syslog => "syslog",
            SinkKind::SplunkHec => "splunk_hec",
            SinkKind::Http => "http",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [SinkKind::Syslog, SinkKind::SplunkHec, SinkKind::Http]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
}

/// A sink's settings, without secrets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SinkSettings {
    /// Syslog.
    pub host: Option<String>,
    pub port: Option<u16>,
    pub transport: Option<SyslogTransport>,
    /// Syslog over TLS: an extra CA to trust (PEM), beside the public roots.
    pub ca_pem: Option<String>,
    /// HTTP: the names of the headers sent; their values are secrets.
    #[serde(default)]
    pub header_names: Vec<String>,
}

/// A sink's secrets, sealed at rest and never returned.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SinkSecrets {
    /// Splunk HEC and HTTP: collectors often carry a token in the URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Splunk HEC token.
    pub token: Option<String>,
    /// HTTP headers, as `(name, value)`.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sink {
    pub id: i64,
    pub name: String,
    pub kind: SinkKind,
    pub enabled: bool,
    pub settings: SinkSettings,
    /// The last audit id this sink accepted.
    pub cursor: i64,
    pub gap_rows: i64,
    pub last_sent_at: Option<i64>,
    pub last_error: Option<String>,
    pub last_error_at: Option<i64>,
}
