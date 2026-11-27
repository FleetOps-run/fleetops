//! Audit forwarding to a SIEM, and how long the audit log is kept.

pub mod db;
pub mod forwarder;
pub mod model;
pub mod routes;
pub mod send;

use fleetops_core::{Error, Result};
use model::{SinkKind, SinkSecrets, SinkSettings, SyslogTransport};

/// Sinks one server may have.
pub const MAX_SINKS: i64 = 10;
pub const NAME_MAX: usize = 64;

fn invalid(m: impl Into<String>) -> Error {
    Error::Invalid(m.into())
}

/// The trimmed name, or why it is not allowed.
pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > NAME_MAX {
        return Err(invalid(format!(
            "sink name must be 1-{NAME_MAX} characters"
        )));
    }
    Ok(name.to_string())
}

/// `https://`, or `http://` to a loopback address only.
fn check_url(url: Option<&str>) -> Result<()> {
    let url = url.ok_or_else(|| invalid("a URL is required"))?;
    let u = url::Url::parse(url).map_err(|_| invalid("the URL is not valid"))?;
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => return Err(invalid("the URL has no host")),
    };
    match u.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(invalid("the URL must start with https://")),
    }
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Whether `kind` has everything it needs.
pub fn validate(kind: SinkKind, set: &SinkSettings, sec: &SinkSecrets) -> Result<()> {
    match kind {
        SinkKind::Syslog => {
            let host = set.host.as_deref().map(str::trim).unwrap_or("");
            if host.is_empty() || host.len() > 253 || host.contains(['/', ' ']) {
                return Err(invalid("syslog needs a host name or address"));
            }
            if set.port.unwrap_or(0) == 0 {
                return Err(invalid("syslog needs a port"));
            }
            if set.transport.is_none() {
                return Err(invalid("syslog needs a transport: udp, tcp or tls"));
            }
            if let Some(ca) = &set.ca_pem {
                if set.transport != Some(SyslogTransport::Tls) {
                    return Err(invalid("a CA certificate applies only to TLS"));
                }
                if !ca.contains("-----BEGIN CERTIFICATE-----") {
                    return Err(invalid("the CA certificate must be PEM"));
                }
            }
        }
        SinkKind::SplunkHec => {
            check_url(set.url.as_deref())?;
            if sec.token.as_deref().unwrap_or("").trim().is_empty() {
                return Err(invalid("Splunk HEC needs a token"));
            }
        }
        SinkKind::Http => {
            check_url(set.url.as_deref())?;
            for (name, _) in &sec.headers {
                if !is_token(name) {
                    return Err(invalid(format!("'{name}' is not a valid header name")));
                }
            }
        }
    }
    Ok(())
}
