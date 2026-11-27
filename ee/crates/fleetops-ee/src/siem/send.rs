//! Delivering audit rows: RFC 5424 syslog (UDP, TCP, TLS), Splunk HEC,
//! and a JSON array over HTTPS. Errors name only the receiver's host.

use super::model::{Sink, SinkKind, SinkSecrets, SyslogTransport};
use crate::notify::send::describe;
use async_trait::async_trait;
use fleetops_core::{Error, Result};
use fleetops_store::AuditEntry;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

pub const TIMEOUT: Duration = Duration::from_secs(10);
/// syslog facility local0.
const FACILITY: u8 = 16;

#[async_trait]
pub trait Sender: Send + Sync {
    /// Delivers `rows` in order; Ok only when the receiver took them all.
    async fn send(&self, sink: &Sink, secrets: &SinkSecrets, rows: &[AuditEntry]) -> Result<()>;
}

/// The most a syslog message may be: what rsyslog and syslog-ng accept by
/// default, and well inside one UDP datagram.
pub const SYSLOG_MAX: usize = 8192;
/// The most one row may be in an HTTP or HEC batch.
pub const HTTP_ROW_MAX: usize = 64 * 1024;

/// A row as receivers get it: the API's audit entry, tagged with its source.
pub fn row_json(e: &AuditEntry) -> Value {
    let mut v = serde_json::to_value(e).expect("audit entry serialises");
    v["source"] = json!("fleetops");
    v
}

/// [`row_json`], with `detail` replaced by a marker when the row would pass
/// `max` bytes: a receiver that refuses big messages would otherwise refuse
/// the same row forever and hold up every row after it.
pub fn row_json_capped(e: &AuditEntry, max: usize) -> Value {
    let v = row_json(e);
    let len = v.to_string().len();
    if len <= max {
        return v;
    }
    let mut v = v;
    v["detail"] = json!({"truncated": true, "bytes": len});
    v
}

/// RFC 5424 MSGID: at most 32 safe ASCII characters.
fn msgid(action: &str) -> String {
    let id: String = action
        .chars()
        .take(32)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if id.is_empty() {
        "-".into()
    } else {
        id
    }
}

/// One RFC 5424 message, without transport framing.
pub fn syslog_line(e: &AuditEntry) -> String {
    let severity = if e.result == "success" { 5 } else { 4 };
    let ts = jiff::Timestamp::from_second(e.ts)
        .map(|t| t.to_string())
        .unwrap_or_else(|_| "-".into());
    format!(
        "<{}>1 {ts} fleetops fleetops - {} - {}",
        FACILITY * 8 + severity,
        msgid(&e.action),
        // Leave room for the header before the JSON.
        row_json_capped(e, SYSLOG_MAX - 128)
    )
}

/// Splunk HEC: one event object per line.
pub fn hec_body(rows: &[AuditEntry]) -> String {
    rows.iter()
        .map(|e| {
            json!({"time": e.ts, "host": "fleetops", "sourcetype": "fleetops:audit", "event": row_json_capped(e, HTTP_ROW_MAX)})
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn http_body(rows: &[AuditEntry]) -> Value {
    Value::Array(
        rows.iter()
            .map(|e| row_json_capped(e, HTTP_ROW_MAX))
            .collect(),
    )
}

/// `msg` with every secret value replaced.
fn scrub(mut msg: String, secrets: &SinkSecrets) -> String {
    let values = secrets
        .token
        .iter()
        .chain(secrets.headers.iter().map(|h| &h.1));
    for v in values.filter(|v| v.len() >= 3) {
        msg = msg.replace(v.as_str(), "…");
    }
    msg
}

fn upstream(message: String) -> Error {
    Error::Upstream {
        status: 502,
        message,
    }
}

pub struct LiveSender {
    http: reqwest::Client,
}

impl Default for LiveSender {
    fn default() -> Self {
        LiveSender {
            http: reqwest::Client::builder()
                .timeout(TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("an HTTP client"),
        }
    }
}

impl LiveSender {
    async fn post(
        &self,
        url: &str,
        content_type: &str,
        body: Vec<u8>,
        headers: &[(String, String)],
        secrets: &SinkSecrets,
    ) -> Result<()> {
        let mut req = self
            .http
            .post(url)
            .header("content-type", content_type)
            .header("user-agent", "FleetOps");
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let res = req.body(body).send().await.map_err(|e| {
            upstream(scrub(
                describe("could not reach", url, &e.without_url().to_string()),
                secrets,
            ))
        })?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        // Remove secrets before cutting, so no partial secret survives the cut.
        let text = scrub(res.text().await.unwrap_or_default(), secrets);
        let text: String = text.chars().take(300).collect();
        Err(upstream(scrub(
            describe(&format!("answered {}", status.as_u16()), url, text.trim()),
            secrets,
        )))
    }

    async fn syslog(&self, sink: &Sink, rows: &[AuditEntry]) -> Result<()> {
        let set = &sink.settings;
        let host = set.host.as_deref().unwrap_or_default();
        let port = set.port.unwrap_or(514);
        let fail = |what: &str, e: &dyn std::fmt::Display| {
            upstream(format!("{what} ({host}:{port}): {e}"))
        };
        match set.transport.unwrap_or(SyslogTransport::Udp) {
            SyslogTransport::Udp => {
                let addr = tokio::net::lookup_host((host, port))
                    .await
                    .map_err(|e| fail("could not resolve", &e))?
                    .next()
                    .ok_or_else(|| fail("could not resolve", &"no address"))?;
                let local = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let sock = tokio::net::UdpSocket::bind(local)
                    .await
                    .map_err(|e| fail("could not open a socket", &e))?;
                for e in rows {
                    sock.send_to(syslog_line(e).as_bytes(), addr)
                        .await
                        .map_err(|e| fail("could not send", &e))?;
                }
                Ok(())
            }
            SyslogTransport::Tcp => {
                let stream =
                    tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect((host, port)))
                        .await
                        .map_err(|_| fail("could not connect", &"timed out"))?
                        .map_err(|e| fail("could not connect", &e))?;
                write_frames(stream, rows)
                    .await
                    .map_err(|e| fail("could not send", &e))
            }
            SyslogTransport::Tls => {
                let config =
                    tls_config(set.ca_pem.as_deref()).map_err(|e| fail("TLS setup", &e))?;
                let name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|e| fail("TLS setup", &e))?;
                let tcp =
                    tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect((host, port)))
                        .await
                        .map_err(|_| fail("could not connect", &"timed out"))?
                        .map_err(|e| fail("could not connect", &e))?;
                let tls = tokio::time::timeout(
                    TIMEOUT,
                    tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
                )
                .await
                .map_err(|_| fail("TLS handshake", &"timed out"))?
                .map_err(|e| fail("TLS handshake", &e))?;
                write_frames(tls, rows)
                    .await
                    .map_err(|e| fail("could not send", &e))
            }
        }
    }
}

/// Octet-counting framing (RFC 6587 §3.4.1): `<len> <message>`.
async fn write_frames<W: tokio::io::AsyncWrite + Unpin>(
    mut w: W,
    rows: &[AuditEntry],
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    for e in rows {
        let line = syslog_line(e);
        buf.extend_from_slice(format!("{} ", line.len()).as_bytes());
        buf.extend_from_slice(line.as_bytes());
    }
    tokio::time::timeout(TIMEOUT, async {
        w.write_all(&buf).await?;
        w.flush().await?;
        w.shutdown().await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"))?
}

fn tls_config(ca_pem: Option<&str>) -> std::result::Result<rustls::ClientConfig, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|e| format!("the CA certificate: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("the CA certificate: {e}"))?;
        }
    }
    // Name the provider: nothing guarantees a process default is installed.
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

#[async_trait]
impl Sender for LiveSender {
    async fn send(&self, sink: &Sink, secrets: &SinkSecrets, rows: &[AuditEntry]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let url = secrets.url.as_deref().unwrap_or_default();
        match sink.kind {
            SinkKind::Syslog => self.syslog(sink, rows).await,
            SinkKind::SplunkHec => {
                let token = secrets.token.as_deref().unwrap_or_default();
                let auth = [("authorization".to_string(), format!("Splunk {token}"))];
                self.post(
                    url,
                    "application/json",
                    hec_body(rows).into_bytes(),
                    &auth,
                    secrets,
                )
                .await
            }
            SinkKind::Http => {
                let body = serde_json::to_vec(&http_body(rows))
                    .map_err(|e| Error::Internal(e.to_string()))?;
                self.post(url, "application/json", body, &secrets.headers, secrets)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(result: &str, action: &str) -> AuditEntry {
        AuditEntry {
            id: 1,
            ts: 1_790_000_000,
            user_id: None,
            username: None,
            environment_id: None,
            action: action.into(),
            target_type: None,
            target_id: None,
            result: result.into(),
            detail: None,
        }
    }

    #[test]
    fn syslog_line_shape() {
        let ok = syslog_line(&row("success", "container.stop"));
        assert!(ok.starts_with("<133>1 2026-"), "{ok}");
        assert!(
            ok.contains(" fleetops fleetops - container.stop - {"),
            "{ok}"
        );
        assert!(ok.ends_with(&row_json(&row("success", "container.stop")).to_string()));
        assert!(syslog_line(&row("failure", "x")).starts_with("<132>1 "));
    }

    #[test]
    fn msgid_is_safe() {
        assert_eq!(msgid("a b\n\"c"), "a_b__c");
        assert_eq!(msgid(&"x".repeat(40)).len(), 32);
        assert_eq!(msgid(""), "-");
    }

    #[test]
    fn hec_body_is_one_event_per_line() {
        let b = hec_body(&[row("success", "a"), row("success", "b")]);
        assert_eq!(b.lines().count(), 2);
        let v: Value = serde_json::from_str(b.lines().next().unwrap()).unwrap();
        assert_eq!(v["event"]["source"], "fleetops");
    }

    #[test]
    fn http_body_is_an_array() {
        let v = http_body(&[row("success", "a")]);
        assert_eq!(v[0]["source"], "fleetops");
    }

    #[test]
    fn scrub_removes_secrets() {
        let s = SinkSecrets {
            url: None,
            token: Some("t0ken".into()),
            headers: vec![("K".into(), "k3y".into())],
        };
        assert_eq!(scrub("bad t0ken k3y".into(), &s), "bad … …");
    }
}
