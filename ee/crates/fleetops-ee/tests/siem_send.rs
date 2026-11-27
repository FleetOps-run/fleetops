use axum::{extract::State, http::HeaderMap, http::StatusCode, routing::post, Router};
use fleetops_ee::siem::{
    model::{Sink, SinkKind, SinkSecrets, SinkSettings, SyslogTransport},
    send::{syslog_line, LiveSender, Sender},
};
use fleetops_store::AuditEntry;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;

fn row(id: i64, detail: serde_json::Value) -> AuditEntry {
    AuditEntry {
        id,
        ts: 1_790_000_000 + id,
        user_id: Some(1),
        username: Some("admin".into()),
        token_name: None,
        environment_id: None,
        action: "container.stop".into(),
        target_type: Some("container".into()),
        target_id: Some("web".into()),
        result: "success".into(),
        detail: Some(detail),
    }
}

fn sink(kind: SinkKind, settings: SinkSettings) -> Sink {
    Sink {
        id: 1,
        name: "s".into(),
        kind,
        enabled: true,
        settings,
        cursor: 0,
        gap_rows: 0,
        last_sent_at: None,
        last_error: None,
        last_error_at: None,
    }
}

fn syslog(port: u16, transport: SyslogTransport) -> Sink {
    sink(
        SinkKind::Syslog,
        SinkSettings {
            host: Some("127.0.0.1".into()),
            port: Some(port),
            transport: Some(transport),
            ..Default::default()
        },
    )
}

/// Splits an octet-counted stream into messages, checking each count.
fn frames(mut buf: &[u8]) -> Vec<String> {
    let mut out = vec![];
    while !buf.is_empty() {
        let sp = buf
            .iter()
            .position(|b| *b == b' ')
            .expect("a length prefix");
        let n: usize = std::str::from_utf8(&buf[..sp]).unwrap().parse().unwrap();
        let msg = &buf[sp + 1..sp + 1 + n];
        out.push(String::from_utf8(msg.to_vec()).unwrap());
        buf = &buf[sp + 1 + n..];
    }
    out
}

#[tokio::test]
async fn tcp_frames_by_octet_count() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let got = tokio::spawn(async move {
        let (mut c, _) = listener.accept().await.unwrap();
        let mut buf = vec![];
        c.read_to_end(&mut buf).await.unwrap();
        buf
    });
    let rows = vec![
        row(1, json!({"cmd": "line1\nline2 é \"q\""})),
        row(2, json!({})),
    ];
    LiveSender::default()
        .send(
            &syslog(port, SyslogTransport::Tcp),
            &SinkSecrets::default(),
            &rows,
        )
        .await
        .unwrap();
    let buf = got.await.unwrap();
    let msgs = frames(&buf);
    assert_eq!(msgs, vec![syslog_line(&rows[0]), syslog_line(&rows[1])]);
}

#[tokio::test]
async fn udp_sends_one_datagram_per_row() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let rows = vec![row(1, json!({})), row(2, json!({}))];
    LiveSender::default()
        .send(
            &syslog(port, SyslogTransport::Udp),
            &SinkSecrets::default(),
            &rows,
        )
        .await
        .unwrap();
    let mut buf = [0u8; 65_536];
    for r in &rows {
        let n = sock.recv(&mut buf).await.unwrap();
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), syslog_line(r));
    }
}

type Seen = Arc<Mutex<Vec<(HeaderMap, String)>>>;

/// A local HTTP server answering `status` and recording each request.
async fn server(status: StatusCode) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let app =
        Router::new()
            .route(
                "/secret/path",
                post(
                    |State((seen, status)): State<(Seen, StatusCode)>,
                     h: HeaderMap,
                     body: String| async move {
                        seen.lock().unwrap().push((h, body));
                        status
                    },
                ),
            )
            .with_state((seen.clone(), status));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (format!("http://{addr}/secret/path?key=q"), seen)
}

#[tokio::test]
async fn hec_sends_token_and_one_event_per_line() {
    let (url, seen) = server(StatusCode::OK).await;
    let s = sink(SinkKind::SplunkHec, SinkSettings::default());
    let sec = SinkSecrets {
        url: Some(url),
        token: Some("t0ken".into()),
        headers: vec![],
    };
    let rows = vec![row(1, json!({})), row(2, json!({}))];
    LiveSender::default().send(&s, &sec, &rows).await.unwrap();
    let seen = seen.lock().unwrap();
    let (h, body) = &seen[0];
    assert_eq!(h["authorization"], "Splunk t0ken");
    let lines: Vec<serde_json::Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["sourcetype"], "fleetops:audit");
    assert_eq!(lines[0]["time"], 1_790_000_001);
    assert_eq!(lines[1]["event"]["id"], 2);
    assert_eq!(lines[1]["event"]["source"], "fleetops");
}

#[tokio::test]
async fn hec_failure_names_only_the_host() {
    let (url, _) = server(StatusCode::FORBIDDEN).await;
    let s = sink(SinkKind::SplunkHec, SinkSettings::default());
    let sec = SinkSecrets {
        url: Some(url),
        token: Some("t0ken".into()),
        headers: vec![],
    };
    let e = LiveSender::default()
        .send(&s, &sec, &[row(1, json!({}))])
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("127.0.0.1"), "{e}");
    assert!(e.contains("403"), "{e}");
    for secret in ["t0ken", "secret/path", "key=q"] {
        assert!(!e.contains(secret), "{e} leaks {secret}");
    }
}

#[tokio::test]
async fn http_sends_a_json_array_with_custom_headers() {
    let (url, seen) = server(StatusCode::ACCEPTED).await;
    let s = sink(
        SinkKind::Http,
        SinkSettings {
            header_names: vec!["DD-API-KEY".into()],
            ..Default::default()
        },
    );
    let sec = SinkSecrets {
        url: Some(url),
        token: None,
        headers: vec![("DD-API-KEY".into(), "k3y".into())],
    };
    LiveSender::default()
        .send(&s, &sec, &[row(1, json!({})), row(2, json!({}))])
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    let (h, body) = &seen[0];
    assert_eq!(h["dd-api-key"], "k3y");
    assert_eq!(h["content-type"], "application/json");
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);
    assert_eq!(v[0]["source"], "fleetops");
}

#[tokio::test]
async fn unreachable_syslog_is_an_error() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let e = LiveSender::default()
        .send(
            &syslog(port, SyslogTransport::Tcp),
            &SinkSecrets::default(),
            &[row(1, json!({}))],
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("127.0.0.1"), "{e}");
}

/// A TLS listener with a self-signed certificate for 127.0.0.1: its CA PEM,
/// port, and what the first client wrote.
async fn tls_receiver() -> (String, u16, tokio::task::JoinHandle<Option<Vec<u8>>>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let got = tokio::spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        let mut s = acceptor.accept(c).await.ok()?;
        let mut buf = vec![];
        let _ = s.read_to_end(&mut buf).await;
        Some(buf)
    });
    (cert.cert.pem(), port, got)
}

#[tokio::test]
async fn tls_trusts_the_pasted_ca() {
    let (ca, port, got) = tls_receiver().await;
    let mut s = syslog(port, SyslogTransport::Tls);
    s.settings.ca_pem = Some(ca);
    let rows = vec![row(1, json!({}))];
    LiveSender::default()
        .send(&s, &SinkSecrets::default(), &rows)
        .await
        .unwrap();
    let buf = got.await.unwrap().expect("a TLS session");
    assert_eq!(frames(&buf), vec![syslog_line(&rows[0])]);
}

#[tokio::test]
async fn tls_refuses_an_unknown_certificate() {
    let (_, port, _) = tls_receiver().await;
    let e = LiveSender::default()
        .send(
            &syslog(port, SyslogTransport::Tls),
            &SinkSecrets::default(),
            &[row(1, json!({}))],
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("TLS handshake"), "{e}");
}

#[tokio::test]
async fn oversized_rows_are_truncated_for_syslog() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let big = row(1, json!({"blob": "x".repeat(100_000)}));
    LiveSender::default()
        .send(
            &syslog(port, SyslogTransport::Udp),
            &SinkSecrets::default(),
            &[big],
        )
        .await
        .unwrap();
    let mut buf = vec![0u8; 65_536];
    let n = sock.recv(&mut buf).await.unwrap();
    let msg = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(n <= 8192, "{n} bytes");
    assert!(msg.contains("\"truncated\":true"), "{msg}");
    assert!(msg.contains("\"action\":\"container.stop\""), "{msg}");
}

#[tokio::test]
async fn secrets_are_scrubbed_before_the_error_is_cut() {
    let token = "t0ken-secret-value";
    let app = Router::new().route(
        "/in",
        post(move || async move {
            (
                StatusCode::BAD_REQUEST,
                format!("{}{token}", "x".repeat(290)),
            )
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let s = sink(SinkKind::SplunkHec, SinkSettings::default());
    let sec = SinkSecrets {
        token: Some(token.into()),
        url: Some(format!("http://{addr}/in")),
        headers: vec![],
    };
    let e = LiveSender::default()
        .send(&s, &sec, &[row(1, json!({}))])
        .await
        .unwrap_err()
        .to_string();
    assert!(!e.contains("t0ken-s"), "{e}");
}
