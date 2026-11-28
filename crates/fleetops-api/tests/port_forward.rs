mod common;

use common::*;
use fleetops_core::kube::KubeKind;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::{net::SocketAddr, time::Duration};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

const MINT: &str = "/api/v1/envs/k/k8s/pods/apps/postgres-0/port-forward";
const REDEEM: &str = "/api/v1/port-forward/redeem";

async fn pf_app(config: fleetops_api::ApiConfig) -> (TestApp, Session, Session) {
    let t = app_with(config).await;
    let admin = t.setup_admin().await;
    t.add_kube_env(&admin, "k").await;
    t.fake.kube.object(KubeKind::Pods, "apps", "postgres-0");
    t.create_user(&admin, "bob", "bob-password", "user").await;
    t.grant("bob", "k", "operator", Some(&["apps"])).await;
    let bob = session_from(&t.login("bob", "bob-password").await);
    (t, admin, bob)
}

async fn mint(t: &TestApp, s: &Session, port: u16) -> Resp {
    t.send(req("POST", MINT, Some(json!({"port": port})), Some(s)))
        .await
}

async fn ticket(t: &TestApp, s: &Session) -> String {
    let r = mint(t, s, 5432).await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    r.json["ticket"].as_str().unwrap().to_string()
}

async fn redeem(t: &TestApp, ticket: &str) -> Resp {
    t.send(req("POST", REDEEM, Some(json!({"ticket": ticket})), None))
        .await
}

async fn credential(t: &TestApp, s: &Session) -> String {
    let tk = ticket(t, s).await;
    let r = redeem(t, &tk).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    r.json["credential"].as_str().unwrap().to_string()
}

type Stream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn stream(
    addr: SocketAddr,
    credential: Option<&str>,
    cookie: Option<&str>,
) -> Result<Stream, u16> {
    let mut r = format!("ws://{addr}/api/v1/port-forward/stream")
        .into_client_request()
        .unwrap();
    if let Some(c) = credential {
        r.headers_mut()
            .insert("x-fleetops-forward", c.parse().unwrap());
    }
    if let Some(c) = cookie {
        r.headers_mut().insert("cookie", c.parse().unwrap());
    }
    match tokio_tungstenite::connect_async(r).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
        Err(e) => panic!("{e}"),
    }
}

/// Sends `msg` and reads binary frames until `want` bytes arrived.
async fn echo(ws: &mut Stream, msg: &str, want: usize) -> String {
    ws.send(Message::Binary(msg.as_bytes().to_vec().into()))
        .await
        .unwrap();
    let mut got = Vec::new();
    while got.len() < want {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => got.extend_from_slice(&b),
            Ok(Some(Ok(_))) => {}
            other => panic!("stream ended: {other:?}"),
        }
    }
    String::from_utf8(got).unwrap()
}

#[tokio::test]
async fn mint_needs_shell() {
    let (t, admin, bob) = pf_app(Default::default()).await;
    t.create_user(&admin, "vic", "vic-password", "user").await;
    t.grant("vic", "k", "viewer", None).await;
    let vic = session_from(&t.login("vic", "vic-password").await);
    let r = mint(&t, &vic, 5432).await;
    assert_eq!(r.status, 403, "{:?}", r.json);
    let denied = t.store.list_audit(20, None).await.unwrap();
    assert!(denied.iter().any(|e| e.action == "access.denied"
        && e.detail
            .as_ref()
            .is_some_and(|d| d["permission"].as_str().unwrap_or("").contains("pods"))));
    let r = mint(&t, &bob, 5432).await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    assert!(r.json["ticket"].as_str().unwrap().starts_with("fpt_"));
    assert!(r.json["expires_at"].as_i64().is_some());
    // Outside bob's namespaces.
    t.fake.kube.object(KubeKind::Pods, "other", "db");
    let r = t
        .send(req(
            "POST",
            "/api/v1/envs/k/k8s/pods/other/db/port-forward",
            Some(json!({"port": 1})),
            Some(&bob),
        ))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
}

#[tokio::test]
async fn port_must_be_valid() {
    let (t, _, bob) = pf_app(Default::default()).await;
    for bad in [json!({"port": 0}), json!({"port": 70000}), json!({})] {
        let r = t
            .send(req("POST", MINT, Some(bad.clone()), Some(&bob)))
            .await;
        assert!(
            r.status == 400 || r.status == 422,
            "{bad}: {} {:?}",
            r.status,
            r.json
        );
    }
}

#[tokio::test]
async fn redeem_once_and_audit_without_secrets() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let tk = ticket(&t, &bob).await;
    let r = redeem(&t, &tk).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert!(r.json["credential"].as_str().unwrap().starts_with("fpc_"));
    assert_eq!(
        (
            r.json["env"].as_str(),
            r.json["namespace"].as_str(),
            r.json["pod"].as_str(),
            r.json["port"].as_u64()
        ),
        (Some("k"), Some("apps"), Some("postgres-0"), Some(5432))
    );
    let again = redeem(&t, &tk).await;
    assert_eq!(again.status, 401);
    assert!(again.json["message"]
        .as_str()
        .unwrap()
        .contains("create a new one in FleetOps"));
    let rows = t.store.list_audit(50, None).await.unwrap();
    let row = rows
        .iter()
        .find(|e| e.action == "k8s.port_forward")
        .expect("audited");
    assert_eq!(row.username.as_deref(), Some("bob"));
    assert_eq!(row.target_id.as_deref(), Some("pods/apps/postgres-0"));
    assert_eq!(row.detail.as_ref().unwrap()["port"], 5432);
    let all = serde_json::to_string(&rows).unwrap();
    assert!(!all.contains("fpt_") && !all.contains("fpc_"), "{all}");
}

#[tokio::test]
async fn concurrent_redeem_has_one_winner() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let tk = ticket(&t, &bob).await;
    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let (router, tk) = (t.router.clone(), tk.clone());
            tokio::spawn(async move {
                use tower::ServiceExt;
                let mut r = req("POST", REDEEM, Some(json!({"ticket": tk})), None);
                r.extensions_mut()
                    .insert(axum::extract::ConnectInfo(SocketAddr::from((
                        [127, 0, 0, 1],
                        1,
                    ))));
                router.oneshot(r).await.unwrap().status().as_u16()
            })
        })
        .collect();
    let mut ok = 0;
    for task in tasks {
        if task.await.unwrap() == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn stream_echoes() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let cred = credential(&t, &bob).await;
    let addr = t.serve().await;
    let mut ws = stream(addr, Some(&cred), None).await.unwrap();
    assert_eq!(
        echo(&mut ws, "hello", "postgres-0:5432|hello".len()).await,
        "postgres-0:5432|hello"
    );
}

#[tokio::test]
async fn stream_needs_the_header_and_ignores_cookies() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let addr = t.serve().await;
    assert_eq!(stream(addr, None, Some(&bob.cookie)).await.err(), Some(401));
    assert_eq!(stream(addr, Some("fpc_nope"), None).await.err(), Some(401));
}

#[tokio::test]
async fn stream_rechecks_access() {
    let config = fleetops_api::ApiConfig {
        forward_recheck: Duration::from_millis(100),
        ..Default::default()
    };
    let (t, _, bob) = pf_app(config).await;
    let cred = credential(&t, &bob).await;
    let addr = t.serve().await;
    let mut open = stream(addr, Some(&cred), None).await.unwrap();
    echo(&mut open, "x", "postgres-0:5432|x".len()).await;
    let bob_id = t.store.find_credentials("bob").await.unwrap().unwrap().0.id;
    let env_id = t.store.list_environments().await.unwrap()[0].id;
    t.store.delete_binding(bob_id, env_id).await.unwrap();
    assert_eq!(
        stream(addr, Some(&cred), None).await.err(),
        Some(403),
        "new streams are refused"
    );
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match open.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                _ => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the open stream was not closed");
}

#[tokio::test]
async fn disabled_user_is_refused() {
    let (t, admin, bob) = pf_app(Default::default()).await;
    let cred = credential(&t, &bob).await;
    let bob_id = t.store.find_credentials("bob").await.unwrap().unwrap().0.id;
    let r = t
        .send(req(
            "PATCH",
            &format!("/api/v1/users/{bob_id}"),
            Some(json!({"disabled": true})),
            Some(&admin),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let addr = t.serve().await;
    assert_eq!(stream(addr, Some(&cred), None).await.err(), Some(401));
}

#[tokio::test]
async fn stream_limit() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let cred = credential(&t, &bob).await;
    let addr = t.serve().await;
    let mut open = Vec::new();
    for _ in 0..16 {
        open.push(stream(addr, Some(&cred), None).await.unwrap());
    }
    assert_eq!(stream(addr, Some(&cred), None).await.err(), Some(429));
    drop(open.pop());
    // The slot frees once the server notices the close.
    let mut freed = false;
    for _ in 0..50 {
        if stream(addr, Some(&cred), None).await.is_ok() {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(freed);
}

#[tokio::test]
async fn gone_pod_fails_one_connection() {
    let (t, admin, _) = pf_app(Default::default()).await;
    t.fake.kube.object(KubeKind::Pods, "apps", "gone");
    let r = t
        .send(req(
            "POST",
            "/api/v1/envs/k/k8s/pods/apps/gone/port-forward",
            Some(json!({"port": 80})),
            Some(&admin),
        ))
        .await;
    assert_eq!(r.status, 201);
    let gone = redeem(&t, r.json["ticket"].as_str().unwrap()).await.json["credential"]
        .as_str()
        .unwrap()
        .to_string();
    let addr = t.serve().await;
    // Opened before the upgrade, so the failure is an HTTP answer the CLI prints.
    assert_eq!(stream(addr, Some(&gone), None).await.err(), Some(404));
    let ok = credential(&t, &admin).await;
    let mut ws = stream(addr, Some(&ok), None).await.unwrap();
    echo(&mut ws, "y", "postgres-0:5432|y".len()).await;
}

#[tokio::test]
async fn a_refused_port_closes_with_the_reason() {
    let (t, admin, _) = pf_app(Default::default()).await;
    t.fake.kube.object(KubeKind::Pods, "apps", "refused");
    let r = t
        .send(req(
            "POST",
            "/api/v1/envs/k/k8s/pods/apps/refused/port-forward",
            Some(json!({"port": 81})),
            Some(&admin),
        ))
        .await;
    let cred = redeem(&t, r.json["ticket"].as_str().unwrap()).await.json["credential"]
        .as_str()
        .unwrap()
        .to_string();
    let addr = t.serve().await;
    let mut ws = stream(addr, Some(&cred), None).await.unwrap();
    // The full reason comes as text, then a (capped) close.
    let (mut text, mut closed) = (None, false);
    while let Ok(Some(m)) = tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        match m {
            Ok(Message::Text(t)) => text = Some(t.to_string()),
            Ok(Message::Close(_)) => {
                closed = true;
                break;
            }
            _ => {}
        }
    }
    assert!(closed);
    assert!(
        text.as_deref().unwrap_or("").contains("connection refused"),
        "{text:?}"
    );
}

#[tokio::test]
async fn idle_streams_are_pinged() {
    let config = fleetops_api::ApiConfig {
        forward_ping: Duration::from_millis(100),
        ..Default::default()
    };
    let (t, _, bob) = pf_app(config).await;
    let cred = credential(&t, &bob).await;
    let addr = t.serve().await;
    let mut ws = stream(addr, Some(&cred), None).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("nothing within 3s");
    assert!(matches!(got, Some(Ok(Message::Ping(_)))), "{got:?}");
}

#[tokio::test]
async fn a_renamed_environment_keeps_working() {
    let (t, admin, bob) = pf_app(Default::default()).await;
    let cred = credential(&t, &bob).await;
    let r = t
        .send(req(
            "PATCH",
            "/api/v1/envs/k",
            Some(json!({"name": "k2", "skip_check": true})),
            Some(&admin),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let addr = t.serve().await;
    let mut ws = stream(addr, Some(&cred), None).await.unwrap();
    echo(&mut ws, "z", "postgres-0:5432|z".len()).await;
}

#[tokio::test]
async fn a_deleted_environment_ends_the_link() {
    let (t, admin, bob) = pf_app(Default::default()).await;
    let cred = credential(&t, &bob).await;
    let r = t
        .send(req("DELETE", "/api/v1/envs/k", None, Some(&admin)))
        .await;
    assert!(
        r.status == 200 || r.status == 204,
        "{} {:?}",
        r.status,
        r.json
    );
    let addr = t.serve().await;
    // 403, not 404: fleetops-cli stops instead of retrying for hours.
    assert_eq!(stream(addr, Some(&cred), None).await.err(), Some(403));
}

#[tokio::test]
async fn the_slot_check_comes_before_the_database() {
    let (t, admin, bob) = pf_app(Default::default()).await;
    let cred = credential(&t, &bob).await;
    let addr = t.serve().await;
    let mut open = Vec::new();
    for _ in 0..16 {
        open.push(stream(addr, Some(&cred), None).await.unwrap());
    }
    let bob_id = t.store.find_credentials("bob").await.unwrap().unwrap().0.id;
    t.send(req(
        "PATCH",
        &format!("/api/v1/users/{bob_id}"),
        Some(json!({"disabled": true})),
        Some(&admin),
    ))
    .await;
    // Full: refused before any user or grant lookup.
    assert_eq!(stream(addr, Some(&cred), None).await.err(), Some(429));
}

#[tokio::test]
async fn redeem_reports_expires_in() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let r = redeem(&t, &ticket(&t, &bob).await).await;
    assert_eq!(r.json["expires_in"], 8 * 3600, "{:?}", r.json);
}

#[tokio::test]
async fn redeem_reports_the_server_version() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let r = redeem(&t, &ticket(&t, &bob).await).await;
    assert_eq!(
        r.json["server_version"],
        env!("CARGO_PKG_VERSION"),
        "{:?}",
        r.json
    );
}

#[tokio::test]
async fn redeem_is_rate_limited_per_address() {
    let (t, _, bob) = pf_app(Default::default()).await;
    let mut statuses = Vec::new();
    for _ in 0..12 {
        statuses.push(redeem(&t, "fpt_guess").await.status);
    }
    assert_eq!(&statuses[..10], &[401; 10], "{statuses:?}");
    assert_eq!(statuses[10], 429, "{statuses:?}");
    // A good ticket from the same address is refused too until the window passes.
    let good = ticket(&t, &bob).await;
    assert_eq!(redeem(&t, &good).await.status, 429);
}

#[tokio::test]
async fn the_full_reason_arrives_before_the_close() {
    let (t, admin, _) = pf_app(Default::default()).await;
    t.fake.kube.object(KubeKind::Pods, "apps", "refused");
    let r = t
        .send(req(
            "POST",
            "/api/v1/envs/k/k8s/pods/apps/refused/port-forward",
            Some(json!({"port": 81})),
            Some(&admin),
        ))
        .await;
    let cred = redeem(&t, r.json["ticket"].as_str().unwrap()).await.json["credential"]
        .as_str()
        .unwrap()
        .to_string();
    let addr = t.serve().await;
    let mut ws = stream(addr, Some(&cred), None).await.unwrap();
    let (mut text, mut close) = (None, None);
    while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        match m {
            Message::Text(s) => text = Some(s.to_string()),
            Message::Close(f) => {
                close = f.map(|f| f.reason.to_string());
                break;
            }
            _ => {}
        }
    }
    let text = text.expect("the full reason as text");
    assert!(
        text.len() > 123 && text.ends_with("connection refused"),
        "{text}"
    );
    let close = close.unwrap();
    assert!(close.len() <= 123, "{} bytes", close.len());
}
