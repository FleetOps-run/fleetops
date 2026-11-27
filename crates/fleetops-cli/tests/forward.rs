use axum::{
    extract::{ws::Message, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use fleetops_cli::forward::{run, ForwardArgs};
use futures_util::StreamExt;
use serde_json::json;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
};

#[derive(Clone, Default)]
struct Mock {
    expired: bool,
    /// Streams to refuse before accepting, and with what status (503 if unset).
    refuse_first: Arc<AtomicUsize>,
    refuse_status: Option<StatusCode>,
    /// Streams open now, and the most at once.
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    /// expires_at in this machine's past, expires_in an hour.
    skewed: bool,
    headers: Arc<Mutex<Vec<String>>>,
}

async fn redeem(State(m): State<Mock>, Json(b): Json<serde_json::Value>) -> Response {
    if m.expired || b["ticket"] != "fpt_test" {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code": "unauthorized",
            "message": "this port-forward link has expired; create a new one in FleetOps"})),
        )
            .into_response();
    }
    let expires_at: i64 = if m.skewed { 1 } else { 4_102_444_800 };
    Json(
        json!({"credential": "fpc_test", "env": "prod", "namespace": "db", "pod": "postgres-0",
        "port": 5432, "expires_at": expires_at, "expires_in": 3600}),
    )
    .into_response()
}

async fn stream(State(m): State<Mock>, h: HeaderMap, ws: WebSocketUpgrade) -> Response {
    m.headers.lock().unwrap().push(
        h.get("x-fleetops-forward")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default(),
    );
    if m.refuse_first.load(Ordering::SeqCst) > 0 {
        m.refuse_first.fetch_sub(1, Ordering::SeqCst);
        return (
            m.refuse_status.unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            "cluster unreachable",
        )
            .into_response();
    }
    ws.on_upgrade(move |mut s| async move {
        let now = m.active.fetch_add(1, Ordering::SeqCst) + 1;
        m.peak.fetch_max(now, Ordering::SeqCst);
        // Hold the stream a moment, so connections overlap.
        tokio::time::sleep(Duration::from_millis(30)).await;
        while let Some(Ok(msg)) = s.next().await {
            if let Message::Binary(b) = msg {
                let mut out = b"pod|".to_vec();
                out.extend_from_slice(&b);
                if s.send(Message::Binary(out.into())).await.is_err() {
                    break;
                }
            }
        }
        m.active.fetch_sub(1, Ordering::SeqCst);
    })
}

async fn mock(m: Mock) -> String {
    let app = Router::new()
        .route("/api/v1/port-forward/redeem", post(redeem))
        .route("/api/v1/port-forward/stream", get(stream))
        .with_state(m);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

fn args(server: String) -> ForwardArgs {
    ForwardArgs {
        server,
        ticket: "fpt_test".into(),
        local: Some(0),
        address: Ipv4Addr::LOCALHOST.into(),
        ca: None,
    }
}

/// Starts `run` and returns the address it listens on.
async fn start(
    a: ForwardArgs,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(fleetops_cli::forward::run_with(
        a,
        async {
            let _ = stop_rx.await;
        },
        Some(ready_tx),
    ));
    let addr = tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    (addr, stop_tx, task)
}

async fn roundtrip(addr: SocketAddr, msg: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; 4 + msg.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf
}

#[tokio::test]
async fn forwards_two_connections() {
    let m = Mock::default();
    let server = mock(m.clone()).await;
    let (addr, stop, task) = start(args(server)).await;
    assert_eq!(roundtrip(addr, b"one").await, b"pod|one");
    assert_eq!(roundtrip(addr, b"two").await, b"pod|two");
    assert!(m.headers.lock().unwrap().iter().all(|h| h == "fpc_test"));
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn expired_link_is_a_clear_error() {
    let server = mock(Mock {
        expired: true,
        ..Default::default()
    })
    .await;
    let e = run(args(server), std::future::pending::<()>())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("create a new one in FleetOps"), "{e}");
}

#[tokio::test]
async fn a_failed_stream_does_not_stop_the_listener() {
    let m = Mock {
        refuse_first: Arc::new(AtomicUsize::new(1)),
        ..Default::default()
    };
    let server = mock(m.clone()).await;
    let (addr, stop, _task) = start(args(server)).await;
    let mut first = TcpStream::connect(addr).await.unwrap();
    let _ = first.write_all(b"x").await;
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(5), first.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "the refused connection is closed");
    assert_eq!(roundtrip(addr, b"ok").await, b"pod|ok");
    let _ = stop.send(());
}

#[test]
fn local_defaults_to_remote_port() {
    assert_eq!(fleetops_cli::forward::local_port(None, 5432), 5432);
    assert_eq!(fleetops_cli::forward::local_port(Some(0), 5432), 0);
    assert_eq!(fleetops_cli::forward::local_port(Some(15432), 5432), 15432);
}

#[tokio::test]
async fn thirty_clients_share_sixteen_streams() {
    let m = Mock::default();
    let server = mock(m.clone()).await;
    let (addr, stop, _task) = start(args(server)).await;
    let clients: Vec<_> = (0..30)
        .map(|i| tokio::spawn(async move { roundtrip(addr, format!("c{i:02}").as_bytes()).await }))
        .collect();
    for (i, c) in clients.into_iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(10), c)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, format!("pod|c{i:02}").into_bytes());
    }
    let peak = m.peak.load(Ordering::SeqCst);
    assert!(peak <= 16, "{peak} streams at once");
    let _ = stop.send(());
}

#[tokio::test]
async fn a_429_is_retried_not_dropped() {
    let m = Mock {
        refuse_first: Arc::new(AtomicUsize::new(2)),
        refuse_status: Some(StatusCode::TOO_MANY_REQUESTS),
        ..Default::default()
    };
    let server = mock(m.clone()).await;
    let (addr, stop, _task) = start(args(server)).await;
    assert_eq!(roundtrip(addr, b"later").await, b"pod|later");
    let _ = stop.send(());
}

#[tokio::test]
async fn expiry_comes_from_the_server_not_the_local_clock() {
    // A server whose expires_at is in this machine's past (clocks apart),
    // but whose expires_in says an hour: the forward must keep running.
    let m = Mock {
        skewed: true,
        ..Default::default()
    };
    let server = mock(m).await;
    let (addr, stop, task) = start(args(server)).await;
    assert_eq!(roundtrip(addr, b"skew").await, b"pod|skew");
    assert!(!task.is_finished());
    let _ = stop.send(());
}

#[tokio::test]
async fn stopping_closes_open_connections() {
    let m = Mock::default();
    let server = mock(m).await;
    let (addr, stop, task) = start(args(server)).await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"held").await.unwrap();
    let mut buf = vec![0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("still open after stop")
        .unwrap_or(0);
    assert_eq!(n, 0);
}

#[test]
fn the_text_frame_is_the_reason() {
    use fleetops_cli::forward::close_reason;
    assert_eq!(
        close_reason(Some("the full story".into()), Some("the full st".into())),
        Some("the full story".into())
    );
    assert_eq!(
        close_reason(None, Some("short".into())),
        Some("short".into())
    );
    assert_eq!(close_reason(None, None), None);
}
