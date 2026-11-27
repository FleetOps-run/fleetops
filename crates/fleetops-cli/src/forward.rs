//! `fleetops-cli forward`: redeem a port-forward link, listen locally, and
//! carry each local connection to the pod over its own websocket.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Semaphore},
};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Error as WsError},
    Connector,
};

/// What the server allows at once per link; more connections wait.
const MAX_STREAMS: usize = 16;
const HEADER: &str = "x-fleetops-forward";

pub struct ForwardArgs {
    /// FleetOps's address, e.g. `https://fleet.example.com`.
    pub server: String,
    /// The `fpt_…` link from the Port-forward dialog.
    pub ticket: String,
    /// Local port; `None` uses the pod's port, `0` picks a free one.
    pub local: Option<u16>,
    pub address: IpAddr,
    /// A PEM CA to trust beside the public roots (self-signed servers).
    pub ca: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Redeemed {
    credential: String,
    env: String,
    namespace: String,
    pod: String,
    port: u16,
    expires_at: i64,
}

#[derive(Deserialize)]
struct ApiError {
    message: String,
}

pub fn local_port(local: Option<u16>, remote: u16) -> u16 {
    local.unwrap_or(remote)
}

fn tls(ca: Option<&PathBuf>) -> Result<rustls::ClientConfig> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca {
        for cert in CertificateDer::pem_file_iter(path)
            .with_context(|| format!("reading {}", path.display()))?
        {
            roots.add(cert.with_context(|| format!("reading {}", path.display()))?)?;
        }
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn lasts(secs: i64) -> String {
    let secs = secs.max(0);
    format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
}

fn warn_plain_http(base: &str) {
    let Some(rest) = base.strip_prefix("http://") else {
        return;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    let loopback = host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        eprintln!("warning: {base} is plain HTTP; the link and your traffic are not encrypted");
    }
}

/// Runs until `shutdown` resolves or the session ends.
pub async fn run(args: ForwardArgs, shutdown: impl Future<Output = ()>) -> Result<()> {
    run_with(args, shutdown, None).await
}

/// [`run`], telling `ready` the local address once it listens.
pub async fn run_with(
    args: ForwardArgs,
    shutdown: impl Future<Output = ()>,
    ready: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let base = args.server.trim_end_matches('/').to_string();
    if !base.starts_with("https://") && !base.starts_with("http://") {
        bail!("--server must start with https:// or http://");
    }
    warn_plain_http(&base);
    let tls = Arc::new(tls(args.ca.as_ref())?);
    let http = reqwest::Client::builder()
        .use_preconfigured_tls((*tls).clone())
        .timeout(Duration::from_secs(20))
        .build()?;
    let res = http
        .post(format!("{base}/api/v1/port-forward/redeem"))
        .json(&serde_json::json!({"ticket": args.ticket.trim()}))
        .send()
        .await
        .with_context(|| format!("could not reach {base}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res
            .json::<ApiError>()
            .await
            .map(|e| e.message)
            .unwrap_or_else(|_| format!("the server answered {status}"));
        bail!("{msg}");
    }
    let r: Redeemed = res
        .json()
        .await
        .context("unexpected answer from the server")?;

    let listener = TcpListener::bind((args.address, local_port(args.local, r.port)))
        .await
        .with_context(|| {
            format!(
                "cannot listen on {}:{}",
                args.address,
                local_port(args.local, r.port)
            )
        })?;
    let local = listener.local_addr()?;
    println!(
        "Forwarding {local} -> {}/{}/{}:{} (for {}). Ctrl-C to stop.",
        r.env,
        r.namespace,
        r.pod,
        r.port,
        lasts(r.expires_at - now())
    );
    if let Some(tx) = ready {
        let _ = tx.send(local);
    }

    let ws_url = format!(
        "{}/api/v1/port-forward/stream",
        base.replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1)
    );
    let slots = Arc::new(Semaphore::new(MAX_STREAMS));
    let (fatal_tx, mut fatal) = mpsc::channel::<String>(1);
    let expiry = tokio::time::sleep(Duration::from_secs((r.expires_at - now()).max(0) as u64));
    tokio::pin!(expiry, shutdown);
    let cred = Arc::new(r.credential);
    loop {
        // A slot first, then the next connection: past 16, connections wait
        // in the kernel's backlog instead of as open sockets here.
        let slot = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = &mut expiry => bail!("the port-forward session ended; create a new link in FleetOps"),
            Some(msg) = fatal.recv() => bail!("{msg}"),
            slot = slots.clone().acquire_owned() => slot.expect("the semaphore is never closed"),
        };
        let conn = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = &mut expiry => bail!("the port-forward session ended; create a new link in FleetOps"),
            Some(msg) = fatal.recv() => bail!("{msg}"),
            conn = listener.accept() => conn,
        };
        let conn = match conn {
            Ok((c, _)) => c,
            Err(e) => {
                // Out of file descriptors or an aborted handshake: not fatal.
                eprintln!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (url, cred, tls, fatal) = (ws_url.clone(), cred.clone(), tls.clone(), fatal_tx.clone());
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(e) = carry(conn, &url, &cred, tls).await {
                match e {
                    Carry::Fatal(m) => {
                        let _ = fatal.send(m).await;
                    }
                    Carry::Once(m) => eprintln!("connection failed: {m}"),
                }
            }
        });
    }
}

enum Carry {
    /// This connection only.
    Once(String),
    /// The link no longer works at all.
    Fatal(String),
}

/// The server answered `status` with `body`: one connection's error, or
/// the end of the link.
fn refused(status: u16, msg: String) -> Carry {
    match status {
        401 | 403 => Carry::Fatal(msg),
        _ => Carry::Once(msg),
    }
}

async fn connect(
    url: &str,
    cred: &str,
    tls: Arc<rustls::ClientConfig>,
) -> std::result::Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    Carry,
> {
    // A slot freed here may not be free on the server yet: retry a 429.
    for attempt in 1..=5u64 {
        let mut req = url
            .into_client_request()
            .map_err(|e| Carry::Fatal(e.to_string()))?;
        req.headers_mut().insert(
            HEADER,
            cred.parse()
                .map_err(|_| Carry::Fatal("bad credential".into()))?,
        );
        match tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            Some(Connector::Rustls(tls.clone())),
        )
        .await
        {
            Ok((ws, _)) => return Ok(ws),
            Err(WsError::Http(resp)) => {
                let status = resp.status().as_u16();
                if status == 429 && attempt < 5 {
                    tokio::time::sleep(Duration::from_millis(100 * attempt)).await;
                    continue;
                }
                let body = resp
                    .body()
                    .as_ref()
                    .and_then(|b| {
                        serde_json::from_slice::<ApiError>(b)
                            .ok()
                            .map(|e| e.message)
                    })
                    .or_else(|| {
                        resp.body()
                            .as_ref()
                            .map(|b| String::from_utf8_lossy(b).into_owned())
                    })
                    .unwrap_or_default();
                let msg = if body.is_empty() {
                    format!("the server answered {status}")
                } else {
                    body
                };
                return Err(refused(status, msg));
            }
            Err(e) => return Err(Carry::Once(anyhow!(e).to_string())),
        }
    }
    unreachable!("the last attempt returns")
}

/// Carries one local connection. The server's close reason (the pod side
/// failed, access was removed, the session ended) is printed.
async fn carry(
    conn: TcpStream,
    url: &str,
    cred: &str,
    tls: Arc<rustls::ClientConfig>,
) -> std::result::Result<(), Carry> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::{protocol::frame::coding::CloseCode, Message};
    let ws = connect(url, cred, tls).await?;
    let (mut tx, mut rx) = ws.split();
    let (mut local_r, mut local_w) = conn.into_split();
    let mut buf = vec![0u8; 32 * 1024];
    let mut local_done = false;
    loop {
        tokio::select! {
            n = local_r.read(&mut buf), if !local_done => match n {
                Ok(0) | Err(_) => {
                    // The local side hung up (or only shut its sending side:
                    // that can't be told apart, so half-close is not kept,
                    // as with kubectl port-forward). Close the stream and let
                    // the server's Close end the loop.
                    local_done = true;
                    let _ = tx.send(Message::Close(None)).await;
                }
                Ok(n) => {
                    if tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        return Ok(());
                    }
                }
            },
            m = rx.next() => match m {
                Some(Ok(Message::Binary(b))) => {
                    if local_w.write_all(&b).await.is_err() {
                        return Ok(());
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    let _ = local_w.shutdown().await;
                    return match frame {
                        Some(f) if f.code != CloseCode::Normal && !f.reason.is_empty() => {
                            let reason = f.reason.to_string();
                            if f.code == CloseCode::Policy {
                                Err(Carry::Fatal(reason))
                            } else {
                                Err(Carry::Once(reason))
                            }
                        }
                        _ => Ok(()),
                    };
                }
                None | Some(Err(_)) => {
                    let _ = local_w.shutdown().await;
                    return Ok(());
                }
                // Pings are answered by the websocket library.
                Some(Ok(_)) => {}
            },
        }
    }
}
