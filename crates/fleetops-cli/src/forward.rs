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
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = &mut expiry => bail!("the port-forward session ended; create a new link in FleetOps"),
            Some(msg) = fatal.recv() => bail!("{msg}"),
            conn = listener.accept() => {
                let (conn, _) = conn?;
                let (url, cred, tls, slots, fatal) =
                    (ws_url.clone(), cred.clone(), tls.clone(), slots.clone(), fatal_tx.clone());
                tokio::spawn(async move {
                    let Ok(_slot) = slots.acquire_owned().await else { return };
                    if let Err(e) = carry(conn, &url, &cred, tls).await {
                        match e {
                            Carry::Fatal(m) => { let _ = fatal.send(m).await; }
                            Carry::Once(m) => eprintln!("connection failed: {m}"),
                        }
                    }
                });
            }
        }
    }
}

enum Carry {
    /// This connection only.
    Once(String),
    /// The link no longer works at all.
    Fatal(String),
}

async fn carry(
    mut conn: TcpStream,
    url: &str,
    cred: &str,
    tls: Arc<rustls::ClientConfig>,
) -> std::result::Result<(), Carry> {
    let mut req = url
        .into_client_request()
        .map_err(|e| Carry::Fatal(e.to_string()))?;
    req.headers_mut().insert(
        HEADER,
        cred.parse()
            .map_err(|_| Carry::Fatal("bad credential".into()))?,
    );
    let ws = match tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        false,
        Some(Connector::Rustls(tls)),
    )
    .await
    {
        Ok((ws, _)) => ws,
        Err(WsError::Http(resp)) => {
            let status = resp.status();
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
            return Err(match status.as_u16() {
                401 | 403 => Carry::Fatal(msg),
                _ => Carry::Once(msg),
            });
        }
        Err(e) => return Err(Carry::Once(anyhow!(e).to_string())),
    };
    let mut io = crate::ws_io::io(ws);
    let _ = tokio::io::copy_bidirectional(&mut conn, &mut io).await;
    Ok(())
}
