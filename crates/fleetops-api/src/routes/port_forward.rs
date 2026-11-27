//! Port-forward (port-forward plan): the browser mints a ticket for one pod
//! port, `fleetops-cli` redeems it for a credential, and each local TCP
//! connection is a websocket stream to the pod's port.

use crate::{
    auth::extract::CurrentUser,
    authz::{authorize_env, deny_audited, effective_grant, Need},
    error::ApiError,
    extract::{ApiJson, ApiPath},
    forward::{Target, FORWARD_HEADER},
    routes::kube::{check_name, check_namespace, kube_for, KubeCtx},
    ApiResult, AppState,
};
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fleetops_core::{
    kube::{KubeOps, PortStream},
    now_unix,
    perm::{Permission, Row, Verb},
    Error, Result,
};
use fleetops_store::NewAudit;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

const SHELL: Permission = Permission::new(Row::Pods, Verb::Shell);
const EXPIRED: &str = "this port-forward link has expired; create a new one in FleetOps";

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub struct PodPath {
    pub env: String,
    pub ns: String,
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ForwardBody {
    /// The pod's port, 1-65535.
    pub port: u32,
}

#[derive(Serialize, ToSchema)]
pub struct ForwardTicket {
    /// Single use; give it to `fleetops-cli forward` within five minutes.
    pub ticket: String,
    pub expires_at: i64,
    /// `FLEETOPS_PUBLIC_URL`, when set: the server `fleetops-cli` should use.
    pub server: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct RedeemBody {
    pub ticket: String,
}

#[derive(Serialize, ToSchema)]
pub struct Redeemed {
    /// Send as `x-fleetops-forward` on each stream.
    pub credential: String,
    pub env: String,
    pub namespace: String,
    pub pod: String,
    pub port: u16,
    pub expires_at: i64,
}

#[utoipa::path(post, path = "/envs/{env}/k8s/pods/{ns}/{name}/port-forward", operation_id = "createPortForward",
    tag = "kubernetes", summary = "A single-use link for fleetops-cli to reach a pod's port (needs Shell on pods)",
    params(PodPath), request_body = ForwardBody,
    responses((status = 201, description = "The ticket", body = ForwardTicket)))]
pub async fn mint(
    State(s): State<AppState>,
    cu: CurrentUser,
    ApiPath(p): ApiPath<PodPath>,
    ApiJson(b): ApiJson<ForwardBody>,
) -> ApiResult<(StatusCode, Json<ForwardTicket>)> {
    check_namespace(&p.ns)?;
    check_name(&p.name)?;
    let port = u16::try_from(b.port)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| Error::Invalid("port must be 1-65535".into()))?;
    let KubeCtx { env, grants, .. } = kube_for(&s, &cu, &p.env, Need::Perm(SHELL)).await?;
    deny_audited(
        &s,
        &cu,
        env.id(),
        "pods.port_forward",
        grants.check_ns(SHELL, &p.ns),
    )
    .await?;
    let now = now_unix();
    let ticket = s.forwards.mint(
        Target {
            user_id: cu.user.id,
            env_id: env.id(),
            env: p.env,
            ns: p.ns,
            pod: p.name,
            port,
        },
        now,
    );
    Ok((
        StatusCode::CREATED,
        Json(ForwardTicket {
            ticket,
            expires_at: now + crate::forward::TICKET_SECS,
            server: s.config.public_url.clone(),
        }),
    ))
}

#[utoipa::path(post, path = "/port-forward/redeem", operation_id = "redeemPortForward", tag = "kubernetes",
    summary = "Trade a port-forward ticket for a credential (fleetops-cli)", request_body = RedeemBody,
    responses((status = 200, description = "The credential", body = Redeemed)))]
pub async fn redeem(
    State(s): State<AppState>,
    ApiJson(b): ApiJson<RedeemBody>,
) -> ApiResult<Json<Redeemed>> {
    let (credential, t, expires_at) = s
        .forwards
        .redeem(b.ticket.trim(), now_unix())
        .ok_or_else(|| Error::Unauthorized(EXPIRED.into()))?;
    let target = format!("pods/{}/{}", t.ns, t.pod);
    let entry = NewAudit {
        ts: now_unix(),
        user_id: Some(t.user_id),
        environment_id: Some(t.env_id),
        action: "k8s.port_forward",
        target_type: Some("k8s"),
        target_id: Some(&target),
        result: "success",
        detail: Some(json!({"port": t.port})),
    };
    if let Err(e) = s.store.insert_audit(&entry).await {
        tracing::error!(error = %e, "failed to write audit log");
    }
    Ok(Json(Redeemed {
        credential,
        env: t.env,
        namespace: t.ns,
        pod: t.pod,
        port: t.port,
        expires_at,
    }))
}

/// Whether the credential's user may still reach its pod: the kube ops to
/// use, or why not (401 for the user, 403 for access, 503 for the cluster).
async fn still_allowed(s: &AppState, t: &Target) -> Result<Arc<dyn KubeOps>> {
    let user = match s.store.get_user(t.user_id).await {
        Ok(u) => u,
        Err(Error::NotFound(_)) => return Err(Error::Unauthorized(EXPIRED.into())),
        Err(e) => return Err(e),
    };
    if user.disabled_at.is_some() {
        return Err(Error::Unauthorized(EXPIRED.into()));
    }
    let env = s.envs.get(&t.env)?;
    if env.id() != t.env_id {
        return Err(Error::Forbidden("the environment changed".into()));
    }
    let grants = effective_grant(s, t.user_id, env.id()).await?;
    authorize_env(&grants, &t.env, Need::Perm(SHELL)).map_err(|e| match e {
        Error::NotFound(_) => {
            Error::Forbidden("you no longer have access to this environment".into())
        }
        e => e,
    })?;
    grants.check_ns(SHELL, &t.ns)?;
    env.kube()
        .ok_or_else(|| Error::EnvUnavailable(format!("environment '{}' is unreachable", t.env)))
}

#[utoipa::path(get, path = "/port-forward/stream", operation_id = "portForwardStream", tag = "kubernetes",
    summary = "One TCP connection to the pod (websocket; fleetops-cli only, with x-fleetops-forward)",
    responses((status = 101, description = "Switching protocols; binary frames carry the bytes")))]
pub async fn stream(
    State(s): State<AppState>,
    headers: HeaderMap,
    ws: std::result::Result<
        WebSocketUpgrade,
        axum::extract::ws::rejection::WebSocketUpgradeRejection,
    >,
) -> Response {
    let refuse = |e: Error| ApiError(e).into_response();
    let Some(cred) = headers
        .get(FORWARD_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return refuse(Error::Unauthorized(
            "a port-forward credential is required".into(),
        ));
    };
    let Some((target, expires_at)) = s.forwards.lookup(&cred, now_unix()) else {
        return refuse(Error::Unauthorized(EXPIRED.into()));
    };
    let ops = match still_allowed(&s, &target).await {
        Ok(ops) => ops,
        Err(e) => return refuse(e),
    };
    let Some(guard) = s.forwards.open_stream(&cred) else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "at most {} connections at once",
                crate::forward::MAX_STREAMS
            ),
        )
            .into_response();
    };
    let ws = match ws {
        Ok(ws) => ws,
        Err(r) => return crate::extract::rejection(r.status(), r.body_text()),
    };
    ws.on_upgrade(move |socket| async move {
        let _guard = guard;
        run(s, cred, target, expires_at, ops, socket).await;
    })
}

async fn close(mut socket: WebSocket, reason: String) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1011,
            reason: reason.chars().take(120).collect::<String>().into(),
        })))
        .await;
}

async fn run(
    s: AppState,
    cred: String,
    t: Target,
    expires_at: i64,
    ops: Arc<dyn KubeOps>,
    socket: WebSocket,
) {
    let mut pod: PortStream = match ops.port_forward(&t.ns, &t.pod, t.port).await {
        Ok(p) => p,
        Err(e) => return close(socket, e.to_string()).await,
    };
    let mut io = crate::agents::axum_io::io(socket);
    let copy = tokio::io::copy_bidirectional(&mut io, &mut pod);
    tokio::pin!(copy);
    let mut recheck = tokio::time::interval(s.config.forward_recheck);
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    recheck.tick().await;
    let until = std::time::Duration::from_secs(expires_at.saturating_sub(now_unix()).max(0) as u64);
    let expiry = tokio::time::sleep(until);
    tokio::pin!(expiry);
    loop {
        tokio::select! {
            _ = &mut copy => return,
            _ = &mut expiry => return,
            _ = recheck.tick() => {
                if s.forwards.lookup(&cred, now_unix()).is_none() || still_allowed(&s, &t).await.is_err() {
                    return;
                }
            }
        }
    }
}
