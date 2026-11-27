//! `/ee/audit/sinks` and `/ee/audit/retention`. Admins only. Without a
//! license, sinks stay listed and deletable; nothing else changes.

use super::{
    db,
    forwarder::Forwarder,
    model::{Sink, SinkKind, SinkSecrets, SinkSettings, SyslogTransport},
    validate, validate_name, MAX_SINKS,
};
use crate::notify::send::host_of;
use axum::{extract::State, http::StatusCode, Extension, Json};
use fleetops_api::{
    auth::extract::AdminUser,
    authz::require_feature,
    extract::{ApiJson, ApiPath},
    ApiResult, AppState,
};
use fleetops_core::{edition::Feature, now_unix, Error};
use fleetops_store::{AuditEntry, AUDIT_RETENTION_KEY};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use utoipa::ToSchema;

pub const RETENTION_DEFAULT_DAYS: i64 = 90;
pub const RETENTION_MAX_DAYS: i64 = 3650;

/// A sink as the page shows it: never a secret.
#[derive(Serialize, ToSchema)]
pub struct SinkView {
    pub id: i64,
    pub name: String,
    pub kind: SinkKind,
    pub enabled: bool,
    /// `host:port` for syslog, the URL's host otherwise.
    pub target: String,
    pub transport: Option<SyslogTransport>,
    /// Whether a URL is stored; the URL itself is a secret.
    pub url_set: bool,
    pub header_names: Vec<String>,
    pub token_set: bool,
    pub ca_set: bool,
    /// The last audit id the receiver accepted.
    pub cursor: i64,
    /// Audit rows not sent yet.
    pub behind: i64,
    /// Rows retention removed before this sink sent them.
    pub gap_rows: i64,
    pub last_sent_at: Option<i64>,
    pub last_error: Option<String>,
    pub last_error_at: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
pub struct HeaderBody {
    pub name: String,
    /// Empty keeps the stored value for this name.
    #[serde(default)]
    pub value: String,
}

#[derive(Deserialize, ToSchema, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SinkStart {
    /// Only rows written from now on (default).
    #[default]
    Now,
    /// Every row the audit log still holds, then new ones.
    All,
}

#[derive(Deserialize, ToSchema)]
pub struct SinkBody {
    pub name: String,
    pub kind: SinkKind,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub transport: Option<SyslogTransport>,
    /// Left out keeps the stored certificate; `""` removes it.
    pub ca_pem: Option<String>,
    /// Empty or left out keeps the stored URL.
    pub url: Option<String>,
    /// Splunk HEC token; empty or left out keeps the stored one.
    pub token: Option<String>,
    #[serde(default)]
    pub headers: Vec<HeaderBody>,
    /// Creating only.
    pub start: Option<SinkStart>,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Retention {
    pub days: i64,
    #[serde(default)]
    pub default_days: i64,
}

fn trimmed(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// The settings and secrets `b` asks for, with blanks filled from `old`.
fn parts(b: &SinkBody, old: Option<(&SinkSettings, &SinkSecrets)>) -> (SinkSettings, SinkSecrets) {
    let syslog = b.kind == SinkKind::Syslog;
    let old_set = old.map(|o| o.0);
    let old = old.map(|o| o.1);
    let ca_pem = match b.ca_pem.as_deref().map(str::trim) {
        None => old_set.and_then(|o| o.ca_pem.clone()),
        Some("") => None,
        Some(pem) => Some(pem.to_string()),
    };
    let settings = SinkSettings {
        host: trimmed(&b.host).filter(|_| syslog),
        port: b.port.filter(|_| syslog),
        transport: b.transport.filter(|_| syslog),
        ca_pem: ca_pem.filter(|_| syslog && b.transport == Some(SyslogTransport::Tls)),
        header_names: if b.kind == SinkKind::Http {
            b.headers
                .iter()
                .map(|h| h.name.trim().to_string())
                .collect()
        } else {
            vec![]
        },
    };
    let token = match trimmed(&b.token) {
        Some(t) => Some(t),
        None => old.and_then(|o| o.token.clone()),
    }
    .filter(|_| b.kind == SinkKind::SplunkHec);
    let headers = if b.kind == SinkKind::Http {
        b.headers
            .iter()
            .map(|h| {
                let name = h.name.trim().to_string();
                let value = if h.value.is_empty() {
                    old.and_then(|o| o.headers.iter().find(|(n, _)| *n == name))
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                } else {
                    h.value.clone()
                };
                (name, value)
            })
            .collect()
    } else {
        vec![]
    };
    let url = match trimmed(&b.url) {
        Some(u) => Some(u),
        None => old.and_then(|o| o.url.clone()),
    }
    .filter(|_| !syslog);
    (
        settings,
        SinkSecrets {
            url,
            token,
            headers,
        },
    )
}

async fn count_after(s: &AppState, cursor: i64) -> ApiResult<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE id > ?")
        .bind(cursor)
        .fetch_one(s.store.pool())
        .await
        .map_err(|e| Error::Internal(format!("database: {e}")).into())
}

async fn view(s: &AppState, sink: Sink, secrets: &SinkSecrets) -> ApiResult<SinkView> {
    let target = match sink.kind {
        SinkKind::Syslog => format!(
            "{}:{}",
            sink.settings.host.as_deref().unwrap_or_default(),
            sink.settings.port.unwrap_or_default()
        ),
        _ => secrets.url.as_deref().and_then(host_of).unwrap_or_default(),
    };
    Ok(SinkView {
        behind: count_after(s, sink.cursor).await?,
        id: sink.id,
        name: sink.name,
        kind: sink.kind,
        enabled: sink.enabled,
        target,
        transport: sink.settings.transport,
        url_set: secrets.url.is_some(),
        header_names: sink.settings.header_names,
        token_set: secrets.token.is_some(),
        ca_set: sink.settings.ca_pem.is_some(),
        cursor: sink.cursor,
        gap_rows: sink.gap_rows,
        last_sent_at: sink.last_sent_at,
        last_error: sink.last_error,
        last_error_at: sink.last_error_at,
    })
}

async fn view_id(s: &AppState, id: i64) -> ApiResult<SinkView> {
    let (sink, secrets) = db::get(&s.store, id).await?;
    view(s, sink, &secrets).await
}

async fn audit(s: &AppState, by: i64, action: &str, name: &str, kind: SinkKind) {
    fleetops_api::audit_detail(
        s,
        Some(by),
        action,
        "audit_sink",
        name,
        "success",
        Some(json!({"kind": kind})),
    )
    .await;
}

#[utoipa::path(get, path = "/ee/audit/sinks", operation_id = "listAuditSinks", tag = "enterprise",
    summary = "Where the audit log is forwarded",
    responses((status = 200, description = "Sinks, by name", body = [SinkView])))]
pub async fn list(State(s): State<AppState>, _a: AdminUser) -> ApiResult<Json<Vec<SinkView>>> {
    let mut out = vec![];
    for sink in db::list(&s.store).await? {
        let (sink, secrets) = db::get(&s.store, sink.id).await?;
        out.push(view(&s, sink, &secrets).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(post, path = "/ee/audit/sinks", operation_id = "createAuditSink", tag = "enterprise",
    summary = "Forward the audit log somewhere (needs the audit_sinks feature)", request_body = SinkBody,
    responses((status = 201, description = "The sink", body = SinkView)))]
pub async fn create(
    State(s): State<AppState>,
    AdminUser(admin): AdminUser,
    ApiJson(b): ApiJson<SinkBody>,
) -> ApiResult<(StatusCode, Json<SinkView>)> {
    require_feature(&s, Feature::AuditSinks)?;
    let name = validate_name(&b.name)?;
    let (settings, secrets) = parts(&b, None);
    validate(b.kind, &settings, &secrets)?;
    if db::count(&s.store).await? >= MAX_SINKS {
        return Err(Error::Conflict(format!("at most {MAX_SINKS} sinks")).into());
    }
    let cursor = match b.start.unwrap_or_default() {
        // Just before the oldest row kept, so rows pruned before this sink
        // existed do not count as a gap.
        SinkStart::All => {
            let oldest: Option<i64> = sqlx::query_scalar("SELECT MIN(id) FROM audit_log")
                .fetch_one(s.store.pool())
                .await
                .map_err(|e| Error::Internal(format!("database: {e}")))?;
            oldest.map_or(0, |id| id - 1)
        }
        SinkStart::Now => s
            .store
            .list_audit(1, None)
            .await?
            .first()
            .map_or(0, |e| e.id),
    };
    let id = db::create(
        &s.store,
        &name,
        b.kind,
        b.enabled,
        &settings,
        &secrets,
        cursor,
        now_unix(),
    )
    .await?;
    audit(&s, admin.user.id, "audit.sink.create", &name, b.kind).await;
    Ok((StatusCode::CREATED, Json(view_id(&s, id).await?)))
}

#[utoipa::path(put, path = "/ee/audit/sinks/{id}", operation_id = "updateAuditSink", tag = "enterprise",
    summary = "Change a sink (needs the audit_sinks feature)", request_body = SinkBody,
    params(("id" = i64, Path, description = "Sink id")),
    responses((status = 200, description = "The sink", body = SinkView)))]
pub async fn update(
    State(s): State<AppState>,
    AdminUser(admin): AdminUser,
    ApiPath(id): ApiPath<i64>,
    ApiJson(b): ApiJson<SinkBody>,
) -> ApiResult<Json<SinkView>> {
    require_feature(&s, Feature::AuditSinks)?;
    let name = validate_name(&b.name)?;
    let (old, old_secrets) = db::get(&s.store, id).await?;
    if old.kind != b.kind {
        return Err(Error::Invalid("a sink's kind cannot change; add a new sink".into()).into());
    }
    let (settings, secrets) = parts(&b, Some((&old.settings, &old_secrets)));
    validate(b.kind, &settings, &secrets)?;
    db::update(
        &s.store,
        id,
        &name,
        b.enabled,
        &settings,
        Some(&secrets),
        now_unix(),
    )
    .await?;
    audit(&s, admin.user.id, "audit.sink.update", &name, b.kind).await;
    Ok(Json(view_id(&s, id).await?))
}

#[utoipa::path(delete, path = "/ee/audit/sinks/{id}", operation_id = "deleteAuditSink", tag = "enterprise",
    summary = "Stop forwarding to a sink",
    params(("id" = i64, Path, description = "Sink id")),
    responses((status = 204, description = "Deleted")))]
pub async fn delete(
    State(s): State<AppState>,
    Extension(fwd): Extension<Arc<Forwarder>>,
    AdminUser(admin): AdminUser,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<StatusCode> {
    let (sink, _) = db::get(&s.store, id).await?;
    db::delete(&s.store, id).await?;
    fwd.forget(id);
    audit(
        &s,
        admin.user.id,
        "audit.sink.delete",
        &sink.name,
        sink.kind,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/ee/audit/sinks/{id}/test", operation_id = "testAuditSink", tag = "enterprise",
    summary = "Send one sample row (not written to the audit log)",
    params(("id" = i64, Path, description = "Sink id")),
    responses((status = 204, description = "The receiver took it")))]
pub async fn test(
    State(s): State<AppState>,
    Extension(fwd): Extension<Arc<Forwarder>>,
    AdminUser(admin): AdminUser,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<StatusCode> {
    require_feature(&s, Feature::AuditSinks)?;
    let (sink, secrets) = db::get(&s.store, id).await?;
    let row = AuditEntry {
        id: 0,
        ts: now_unix(),
        user_id: Some(admin.user.id),
        username: Some(admin.user.username.clone()),
        environment_id: None,
        action: "audit.sink.test".into(),
        target_type: Some("audit_sink".into()),
        target_id: Some(sink.name.clone()),
        result: "success".into(),
        detail: Some(json!({"test": true})),
    };
    fwd.sender()
        .send(&sink, &secrets, &[row])
        .await
        .map_err(|e| match e {
            Error::Upstream { message, .. } => Error::Invalid(message),
            other => other,
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/ee/audit/sinks/{id}/skip", operation_id = "skipAuditSink", tag = "enterprise",
    summary = "Skip everything not sent yet (counted as a gap); for a receiver that keeps refusing a row",
    params(("id" = i64, Path, description = "Sink id")),
    responses((status = 200, description = "The sink", body = SinkView)))]
pub async fn skip(
    State(s): State<AppState>,
    Extension(fwd): Extension<Arc<Forwarder>>,
    AdminUser(admin): AdminUser,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<Json<SinkView>> {
    require_feature(&s, Feature::AuditSinks)?;
    let (sink, _) = db::get(&s.store, id).await?;
    let newest = s
        .store
        .list_audit(1, None)
        .await?
        .first()
        .map_or(0, |e| e.id);
    let skipped = count_after(&s, sink.cursor).await?;
    db::skip(&s.store, id, newest, skipped).await?;
    fwd.forget(id);
    fleetops_api::audit_detail(
        &s,
        Some(admin.user.id),
        "audit.sink.skip",
        "audit_sink",
        &sink.name,
        "success",
        Some(json!({"skipped": skipped})),
    )
    .await;
    Ok(Json(view_id(&s, id).await?))
}

async fn retention(s: &AppState) -> ApiResult<Json<Retention>> {
    Ok(Json(Retention {
        days: s.store.audit_retention_days().await?,
        default_days: RETENTION_DEFAULT_DAYS,
    }))
}

#[utoipa::path(get, path = "/ee/audit/retention", operation_id = "getAuditRetention", tag = "enterprise",
    summary = "How many days audit rows are kept",
    responses((status = 200, description = "Retention", body = Retention)))]
pub async fn get_retention(State(s): State<AppState>, _a: AdminUser) -> ApiResult<Json<Retention>> {
    retention(&s).await
}

#[utoipa::path(put, path = "/ee/audit/retention", operation_id = "putAuditRetention", tag = "enterprise",
    summary = "Keep audit rows longer (needs the audit_sinks feature)", request_body = Retention,
    responses((status = 200, description = "Retention", body = Retention)))]
pub async fn put_retention(
    State(s): State<AppState>,
    AdminUser(admin): AdminUser,
    ApiJson(b): ApiJson<Retention>,
) -> ApiResult<Json<Retention>> {
    require_feature(&s, Feature::AuditSinks)?;
    if !(1..=RETENTION_MAX_DAYS).contains(&b.days) {
        return Err(Error::Invalid(format!("days must be 1-{RETENTION_MAX_DAYS}")).into());
    }
    let old = s.store.audit_retention_days().await?;
    s.store
        .set_setting(AUDIT_RETENTION_KEY, &json!(b.days))
        .await?;
    fleetops_api::audit_detail(
        &s,
        Some(admin.user.id),
        "audit.retention.update",
        "audit",
        "retention",
        "success",
        Some(json!({"from": old, "days": b.days})),
    )
    .await;
    retention(&s).await
}
