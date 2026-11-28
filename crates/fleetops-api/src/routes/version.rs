use crate::{auth::extract::AdminUser, update_check, AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use utoipa::ToSchema;

/// This server's version and the newest release the update check has seen.
#[derive(Serialize, ToSchema)]
pub struct VersionInfo {
    /// The running version, e.g. `1.5.0`.
    pub current: String,
    /// The newest release's tag, e.g. `v1.6.0`; none before the first
    /// successful check.
    pub latest: Option<String>,
    /// Whether `latest` is newer than `current`.
    pub update_available: bool,
    /// The newest release's page.
    pub release_url: Option<String>,
    /// When the newest release was last seen (unix seconds).
    pub checked_at: Option<i64>,
    /// Whether this server checks for updates (`--update-check`).
    pub check_enabled: bool,
}

#[utoipa::path(
    get,
    path = "/system/version",
    operation_id = "getVersion",
    tag = "system",
    summary = "This server's version and whether a newer release is out (admins only)",
    responses((status = 200, description = "Version", body = VersionInfo))
)]
pub async fn get(State(s): State<AppState>, _admin: AdminUser) -> Json<VersionInfo> {
    let current = env!("CARGO_PKG_VERSION");
    let seen = s.update.get();
    Json(VersionInfo {
        current: current.into(),
        update_available: seen
            .as_ref()
            .is_some_and(|(r, _)| update_check::is_newer(&r.tag, current)),
        latest: seen.as_ref().map(|(r, _)| r.tag.clone()),
        release_url: seen.as_ref().map(|(r, _)| r.url.clone()),
        checked_at: seen.map(|(_, at)| at),
        check_enabled: s.config.update_check,
    })
}
