//! `/ee/tokens`: each user's own API tokens; admins see and revoke all.
//! Managing tokens needs a browser session, so a token cannot mint more.

use super::{db, validate_expiry, validate_name, PER_USER_MAX, PREFIX_LEN};
use axum::{extract::State, http::StatusCode, Json};
use fleetops_api::{
    auth::{
        bearer::BEARER_PREFIX,
        extract::{AdminUser, CurrentUser},
        token::{generate_token, hash_token},
    },
    authz::require_feature,
    extract::{ApiJson, ApiPath},
    ApiResult, AppState,
};
use fleetops_core::{edition::Feature, now_unix, Error, Role};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

pub use db::TokenInfo;

#[derive(Deserialize, ToSchema)]
pub struct NewToken {
    pub name: String,
    #[serde(default)]
    pub read_only: bool,
    /// 1-365; left out, the token never expires.
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct CreatedToken {
    pub token: TokenInfo,
    /// The token itself. Shown only now; FleetOps keeps only its hash.
    pub secret: String,
}

fn gate(s: &AppState, cu: &CurrentUser) -> ApiResult<()> {
    require_feature(s, Feature::ApiTokens)?;
    cu.require_session()?;
    Ok(())
}

async fn audit(s: &AppState, by: i64, action: &str, t: &TokenInfo) {
    fleetops_api::audit_detail(
        s,
        Some(by),
        action,
        "api_token",
        &t.name,
        "success",
        Some(json!({"owner": t.username, "read_only": t.read_only, "expires_at": t.expires_at})),
    )
    .await;
}

#[utoipa::path(get, path = "/ee/tokens", operation_id = "listApiTokens", tag = "enterprise",
    summary = "Your API tokens",
    responses((status = 200, description = "Tokens, newest first", body = [TokenInfo])))]
pub async fn list(State(s): State<AppState>, cu: CurrentUser) -> ApiResult<Json<Vec<TokenInfo>>> {
    gate(&s, &cu)?;
    Ok(Json(db::list(s.store.pool(), Some(cu.user.id)).await?))
}

#[utoipa::path(get, path = "/ee/tokens/all", operation_id = "listAllApiTokens", tag = "enterprise",
    summary = "Every user's API tokens (admins)",
    responses((status = 200, description = "Tokens, newest first", body = [TokenInfo])))]
pub async fn list_all(
    State(s): State<AppState>,
    AdminUser(admin): AdminUser,
) -> ApiResult<Json<Vec<TokenInfo>>> {
    gate(&s, &admin)?;
    Ok(Json(db::list(s.store.pool(), None).await?))
}

#[utoipa::path(post, path = "/ee/tokens", operation_id = "createApiToken", tag = "enterprise",
    summary = "Create an API token for yourself (needs the api_tokens feature)", request_body = NewToken,
    responses((status = 201, description = "The token and, once only, its secret", body = CreatedToken)))]
pub async fn create(
    State(s): State<AppState>,
    cu: CurrentUser,
    ApiJson(body): ApiJson<NewToken>,
) -> ApiResult<(StatusCode, Json<CreatedToken>)> {
    gate(&s, &cu)?;
    let name = validate_name(&body.name)?;
    let days = validate_expiry(body.expires_in_days)?;
    let pool = s.store.pool();
    if db::count(pool, cu.user.id).await? >= PER_USER_MAX {
        return Err(Error::Conflict(format!("token limit reached ({PER_USER_MAX})")).into());
    }
    let secret = format!("{BEARER_PREFIX}{}", generate_token());
    let now = now_unix();
    let token = db::create(
        pool,
        &db::NewToken {
            user_id: cu.user.id,
            name: &name,
            prefix: &secret[..PREFIX_LEN],
            hash: &hash_token(&secret),
            read_only: body.read_only,
            created_at: now,
            expires_at: days.map(|d| now + i64::from(d) * 86_400),
        },
    )
    .await?;
    audit(&s, cu.user.id, "token.create", &token).await;
    Ok((StatusCode::CREATED, Json(CreatedToken { token, secret })))
}

#[utoipa::path(delete, path = "/ee/tokens/{id}", operation_id = "deleteApiToken", tag = "enterprise",
    summary = "Revoke an API token (yours, or anyone's for admins)",
    params(("id" = i64, Path, description = "Token id")),
    responses((status = 204, description = "Revoked")))]
pub async fn delete(
    State(s): State<AppState>,
    cu: CurrentUser,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<StatusCode> {
    // Revoking works without a license, so leftover tokens can go.
    cu.require_session()?;
    let pool = s.store.pool();
    let token = db::get(pool, id).await?;
    if token.user_id != cu.user.id && cu.user.role != Role::Admin {
        return Err(Error::NotFound(format!("token {id}")).into());
    }
    db::delete(pool, id).await?;
    audit(&s, cu.user.id, "token.revoke", &token).await;
    Ok(StatusCode::NO_CONTENT)
}
