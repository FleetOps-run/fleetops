use super::{
    bearer::TokenRef,
    cookie::{read_cookie, SESSION_COOKIE},
    token::{constant_time_eq, hash_token},
    CSRF_HEADER, SESSION_IDLE_SECS, SESSION_TOUCH_SECS,
};
use crate::{ApiError, AppState, IsTls};
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{
        header::{AUTHORIZATION, USER_AGENT},
        request::Parts,
        Method,
    },
};
use fleetops_core::{now_unix, Error, Role, User};
use fleetops_store::SessionRecord;
use std::{convert::Infallible, net::SocketAddr};

/// Connection metadata recorded on sessions and used for rate limiting.
pub struct ClientMeta {
    pub ip: String,
    pub user_agent: Option<String>,
    pub tls: bool,
}

impl<S: Send + Sync> FromRequestParts<S> for ClientMeta {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string())
            .unwrap_or_else(|| "unknown".into());
        let user_agent = parts
            .headers
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(256).collect());
        let tls = parts.extensions.get::<IsTls>().is_some_and(|t| t.0);
        Ok(ClientMeta {
            ip,
            user_agent,
            tls,
        })
    }
}

/// An authenticated user, by browser session or by API token (exactly one
/// of `session` and `token` is set). Extracting this enforces CSRF on every
/// session request other than GET/HEAD/OPTIONS, so handlers cannot forget
/// it; bearer requests need none, since browsers never send the header.
pub struct CurrentUser {
    pub user: User,
    pub session: Option<SessionRecord>,
    pub token: Option<TokenRef>,
}

impl CurrentUser {
    /// The browser session, for what an API token may not do (sign out,
    /// change a password, open the websocket, manage tokens).
    pub fn require_session(&self) -> Result<&SessionRecord, ApiError> {
        self.session
            .as_ref()
            .ok_or_else(|| Error::Forbidden("this needs a signed-in browser session".into()).into())
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// The token path: no cookie fallback, so a bad token never falls through
/// to a session the same client also holds.
async fn from_token(parts: &Parts, state: &AppState, raw: &str) -> Result<CurrentUser, ApiError> {
    let ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    let (user, token) = state
        .token_auth
        .authenticate(state, raw, &ip)
        .await?
        .ok_or_else(|| {
            ApiError::from(Error::Unauthorized("invalid or expired API token".into()))
        })?;
    if user.disabled_at.is_some() {
        return Err(Error::Unauthorized("invalid or expired API token".into()).into());
    }
    if token.read_only && !is_safe_method(&parts.method) {
        return Err(Error::Forbidden("this token is read-only".into()).into());
    }
    fleetops_store::set_credential(token.id, &token.name);
    Ok(CurrentUser {
        user,
        session: None,
        token: Some(token),
    })
}

fn is_safe_method(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn unauthorized() -> ApiError {
    Error::Unauthorized("authentication required".into()).into()
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if let Some(raw) = bearer(parts) {
            return from_token(parts, state, raw).await;
        }
        let token = read_cookie(&parts.headers, SESSION_COOKIE).ok_or_else(unauthorized)?;
        let session = state
            .store
            .find_session(&hash_token(&token))
            .await?
            .ok_or_else(unauthorized)?;
        let now = now_unix();
        if !session.is_active(now, SESSION_IDLE_SECS) {
            state.store.delete_session(session.id).await?;
            return Err(unauthorized());
        }
        if !is_safe_method(&parts.method) {
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !constant_time_eq(sent, &session.csrf_token) {
                return Err(Error::Forbidden("missing or invalid CSRF token".into()).into());
            }
        }
        if now - session.last_seen_at >= SESSION_TOUCH_SECS {
            state.store.touch_session(session.id, now).await?;
        }
        let user = match state.store.get_user(session.user_id).await {
            // Disabling ends the sessions too; this covers one made in between.
            Ok(u) if u.disabled_at.is_some() => return Err(unauthorized()),
            Ok(u) => u,
            Err(Error::NotFound(_)) => return Err(unauthorized()),
            Err(e) => return Err(e.into()),
        };
        Ok(CurrentUser {
            user,
            session: Some(session),
            token: None,
        })
    }
}

pub struct AdminUser(pub CurrentUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let cu = CurrentUser::from_request_parts(parts, state).await?;
        if cu.user.role != Role::Admin {
            return Err(Error::Forbidden("admin role required".into()).into());
        }
        Ok(AdminUser(cu))
    }
}
