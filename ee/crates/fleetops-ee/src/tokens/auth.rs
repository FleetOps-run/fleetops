//! The bearer hook core calls for `Authorization: Bearer fo_…`.

use super::{db, TOUCH_SECS};
use async_trait::async_trait;
use fleetops_api::{
    auth::{
        bearer::{TokenAuth, TokenRef, BEARER_PREFIX},
        token::hash_token,
    },
    AppState,
};
use fleetops_core::{edition::Feature, now_unix, Error, Result, User};

pub struct EeTokens;

#[async_trait]
impl TokenAuth for EeTokens {
    async fn authenticate(
        &self,
        s: &AppState,
        raw: &str,
        ip: &str,
    ) -> Result<Option<(User, TokenRef)>> {
        if !s.entitlements.has(Feature::ApiTokens) {
            return Err(Error::LicenseRequired(Feature::ApiTokens.as_str().into()));
        }
        if !raw.starts_with(BEARER_PREFIX) {
            return Ok(None);
        }
        let pool = s.store.pool();
        let now = now_unix();
        let Some((id, user_id, name, read_only, last_used)) =
            db::find_live(pool, &hash_token(raw), now).await?
        else {
            return Ok(None);
        };
        let user = match s.store.get_user(user_id).await {
            Ok(u) => u,
            Err(Error::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        if last_used.is_none_or(|t| now - t >= TOUCH_SECS) {
            db::touch(pool, id, now, ip).await?;
        }
        Ok(Some((
            user,
            TokenRef {
                id,
                name,
                read_only,
            },
        )))
    }
}
