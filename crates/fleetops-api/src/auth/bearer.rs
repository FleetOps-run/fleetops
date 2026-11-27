//! `Authorization: Bearer` API tokens (Enterprise). Core asks this hook
//! who a token belongs to; Community has no tokens.

use crate::AppState;
use async_trait::async_trait;
use fleetops_core::{Error, Result, User};

/// Every API token starts with this.
pub const BEARER_PREFIX: &str = "fo_";

/// The token a request authenticated with.
#[derive(Debug, Clone)]
pub struct TokenRef {
    pub id: i64,
    pub name: String,
    /// Only GET, HEAD and OPTIONS.
    pub read_only: bool,
}

#[async_trait]
pub trait TokenAuth: Send + Sync {
    /// The token's owner, or `None` when the token is unknown or expired.
    /// Errors (such as `LicenseRequired`) are returned to the client.
    async fn authenticate(
        &self,
        s: &AppState,
        raw: &str,
        ip: &str,
    ) -> Result<Option<(User, TokenRef)>>;
}

/// The Community edition: API tokens need a license.
pub struct NoTokenAuth;

#[async_trait]
impl TokenAuth for NoTokenAuth {
    async fn authenticate(
        &self,
        _: &AppState,
        _: &str,
        _: &str,
    ) -> Result<Option<(User, TokenRef)>> {
        Err(Error::LicenseRequired(
            fleetops_core::edition::Feature::ApiTokens.as_str().into(),
        ))
    }
}
