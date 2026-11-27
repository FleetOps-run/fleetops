//! Personal API tokens: `Authorization: Bearer fo_…` acting as their owner.

pub mod auth;
pub mod db;
pub mod routes;

use fleetops_core::{Error, Result};

pub const NAME_MAX: usize = 64;
/// Tokens one user may hold.
pub const PER_USER_MAX: i64 = 50;
pub const EXPIRY_DAYS_MAX: u32 = 365;
/// Minimum gap between `last_used_*` writes for one token.
pub const TOUCH_SECS: i64 = 60;
/// Characters of a token kept to tell it apart (`fo_` and 6 hex).
pub const PREFIX_LEN: usize = 9;

/// The trimmed name, or why it is not allowed.
pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > NAME_MAX {
        return Err(Error::Invalid(format!(
            "token name must be 1-{NAME_MAX} characters"
        )));
    }
    Ok(name.to_string())
}

pub fn validate_expiry(days: Option<u32>) -> Result<Option<u32>> {
    match days {
        Some(d) if d == 0 || d > EXPIRY_DAYS_MAX => Err(Error::Invalid(format!(
            "expires_in_days must be 1-{EXPIRY_DAYS_MAX}, or left out for no expiry"
        ))),
        d => Ok(d),
    }
}
