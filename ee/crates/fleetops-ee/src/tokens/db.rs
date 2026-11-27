//! The `api_tokens` table (`1000011_api_tokens.sql`).

use fleetops_core::{Error, Result};
use serde::Serialize;
use sqlx::{AssertSqlSafe, SqlitePool};
use utoipa::ToSchema;

fn db_err(e: sqlx::Error) -> Error {
    Error::Internal(format!("database: {e}"))
}

/// A token as pages show it; never the secret or its hash.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, sqlx::FromRow)]
pub struct TokenInfo {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub name: String,
    /// The token's first characters (`fo_` and 6 hex), to tell it apart.
    pub prefix: String,
    /// Only GET, HEAD and OPTIONS.
    pub read_only: bool,
    pub created_at: i64,
    /// `null`: never expires.
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub last_used_ip: Option<String>,
}

const SELECT: &str = "SELECT t.id, t.user_id, u.username, t.name, t.prefix, t.read_only,
        t.created_at, t.expires_at, t.last_used_at, t.last_used_ip
     FROM api_tokens t JOIN users u ON u.id = t.user_id";

pub struct NewToken<'a> {
    pub user_id: i64,
    pub name: &'a str,
    pub prefix: &'a str,
    pub hash: &'a str,
    pub read_only: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

pub async fn create(pool: &SqlitePool, t: &NewToken<'_>) -> Result<TokenInfo> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO api_tokens (user_id, name, prefix, token_hash, read_only, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(t.user_id)
    .bind(t.name)
    .bind(t.prefix)
    .bind(t.hash)
    .bind(t.read_only)
    .bind(t.created_at)
    .bind(t.expires_at)
    .fetch_one(pool)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            Error::Conflict(format!("you already have a token named '{}'", t.name))
        }
        _ => db_err(e),
    })?;
    get(pool, id).await
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<TokenInfo> {
    // SELECT is a constant; values are bound.
    sqlx::query_as(AssertSqlSafe(format!("{SELECT} WHERE t.id = ?")))
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| Error::NotFound(format!("token {id}")))
}

/// One user's tokens, or everyone's; newest first.
pub async fn list(pool: &SqlitePool, user_id: Option<i64>) -> Result<Vec<TokenInfo>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "{SELECT} WHERE (? IS NULL OR t.user_id = ?) ORDER BY t.id DESC"
    )))
    .bind(user_id)
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn count(pool: &SqlitePool, user_id: i64) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)
}

pub async fn delete(pool: &SqlitePool, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM api_tokens WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// A live token by hash: `(id, user_id, name, read_only, last_used_at)`.
pub async fn find_live(
    pool: &SqlitePool,
    hash: &str,
    now: i64,
) -> Result<Option<(i64, i64, String, bool, Option<i64>)>> {
    sqlx::query_as(
        "SELECT id, user_id, name, read_only, last_used_at FROM api_tokens
         WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(hash)
    .bind(now)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub async fn touch(pool: &SqlitePool, id: i64, now: i64, ip: &str) -> Result<()> {
    sqlx::query("UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?")
        .bind(now)
        .bind(ip)
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    Ok(())
}
