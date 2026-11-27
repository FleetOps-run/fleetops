//! The `ee_audit_sinks` table (`1000010_audit_sinks.sql`).

use super::model::{Sink, SinkKind, SinkSecrets, SinkSettings};
use fleetops_core::{Error, Result};
use fleetops_store::Store;
use sqlx::Row;

fn db_err(e: sqlx::Error) -> Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            Error::Conflict("that name is already taken".into())
        }
        _ => Error::Internal(format!("database: {e}")),
    }
}

fn json_err(e: serde_json::Error) -> Error {
    Error::Internal(format!("audit sinks: {e}"))
}

fn aad(id: i64) -> Vec<u8> {
    format!("audit-sink:{id}").into_bytes()
}

fn seal(store: &Store, id: i64, s: &SinkSecrets) -> Result<String> {
    let plain = serde_json::to_vec(s).map_err(json_err)?;
    Ok(store.secrets().seal(&aad(id), &plain))
}

const COLS: &str = "id, name, kind, enabled, settings, secrets, cursor, gap_rows,
    last_sent_at, last_error, last_error_at";

fn sink_from(r: &sqlx::sqlite::SqliteRow) -> Result<Sink> {
    Ok(Sink {
        id: r.get("id"),
        name: r.get("name"),
        kind: SinkKind::parse(r.get::<String, _>("kind").as_str())
            .ok_or_else(|| Error::Internal("unknown sink kind".into()))?,
        enabled: r.get("enabled"),
        settings: serde_json::from_str(r.get::<String, _>("settings").as_str())
            .map_err(json_err)?,
        cursor: r.get("cursor"),
        gap_rows: r.get("gap_rows"),
        last_sent_at: r.get("last_sent_at"),
        last_error: r.get("last_error"),
        last_error_at: r.get("last_error_at"),
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    store: &Store,
    name: &str,
    kind: SinkKind,
    enabled: bool,
    settings: &SinkSettings,
    secrets: &SinkSecrets,
    cursor: i64,
    now: i64,
) -> Result<i64> {
    let settings = serde_json::to_string(settings).map_err(json_err)?;
    let mut tx = store.pool().begin().await.map_err(db_err)?;
    let id = sqlx::query(
        "INSERT INTO ee_audit_sinks (name, kind, enabled, settings, cursor, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(kind.as_str())
    .bind(enabled)
    .bind(settings)
    .bind(cursor)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?
    .last_insert_rowid();
    sqlx::query("UPDATE ee_audit_sinks SET secrets = ? WHERE id = ?")
        .bind(seal(store, id, secrets)?)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(id)
}

/// A sink with its secrets opened.
pub async fn get(store: &Store, id: i64) -> Result<(Sink, SinkSecrets)> {
    let r = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} FROM ee_audit_sinks WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(store.pool())
    .await
    .map_err(db_err)?
    .ok_or_else(|| Error::NotFound(format!("audit sink {id}")))?;
    let secrets = match r.get::<Option<String>, _>("secrets") {
        None => SinkSecrets::default(),
        Some(sealed) => {
            let plain = store.secrets().open(&aad(id), &sealed).map_err(|_| {
                Error::Invalid("this sink's saved secret can't be read; enter it again".into())
            })?;
            serde_json::from_slice(&plain).map_err(json_err)?
        }
    };
    Ok((sink_from(&r)?, secrets))
}

pub async fn list(store: &Store) -> Result<Vec<Sink>> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} FROM ee_audit_sinks ORDER BY name"
    )))
    .fetch_all(store.pool())
    .await
    .map_err(db_err)?
    .iter()
    .map(sink_from)
    .collect()
}

pub async fn count(store: &Store) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM ee_audit_sinks")
        .fetch_one(store.pool())
        .await
        .map_err(db_err)
}

/// `secrets: None` keeps the stored ones.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    store: &Store,
    id: i64,
    name: &str,
    enabled: bool,
    settings: &SinkSettings,
    secrets: Option<&SinkSecrets>,
    now: i64,
) -> Result<()> {
    let settings = serde_json::to_string(settings).map_err(json_err)?;
    let res = sqlx::query(
        "UPDATE ee_audit_sinks SET name = ?, enabled = ?, settings = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(name)
    .bind(enabled)
    .bind(settings)
    .bind(now)
    .bind(id)
    .execute(store.pool())
    .await
    .map_err(db_err)?;
    if res.rows_affected() == 0 {
        return Err(Error::NotFound(format!("audit sink {id}")));
    }
    if let Some(s) = secrets {
        sqlx::query("UPDATE ee_audit_sinks SET secrets = ? WHERE id = ?")
            .bind(seal(store, id, s)?)
            .bind(id)
            .execute(store.pool())
            .await
            .map_err(db_err)?;
    }
    Ok(())
}

pub async fn delete(store: &Store, id: i64) -> Result<()> {
    let res = sqlx::query("DELETE FROM ee_audit_sinks WHERE id = ?")
        .bind(id)
        .execute(store.pool())
        .await
        .map_err(db_err)?;
    if res.rows_affected() == 0 {
        return Err(Error::NotFound(format!("audit sink {id}")));
    }
    Ok(())
}

/// The sink accepted everything up to `cursor`; `gap_add` rows were lost
/// to retention on the way.
pub async fn advance(store: &Store, id: i64, cursor: i64, gap_add: i64, now: i64) -> Result<()> {
    sqlx::query(
        "UPDATE ee_audit_sinks SET cursor = ?, gap_rows = gap_rows + ?, last_sent_at = ?,
             last_error = NULL, last_error_at = NULL
         WHERE id = ?",
    )
    .bind(cursor)
    .bind(gap_add)
    .bind(now)
    .bind(id)
    .execute(store.pool())
    .await
    .map_err(db_err)?;
    Ok(())
}

pub async fn fail(store: &Store, id: i64, err: &str, now: i64) -> Result<()> {
    sqlx::query("UPDATE ee_audit_sinks SET last_error = ?, last_error_at = ? WHERE id = ?")
        .bind(err)
        .bind(now)
        .bind(id)
        .execute(store.pool())
        .await
        .map_err(db_err)?;
    Ok(())
}
