mod common;

use axum::http::StatusCode;
use common::*;
use fleetops_core::now_unix;
use serde_json::{json, Value};

const DAY: i64 = 86_400;

fn body(v: Value) -> Option<(&'static str, String)> {
    Some(("application/json", v.to_string()))
}

struct Fx {
    ee: Ee,
    key: ed25519_dalek::SigningKey,
    admin: Session,
    bob: Session,
}

/// A licensed server with an admin and user bob.
async fn fx() -> Fx {
    let key = key();
    let ee = ee_app(&key, None).await;
    let admin = ee.admin().await;
    let r = ee
        .install(
            &admin,
            &license(&key, now_unix() + 30 * DAY, None, &["audit_export"]),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    ee.user(&admin, "bob").await;
    let bob = ee.login("bob").await;
    Fx {
        ee,
        key,
        admin,
        bob,
    }
}

async fn create(ee: &Ee, s: &Session, v: Value) -> Resp {
    ee.send("POST", "/api/v1/ee/tokens", body(v), Some(s)).await
}

/// Creates a token and returns `(id, secret)`.
async fn token(ee: &Ee, s: &Session, name: &str, read_only: bool) -> (i64, String) {
    let r = create(ee, s, json!({"name": name, "read_only": read_only})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let j = r.json();
    (
        j["token"]["id"].as_i64().unwrap(),
        j["secret"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn create_then_use() {
    let f = fx().await;
    let r = create(
        &f.ee,
        &f.admin,
        json!({"name": "ci", "read_only": false, "expires_in_days": 30}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let j = r.json();
    let secret = j["secret"].as_str().unwrap();
    assert!(secret.starts_with("fo_"));
    assert_eq!(secret.len(), 67);
    assert_eq!(j["token"]["prefix"], &secret[..9]);
    assert_eq!(j["token"]["username"], "admin");
    let exp = j["token"]["expires_at"].as_i64().unwrap();
    assert!((exp - (now_unix() + 30 * DAY)).abs() < 10);

    let me =
        f.ee.send_bearer("GET", "/api/v1/auth/me", None, secret)
            .await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text);
    assert_eq!(me.json()["user"]["username"], "admin");

    let list =
        f.ee.send("GET", "/api/v1/ee/tokens", None, Some(&f.admin))
            .await;
    assert_eq!(list.status, StatusCode::OK);
    let rows = list.json();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert!(rows[0]["last_used_at"].as_i64().is_some());
    assert_eq!(rows[0]["last_used_ip"], "127.0.0.1");
}

#[tokio::test]
async fn secret_is_shown_once() {
    let f = fx().await;
    token(&f.ee, &f.admin, "ci", false).await;
    let list =
        f.ee.send("GET", "/api/v1/ee/tokens", None, Some(&f.admin))
            .await;
    assert!(!list.text.contains("secret"));
    assert!(!list.text.contains("hash"));
}

#[tokio::test]
async fn name_rules() {
    let f = fx().await;
    for bad in [
        json!({"name": ""}),
        json!({"name": "   "}),
        json!({"name": "x".repeat(65)}),
    ] {
        let r = create(&f.ee, &f.admin, bad.clone()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", r.text);
    }
    for days in [0, 366] {
        let r = create(
            &f.ee,
            &f.admin,
            json!({"name": "d", "expires_in_days": days}),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{days}: {}", r.text);
    }
    token(&f.ee, &f.admin, "ci", false).await;
    let dup = create(&f.ee, &f.admin, json!({"name": " ci "})).await;
    assert_eq!(dup.status, StatusCode::CONFLICT, "{}", dup.text);
    // Another user may use the same name.
    token(&f.ee, &f.bob, "ci", false).await;
}

#[tokio::test]
async fn expired_token_is_401() {
    let f = fx().await;
    let (id, secret) = token(&f.ee, &f.admin, "ci", false).await;
    sqlx::query("UPDATE api_tokens SET expires_at = ? WHERE id = ?")
        .bind(now_unix() - 1)
        .bind(id)
        .execute(f.ee.store.pool())
        .await
        .unwrap();
    let r = f.ee.send_bearer("GET", "/api/v1/envs", None, &secret).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_only_token() {
    let f = fx().await;
    let (_, secret) = token(&f.ee, &f.admin, "ro", true).await;
    let r =
        f.ee.send_bearer(
            "POST",
            "/api/v1/envs",
            body(json!({"name": "x", "kind": "docker-local", "url": "unix:///x.sock"})),
            &secret,
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text);
    let ok = f.ee.send_bearer("GET", "/api/v1/envs", None, &secret).await;
    assert_eq!(ok.status, StatusCode::OK);
}

#[tokio::test]
async fn token_cannot_mint_or_revoke_tokens() {
    let f = fx().await;
    let (id, secret) = token(&f.ee, &f.admin, "ci", false).await;
    let mint =
        f.ee.send_bearer(
            "POST",
            "/api/v1/ee/tokens",
            body(json!({"name": "more"})),
            &secret,
        )
        .await;
    assert_eq!(mint.status, StatusCode::FORBIDDEN, "{}", mint.text);
    let del =
        f.ee.send_bearer("DELETE", &format!("/api/v1/ee/tokens/{id}"), None, &secret)
            .await;
    assert_eq!(del.status, StatusCode::FORBIDDEN, "{}", del.text);
}

#[tokio::test]
async fn revoke() {
    let f = fx().await;
    let (mine, secret) = token(&f.ee, &f.admin, "ci", false).await;
    let (bobs, bob_secret) = token(&f.ee, &f.bob, "bob-ci", false).await;

    let r =
        f.ee.send(
            "DELETE",
            &format!("/api/v1/ee/tokens/{mine}"),
            None,
            Some(&f.bob),
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "bob cannot see the admin's token"
    );

    let r =
        f.ee.send(
            "DELETE",
            &format!("/api/v1/ee/tokens/{mine}"),
            None,
            Some(&f.admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    let gone = f.ee.send_bearer("GET", "/api/v1/envs", None, &secret).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);

    let r =
        f.ee.send(
            "DELETE",
            &format!("/api/v1/ee/tokens/{bobs}"),
            None,
            Some(&f.admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "admins revoke anyone's");
    let gone =
        f.ee.send_bearer("GET", "/api/v1/envs", None, &bob_secret)
            .await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);

    let log = f.ee.store.list_audit(100, None).await.unwrap();
    let has = |action: &str, name: &str| {
        log.iter()
            .any(|e| e.action == action && e.target_id.as_deref() == Some(name))
    };
    assert!(has("token.create", "ci"));
    assert!(has("token.revoke", "ci"));
    assert!(has("token.revoke", "bob-ci"));
}

#[tokio::test]
async fn admin_lists_all() {
    let f = fx().await;
    token(&f.ee, &f.admin, "ci", false).await;
    token(&f.ee, &f.bob, "bob-ci", true).await;
    let all =
        f.ee.send("GET", "/api/v1/ee/tokens/all", None, Some(&f.admin))
            .await;
    assert_eq!(all.status, StatusCode::OK, "{}", all.text);
    let users: Vec<_> = all
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["username"].as_str().unwrap().to_string())
        .collect();
    assert!(users.contains(&"admin".into()) && users.contains(&"bob".into()));
    let own =
        f.ee.send("GET", "/api/v1/ee/tokens", None, Some(&f.bob))
            .await;
    assert_eq!(own.json().as_array().unwrap().len(), 1);
    let r =
        f.ee.send("GET", "/api/v1/ee/tokens/all", None, Some(&f.bob))
            .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn license_gone_then_back() {
    let f = fx().await;
    let (_, secret) = token(&f.ee, &f.admin, "ci", false).await;
    let r =
        f.ee.send("DELETE", "/api/v1/ee/license", None, Some(&f.admin))
            .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let off = f.ee.send_bearer("GET", "/api/v1/envs", None, &secret).await;
    assert_eq!(off.status, StatusCode::FORBIDDEN, "{}", off.text);
    assert_eq!(off.json()["code"], "license_required");
    f.ee.install(&f.admin, &license(&f.key, now_unix() + 30 * DAY, None, &[]))
        .await;
    let on = f.ee.send_bearer("GET", "/api/v1/envs", None, &secret).await;
    assert_eq!(on.status, StatusCode::OK, "{}", on.text);
}

#[tokio::test]
async fn limit_is_50() {
    let f = fx().await;
    for i in 0..50 {
        token(&f.ee, &f.bob, &format!("t{i}"), true).await;
    }
    let r = create(&f.ee, &f.bob, json!({"name": "t50"})).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.text);
    assert!(r.text.contains("token limit reached (50)"));
}

#[tokio::test]
async fn deleting_the_owner_deletes_tokens() {
    let f = fx().await;
    let (_, secret) = token(&f.ee, &f.bob, "ci", false).await;
    let bob_id =
        f.ee.store
            .find_credentials("bob")
            .await
            .unwrap()
            .unwrap()
            .0
            .id;
    let r =
        f.ee.send(
            "DELETE",
            &format!("/api/v1/users/{bob_id}"),
            None,
            Some(&f.admin),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text);
    let gone = f.ee.send_bearer("GET", "/api/v1/envs", None, &secret).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
    let all =
        f.ee.send("GET", "/api/v1/ee/tokens/all", None, Some(&f.admin))
            .await;
    assert_eq!(all.json().as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn export_has_token_name() {
    let f = fx().await;
    let r =
        f.ee.send("GET", "/api/v1/ee/audit/export", None, Some(&f.admin))
            .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert!(
        r.text.starts_with("id,ts,user_id,username,token_name,"),
        "{}",
        r.text
    );
}
