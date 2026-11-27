mod common;

use async_trait::async_trait;
use axum::http::StatusCode;
use common::fake_docker::summary;
use common::*;
use fleetops_api::auth::bearer::{TokenAuth, TokenRef};
use fleetops_api::AppState;
use fleetops_core::{Result, User};
use serde_json::json;
use std::sync::Arc;

/// Knows `fo_good` (read-write) and `fo_ro` (read-only), both the admin's.
struct Tokens;

#[async_trait]
impl TokenAuth for Tokens {
    async fn authenticate(
        &self,
        s: &AppState,
        raw: &str,
        _ip: &str,
    ) -> Result<Option<(User, TokenRef)>> {
        let read_only = match raw {
            "fo_good" => false,
            "fo_ro" => true,
            _ => return Ok(None),
        };
        let user = s.store.find_credentials(ADMIN).await?.unwrap().0;
        Ok(Some((
            user,
            TokenRef {
                id: if read_only { 2 } else { 1 },
                name: if read_only { "ro".into() } else { "ci".into() },
                read_only,
            },
        )))
    }
}

async fn tokens_app() -> (TestApp, Session) {
    let app = app_with_tokens(Arc::new(Tokens)).await;
    let admin = app.setup_admin().await;
    (app, admin)
}

fn env_body(name: &str) -> serde_json::Value {
    json!({"name": name, "kind": "docker-local", "url": "unix:///fake.sock"})
}

#[tokio::test]
async fn bearer_acts_as_owner() {
    let (app, _) = tokens_app().await;
    let r = app
        .send(req_bearer("GET", "/api/v1/auth/me", "fo_good", None))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    assert_eq!(r.json["user"]["username"], ADMIN);
    assert_eq!(r.json["csrf_token"], "");
}

#[tokio::test]
async fn bearer_needs_no_csrf() {
    let (app, _) = tokens_app().await;
    let r = app
        .send(req_bearer(
            "POST",
            "/api/v1/envs",
            "fo_good",
            Some(env_body("ci-env")),
        ))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json);
}

#[tokio::test]
async fn unknown_bearer_is_401_even_with_a_cookie() {
    let (app, admin) = tokens_app().await;
    let mut r = req("GET", "/api/v1/envs", None, Some(&admin));
    r.headers_mut()
        .insert("authorization", "Bearer fo_bad".parse().unwrap());
    assert_eq!(app.send(r).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_only_refuses_writes() {
    let (app, _) = tokens_app().await;
    let w = app
        .send(req_bearer(
            "POST",
            "/api/v1/envs",
            "fo_ro",
            Some(env_body("nope")),
        ))
        .await;
    assert_eq!(w.status, StatusCode::FORBIDDEN, "{:?}", w.json);
    assert!(w.json["message"].as_str().unwrap().contains("read-only"));
    let r = app
        .send(req_bearer("GET", "/api/v1/envs", "fo_ro", None))
        .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn tokens_cannot_open_ws_or_logout() {
    let (app, _) = tokens_app().await;
    let mut ws = req_bearer("GET", "/api/v1/ws", "fo_good", None);
    for (k, v) in [
        ("connection", "upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ] {
        ws.headers_mut().insert(k, v.parse().unwrap());
    }
    assert_eq!(app.send(ws).await.status, StatusCode::FORBIDDEN);
    let out = app
        .send(req_bearer("POST", "/api/v1/auth/logout", "fo_good", None))
        .await;
    assert_eq!(out.status, StatusCode::FORBIDDEN, "{:?}", out.json);
}

#[tokio::test]
async fn community_refuses_bearer() {
    let app = app().await;
    app.setup_admin().await;
    let r = app
        .send(req_bearer("GET", "/api/v1/envs", "fo_good", None))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json);
    assert_eq!(r.json["code"], "license_required");
}

#[tokio::test]
async fn disabled_owner_is_401() {
    let (app, admin) = tokens_app().await;
    // The last admin cannot be disabled.
    app.create_user(&admin, "second", "second-password", "admin")
        .await;
    let id = app
        .store
        .find_credentials(ADMIN)
        .await
        .unwrap()
        .unwrap()
        .0
        .id;
    app.store.set_user_disabled(id, true, 1).await.unwrap();
    let r = app
        .send(req_bearer("GET", "/api/v1/envs", "fo_good", None))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_rows_name_the_token() {
    let (app, admin) = tokens_app().await;
    app.add_env(&admin, "by-cookie").await;
    let r = app
        .send(req_bearer(
            "POST",
            "/api/v1/envs",
            "fo_good",
            Some(env_body("by-token")),
        ))
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let log = app
        .send(req("GET", "/api/v1/audit", None, Some(&admin)))
        .await;
    let rows = log.json.as_array().expect("audit rows");
    let token_row = rows
        .iter()
        .find(|e| e["action"] == "env.create" && e["token_name"] == "ci")
        .expect("a row made with the token");
    assert_eq!(token_row["username"], ADMIN);
    let cookie_row = rows
        .iter()
        .find(|e| e["action"] == "env.create" && e["token_name"].is_null())
        .expect("a row made with the cookie");
    assert_ne!(token_row["target_id"], cookie_row["target_id"]);
}

/// The newest audit row for `action`, once it is written.
async fn audited(app: &TestApp, action: &str) -> fleetops_store::AuditEntry {
    for _ in 0..200 {
        if let Some(e) = app
            .store
            .list_audit(100, None)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.action == action)
        {
            return e;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no {action} row");
}

#[tokio::test]
async fn background_work_is_tagged_with_the_token() {
    let (app, admin) = tokens_app().await;
    app.add_env(&admin, "local").await;
    app.fake.add(summary("c1", "web", "running", None));
    let r = app
        .send(req_bearer(
            "POST",
            "/api/v1/envs/local/containers/c1/recreate",
            "fo_good",
            Some(json!({"image": "nginx:2"})),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    let row = audited(&app, "container.recreate").await;
    assert_eq!(row.token_name.as_deref(), Some("ci"), "detached work");

    let r = app
        .send(req_bearer(
            "POST",
            "/api/v1/envs/local/images/pull",
            "fo_good",
            Some(json!({"image": "nginx:1.27"})),
        ))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.json);
    let row = audited(&app, "image.pull").await;
    assert_eq!(row.token_name.as_deref(), Some("ci"), "a task");
}

#[tokio::test]
async fn admin_tokens_cannot_create_users_or_change_passwords_and_roles() {
    let (app, admin) = tokens_app().await;
    let bob = app.create_user(&admin, "bob", "bob-password", "user").await;
    let bob_id = bob.json["id"].as_i64().unwrap();
    let me = app
        .store
        .find_credentials(ADMIN)
        .await
        .unwrap()
        .unwrap()
        .0
        .id;
    let create = app
        .send(req_bearer(
            "POST",
            "/api/v1/users",
            "fo_good",
            Some(json!({"username": "eve", "password": "eve-password", "role": "admin"})),
        ))
        .await;
    assert_eq!(create.status, StatusCode::FORBIDDEN, "{:?}", create.json);
    for (id, body) in [
        (me, json!({"password": "taken-over-pw"})),
        (bob_id, json!({"password": "taken-over-pw"})),
        (bob_id, json!({"role": "admin"})),
    ] {
        let r = app
            .send(req_bearer(
                "PATCH",
                &format!("/api/v1/users/{id}"),
                "fo_good",
                Some(body.clone()),
            ))
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{body}: {:?}", r.json);
    }
    // The admin's own session survived.
    let still = app
        .send(req("GET", "/api/v1/auth/me", None, Some(&admin)))
        .await;
    assert_eq!(still.status, StatusCode::OK);
}
