mod common;

use axum::http::StatusCode;
use common::*;
use fleetops_api::update_check::{check_once, Release, ReleaseSource, UpdateStatus};
use std::sync::Mutex;

#[tokio::test]
async fn version_requires_admin() {
    let app = app().await;
    let admin = app.setup_admin().await;
    app.create_user(&admin, "bob", "bob-password", "user").await;
    let bob = session_from(&app.login("bob", "bob-password").await);
    let r = app
        .send(req("GET", "/api/v1/system/version", None, Some(&bob)))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn version_reports_current_without_check() {
    let app = app().await;
    let admin = app.setup_admin().await;
    let r = app
        .send(req("GET", "/api/v1/system/version", None, Some(&admin)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["current"], env!("CARGO_PKG_VERSION"));
    assert_eq!(r.json["update_available"], false);
    assert!(r.json["latest"].is_null());
    assert!(r.json["checked_at"].is_null());
    assert_eq!(r.json["check_enabled"], false);
}

#[tokio::test]
async fn version_reports_newer_release() {
    let app = app().await;
    let admin = app.setup_admin().await;
    app.state.update.record(Release {
        tag: "v99.0.0".into(),
        url: "https://x/r".into(),
    });
    let r = app
        .send(req("GET", "/api/v1/system/version", None, Some(&admin)))
        .await;
    assert_eq!(r.json["update_available"], true);
    assert_eq!(r.json["latest"], "v99.0.0");
    assert_eq!(r.json["release_url"], "https://x/r");
    assert!(r.json["checked_at"].as_i64().unwrap() > 0);
}

/// Answers each `latest()` with the next queued result.
struct Scripted(Mutex<Vec<Result<Release, String>>>);

#[async_trait::async_trait]
impl ReleaseSource for Scripted {
    async fn latest(&self) -> Result<Release, String> {
        self.0.lock().unwrap().remove(0)
    }
}

#[tokio::test]
async fn failure_keeps_last_result() {
    let release = Release {
        tag: "v99.0.0".into(),
        url: "https://x/r".into(),
    };
    let source = Scripted(Mutex::new(vec![
        Ok(release.clone()),
        Err("rate limited".into()),
    ]));
    let status = UpdateStatus::default();
    check_once(&status, &source).await;
    check_once(&status, &source).await;
    assert_eq!(status.get().map(|(r, _)| r), Some(release));
}
