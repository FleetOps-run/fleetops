mod common;

use async_trait::async_trait;
use axum::http::StatusCode;
use common::*;
use fleetops_core::{now_unix, Error, Result};
use fleetops_ee::siem::{
    model::{Sink, SinkSecrets},
    send::Sender,
};
use fleetops_store::AuditEntry;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

const DAY: i64 = 86_400;
const BASE: &str = "/api/v1/ee/audit/sinks";

/// One send: sink name, token, and the rows' actions.
type Sent = (String, Option<String>, Vec<String>);

#[derive(Default)]
struct Rec {
    seen: Mutex<Vec<Sent>>,
    down: AtomicBool,
}

#[async_trait]
impl Sender for Rec {
    async fn send(&self, sink: &Sink, sec: &SinkSecrets, rows: &[AuditEntry]) -> Result<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(Error::Upstream {
                status: 502,
                message: "answered 403 (splunk.example): Invalid token".into(),
            });
        }
        self.seen.lock().unwrap().push((
            sink.name.clone(),
            sec.token.clone(),
            rows.iter().map(|r| r.action.clone()).collect(),
        ));
        Ok(())
    }
}

fn body(v: Value) -> Option<(&'static str, String)> {
    Some(("application/json", v.to_string()))
}

struct Fx {
    ee: Ee,
    rec: Arc<Rec>,
    admin: Session,
    bob: Session,
}

async fn fx() -> Fx {
    let key = key();
    let rec = Arc::new(Rec::default());
    let ee = ee_siem_app(&key, rec.clone()).await;
    let admin = ee.admin().await;
    let r = ee
        .install(&admin, &license(&key, now_unix() + 30 * DAY, None, &[]))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    ee.user(&admin, "bob").await;
    let bob = ee.login("bob").await;
    Fx {
        ee,
        rec,
        admin,
        bob,
    }
}

fn hec(name: &str) -> Value {
    json!({
        "name": name,
        "kind": "splunk_hec",
        "url": "https://splunk.example:8088/services/collector/event",
        "token": "t0ken-secret",
    })
}

async fn create(f: &Fx, v: Value) -> Resp {
    f.ee.send("POST", BASE, body(v), Some(&f.admin)).await
}

#[tokio::test]
async fn crud_and_no_secrets_in_views() {
    let f = fx().await;
    let r = create(&f, hec("splunk")).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let v = r.json();
    let id = v["id"].as_i64().unwrap();
    assert_eq!(v["kind"], "splunk_hec");
    assert_eq!(v["target"], "splunk.example");
    assert_eq!(v["token_set"], true);
    assert_eq!(v["enabled"], true);

    let syslog = create(
        &f,
        json!({"name": "rsyslog", "kind": "syslog", "host": "siem.lan", "port": 6514, "transport": "tls"}),
    )
    .await;
    assert_eq!(syslog.status, StatusCode::CREATED, "{}", syslog.text);
    assert_eq!(syslog.json()["target"], "siem.lan:6514");

    // An empty token keeps the stored one.
    let r = f
        .ee
        .send(
            "PUT",
            &format!("{BASE}/{id}"),
            body(json!({"name": "splunk-prod", "kind": "splunk_hec",
                "url": "https://splunk.example:8088/services/collector/event", "token": "", "enabled": false})),
            Some(&f.admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.json()["name"], "splunk-prod");
    assert_eq!(r.json()["enabled"], false);
    let (_, sec) = fleetops_ee::siem::db::get(&f.ee.store, id).await.unwrap();
    assert_eq!(sec.token.as_deref(), Some("t0ken-secret"));

    let list = f.ee.send("GET", BASE, None, Some(&f.admin)).await;
    assert_eq!(list.json().as_array().unwrap().len(), 2);
    assert!(!list.text.contains("t0ken-secret"));

    let del =
        f.ee.send("DELETE", &format!("{BASE}/{id}"), None, Some(&f.admin))
            .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);

    let log = f.ee.store.list_audit(100, None).await.unwrap();
    for a in [
        "audit.sink.create",
        "audit.sink.update",
        "audit.sink.delete",
    ] {
        assert!(log.iter().any(|e| e.action == a), "{a}");
    }
    let all = serde_json::to_string(&log).unwrap();
    assert!(
        !all.contains("t0ken-secret"),
        "a secret reached the audit log"
    );
}

#[tokio::test]
async fn http_headers_keep_stored_values_when_blank() {
    let f = fx().await;
    let r = create(
        &f,
        json!({"name": "dd", "kind": "http", "url": "https://http-intake.logs.datadoghq.com/api/v2/logs",
            "headers": [{"name": "DD-API-KEY", "value": "k3y"}]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    assert_eq!(r.json()["header_names"], json!(["DD-API-KEY"]));
    let id = r.json()["id"].as_i64().unwrap();
    let r = f
        .ee
        .send(
            "PUT",
            &format!("{BASE}/{id}"),
            body(json!({"name": "dd", "kind": "http", "url": "https://http-intake.logs.datadoghq.com/api/v2/logs",
                "headers": [{"name": "DD-API-KEY", "value": ""}, {"name": "X-Env", "value": "prod"}]})),
            Some(&f.admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let (_, sec) = fleetops_ee::siem::db::get(&f.ee.store, id).await.unwrap();
    assert_eq!(
        sec.headers,
        vec![
            ("DD-API-KEY".into(), "k3y".into()),
            ("X-Env".into(), "prod".into())
        ]
    );
}

#[tokio::test]
async fn invalid_bodies_are_400() {
    let f = fx().await;
    for bad in [
        json!({"name": "x", "kind": "splunk_hec", "url": "https://s.example/x"}),
        json!({"name": "x", "kind": "http", "url": "http://plain.example/x"}),
        json!({"name": "", "kind": "syslog", "host": "h", "port": 514, "transport": "udp"}),
        json!({"name": "x", "kind": "syslog", "host": "h", "transport": "udp"}),
    ] {
        let r = create(&f, bad.clone()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", r.text);
    }
    create(&f, hec("dup")).await;
    assert_eq!(create(&f, hec("dup")).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn eleventh_sink_is_409() {
    let f = fx().await;
    for i in 0..10 {
        let r = create(&f, hec(&format!("s{i}"))).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    }
    let r = create(&f, hec("s10")).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.text);
}

#[tokio::test]
async fn non_admin_403() {
    let f = fx().await;
    assert_eq!(
        f.ee.send("GET", BASE, None, Some(&f.bob)).await.status,
        StatusCode::FORBIDDEN
    );
    let r = f.ee.send("POST", BASE, body(hec("x")), Some(&f.bob)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r =
        f.ee.send("GET", "/api/v1/ee/audit/retention", None, Some(&f.bob))
            .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unlicensed_create_403_but_delete_works() {
    let f = fx().await;
    let id = create(&f, hec("splunk")).await.json()["id"]
        .as_i64()
        .unwrap();
    f.ee.send("DELETE", "/api/v1/ee/license", None, Some(&f.admin))
        .await;
    let r = create(&f, hec("other")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.json()["code"], "license_required");
    let list = f.ee.send("GET", BASE, None, Some(&f.admin)).await;
    assert_eq!(list.status, StatusCode::OK, "frozen sinks stay visible");
    let del =
        f.ee.send("DELETE", &format!("{BASE}/{id}"), None, Some(&f.admin))
            .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn start_now_skips_history_and_all_sends_it() {
    let f = fx().await;
    let now = create(&f, hec("now")).await.json();
    // Only its own audit.sink.create row, written after the cursor was set.
    assert_eq!(now["behind"], 1);
    let mut all = hec("all");
    all["start"] = json!("all");
    let all = create(&f, all).await.json();
    assert!(all["behind"].as_i64().unwrap() >= 2, "{all}");
    f.ee.forwarder.tick(&f.ee.state, now_unix()).await.unwrap();
    let seen = f.rec.seen.lock().unwrap();
    let sent = |name: &str| {
        seen.iter()
            .filter(|s| s.0 == name)
            .flat_map(|s| s.2.clone())
            .collect::<Vec<_>>()
    };
    assert!(sent("all").contains(&"license.update".to_string()));
    assert!(!sent("now").contains(&"license.update".to_string()));
}

#[tokio::test]
async fn test_endpoint_sends_one_row_and_reports_errors() {
    let f = fx().await;
    let id = create(&f, hec("splunk")).await.json()["id"]
        .as_i64()
        .unwrap();
    let before = f.ee.store.list_audit(1, None).await.unwrap()[0].id;
    let r =
        f.ee.send("POST", &format!("{BASE}/{id}/test"), None, Some(&f.admin))
            .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    {
        let seen = f.rec.seen.lock().unwrap();
        assert_eq!(seen.last().unwrap().1.as_deref(), Some("t0ken-secret"));
        assert_eq!(seen.last().unwrap().2, vec!["audit.sink.test".to_string()]);
    }
    let after = f.ee.store.list_audit(1, None).await.unwrap()[0].id;
    assert_eq!(
        before, after,
        "the test row is not written to the audit log"
    );

    f.rec.down.store(true, Ordering::SeqCst);
    let r =
        f.ee.send("POST", &format!("{BASE}/{id}/test"), None, Some(&f.admin))
            .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text);
    assert!(r.json()["message"]
        .as_str()
        .unwrap()
        .contains("splunk.example"));
}

#[tokio::test]
async fn behind_counts_unsent_rows() {
    let f = fx().await;
    let id = create(&f, hec("splunk")).await.json()["id"]
        .as_i64()
        .unwrap();
    for _ in 0..3 {
        f.ee.user(&f.admin, &format!("u{}", rand::random::<u32>()))
            .await;
    }
    let list = f.ee.send("GET", BASE, None, Some(&f.admin)).await;
    let row = list
        .json()
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == id)
        .unwrap()
        .clone();
    assert_eq!(row["behind"], 4, "its own create row and three users");
}

#[tokio::test]
async fn retention_round_trip_and_bounds() {
    let f = fx().await;
    let r =
        f.ee.send("GET", "/api/v1/ee/audit/retention", None, Some(&f.admin))
            .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.json(), json!({"days": 90, "default_days": 90}));
    for bad in [0, 3651] {
        let r =
            f.ee.send(
                "PUT",
                "/api/v1/ee/audit/retention",
                body(json!({"days": bad})),
                Some(&f.admin),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r =
        f.ee.send(
            "PUT",
            "/api/v1/ee/audit/retention",
            body(json!({"days": 365})),
            Some(&f.admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.json()["days"], 365);
    assert_eq!(f.ee.store.audit_retention_days().await.unwrap(), 365);
    assert!(f
        .ee
        .actions()
        .await
        .contains(&"audit.retention.update".to_string()));
}
