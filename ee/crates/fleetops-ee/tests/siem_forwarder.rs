mod common;

use async_trait::async_trait;
use common::*;
use fleetops_core::{now_unix, Error, Result};
use fleetops_ee::siem::{
    db,
    forwarder::BATCH,
    model::{Sink, SinkKind, SinkSecrets, SinkSettings},
    send::Sender,
};
use fleetops_store::{AuditEntry, NewAudit};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

const DAY: i64 = 86_400;

/// Records each batch's ids; fails while `down` is set.
#[derive(Default)]
struct Rec {
    batches: Mutex<Vec<Vec<i64>>>,
    down: AtomicBool,
}

#[async_trait]
impl Sender for Rec {
    async fn send(&self, _: &Sink, _: &SinkSecrets, rows: &[AuditEntry]) -> Result<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(Error::Upstream {
                status: 502,
                message: "could not reach (siem.lan): refused".into(),
            });
        }
        self.batches
            .lock()
            .unwrap()
            .push(rows.iter().map(|r| r.id).collect());
        Ok(())
    }
}

impl Rec {
    fn sent(&self) -> Vec<i64> {
        self.batches.lock().unwrap().concat()
    }
}

struct Fx {
    ee: Ee,
    rec: Arc<Rec>,
    key: ed25519_dalek::SigningKey,
    admin: Session,
}

async fn fx() -> Fx {
    let key = key();
    let rec = Arc::new(Rec::default());
    let ee = ee_siem_app(&key, rec.clone()).await;
    let admin = ee.admin().await;
    ee.install(&admin, &license(&key, now_unix() + 30 * DAY, None, &[]))
        .await;
    Fx {
        ee,
        rec,
        key,
        admin,
    }
}

async fn rows(ee: &Ee, n: usize) -> Vec<i64> {
    let mut ids = vec![];
    for _ in 0..n {
        ids.push(
            ee.store
                .insert_audit(&NewAudit {
                    ts: now_unix(),
                    user_id: None,
                    environment_id: None,
                    action: "x.y",
                    target_type: None,
                    target_id: None,
                    result: "success",
                    detail: None,
                })
                .await
                .unwrap(),
        );
    }
    ids
}

async fn newest(ee: &Ee) -> i64 {
    ee.store.list_audit(1, None).await.unwrap()[0].id
}

/// A sink that starts after every row written so far.
async fn sink_now(ee: &Ee) -> i64 {
    let cursor = newest(ee).await;
    db::create(
        &ee.store,
        "siem",
        SinkKind::Http,
        true,
        &SinkSettings {
            url: Some("https://siem.lan/in".into()),
            ..Default::default()
        },
        &SinkSecrets::default(),
        cursor,
        0,
    )
    .await
    .unwrap()
}

async fn tick(f: &Fx, now: i64) {
    f.ee.forwarder.tick(&f.ee.state, now).await.unwrap();
}

#[tokio::test]
async fn forwards_new_rows_in_order_and_advances() {
    let f = fx().await;
    let id = sink_now(&f.ee).await;
    let ids = rows(&f.ee, 3).await;
    tick(&f, 100).await;
    assert_eq!(f.rec.sent(), ids);
    let sink = db::get(&f.ee.store, id).await.unwrap().0;
    assert_eq!(sink.cursor, ids[2]);
    assert_eq!(sink.last_sent_at, Some(100));
    tick(&f, 101).await;
    assert_eq!(
        f.rec.batches.lock().unwrap().len(),
        1,
        "nothing new to send"
    );
}

#[tokio::test]
async fn sends_in_batches_until_caught_up() {
    let f = fx().await;
    sink_now(&f.ee).await;
    let ids = rows(&f.ee, BATCH as usize * 2 + 200).await;
    tick(&f, 100).await;
    let sizes: Vec<usize> = f.rec.batches.lock().unwrap().iter().map(Vec::len).collect();
    assert_eq!(sizes, vec![BATCH as usize, BATCH as usize, 200]);
    assert_eq!(f.rec.sent(), ids);
}

#[tokio::test]
async fn failure_keeps_cursor_and_backs_off() {
    let f = fx().await;
    let id = sink_now(&f.ee).await;
    let start = newest(&f.ee).await;
    let ids = rows(&f.ee, 2).await;
    f.rec.down.store(true, Ordering::SeqCst);
    tick(&f, 100).await;
    let sink = db::get(&f.ee.store, id).await.unwrap().0;
    assert_eq!(sink.cursor, start);
    assert_eq!(
        sink.last_error.as_deref(),
        Some("could not reach (siem.lan): refused")
    );
    assert_eq!(sink.last_error_at, Some(100));

    f.rec.down.store(false, Ordering::SeqCst);
    tick(&f, 105).await;
    assert!(f.rec.sent().is_empty(), "still backing off");
    tick(&f, 110).await;
    assert_eq!(f.rec.sent(), ids, "the same rows, retried");
    let sink = db::get(&f.ee.store, id).await.unwrap().0;
    assert_eq!(sink.last_error, None);
}

#[tokio::test]
async fn backoff_doubles_to_five_minutes() {
    let f = fx().await;
    sink_now(&f.ee).await;
    rows(&f.ee, 1).await;
    f.rec.down.store(true, Ordering::SeqCst);
    let mut at = 0;
    let mut gaps = vec![];
    for _ in 0..7 {
        // Find the next attempt: the first second at which last_error_at moves.
        let before = db::list(&f.ee.store).await.unwrap()[0].last_error_at;
        let mut t = at;
        loop {
            tick(&f, t).await;
            if db::list(&f.ee.store).await.unwrap()[0].last_error_at != before {
                break;
            }
            t += 1;
        }
        gaps.push(t - at);
        at = t;
    }
    assert_eq!(gaps, vec![0, 10, 20, 40, 80, 160, 300]);
}

#[tokio::test]
async fn pruned_rows_count_as_a_gap() {
    let f = fx().await;
    let id = sink_now(&f.ee).await;
    let ids = rows(&f.ee, 5).await;
    sqlx::query("DELETE FROM audit_log WHERE id < ?")
        .bind(ids[3])
        .execute(f.ee.store.pool())
        .await
        .unwrap();
    tick(&f, 100).await;
    assert_eq!(f.rec.sent(), ids[3..].to_vec());
    let sink = db::get(&f.ee.store, id).await.unwrap().0;
    assert_eq!(sink.gap_rows, 3);
}

#[tokio::test]
async fn disabled_sink_is_skipped() {
    let f = fx().await;
    let id = sink_now(&f.ee).await;
    let (sink, _) = db::get(&f.ee.store, id).await.unwrap();
    db::update(&f.ee.store, id, &sink.name, false, &sink.settings, None, 1)
        .await
        .unwrap();
    rows(&f.ee, 2).await;
    tick(&f, 100).await;
    assert!(f.rec.sent().is_empty());
}

#[tokio::test]
async fn unlicensed_sends_nothing_then_resumes() {
    let f = fx().await;
    let id = sink_now(&f.ee).await;
    let start = newest(&f.ee).await;
    f.ee.send("DELETE", "/api/v1/ee/license", None, Some(&f.admin))
        .await;
    rows(&f.ee, 2).await;
    tick(&f, 100).await;
    assert!(f.rec.sent().is_empty());
    assert_eq!(db::get(&f.ee.store, id).await.unwrap().0.cursor, start);
    f.ee.install(&f.admin, &license(&f.key, now_unix() + 30 * DAY, None, &[]))
        .await;
    tick(&f, 101).await;
    // The license.remove and license.update rows go too: everything after the cursor.
    let sent = f.rec.sent();
    assert_eq!(sent.first(), Some(&(start + 1)));
    assert_eq!(sent.last(), Some(&newest(&f.ee).await));
}

#[tokio::test]
async fn sinks_progress_independently() {
    let f = fx().await;
    let a = sink_now(&f.ee).await;
    let cursor = newest(&f.ee).await;
    let b = db::create(
        &f.ee.store,
        "second",
        SinkKind::Http,
        true,
        &SinkSettings {
            url: Some("https://other.lan/in".into()),
            ..Default::default()
        },
        &SinkSecrets::default(),
        cursor,
        0,
    )
    .await
    .unwrap();
    let ids = rows(&f.ee, 2).await;
    tick(&f, 100).await;
    assert_eq!(f.rec.sent(), [ids.clone(), ids.clone()].concat());
    for id in [a, b] {
        assert_eq!(db::get(&f.ee.store, id).await.unwrap().0.cursor, ids[1]);
    }
}
