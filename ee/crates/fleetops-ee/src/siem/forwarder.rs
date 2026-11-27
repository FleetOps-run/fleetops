//! Sends every audit row to every enabled sink, in id order, at least once.
//! A sink's cursor moves only after the receiver took the batch; a failing
//! sink is retried with backoff (10 s, doubling to 5 min).

use super::{
    db,
    send::{LiveSender, Sender},
};
use fleetops_api::AppState;
use fleetops_core::{edition::Feature, now_unix, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Rows per send.
pub const BATCH: i64 = 500;
/// Batches one sink sends per pass before the next sink gets a turn.
pub const MAX_BATCHES_PER_TICK: usize = 20;
const FIRST_DELAY: i64 = 10;
const MAX_DELAY: i64 = 300;
const POLL: Duration = Duration::from_secs(10);
/// New rows usually come in bursts; wait this long to batch them.
const DEBOUNCE: Duration = Duration::from_secs(1);

pub struct Forwarder {
    sender: Arc<dyn Sender>,
    /// Per sink: when to try again, and the delay after the next failure.
    backoff: Mutex<HashMap<i64, (i64, i64)>>,
    /// One pass at a time.
    pass: tokio::sync::Mutex<()>,
}

impl Forwarder {
    pub fn new(sender: Option<Arc<dyn Sender>>) -> Arc<Self> {
        Arc::new(Forwarder {
            sender: sender.unwrap_or_else(|| Arc::new(LiveSender::default())),
            backoff: Mutex::default(),
            pass: tokio::sync::Mutex::new(()),
        })
    }

    pub fn sender(&self) -> &Arc<dyn Sender> {
        &self.sender
    }

    /// Runs forever: a pass on new audit rows (debounced) and every 10 s.
    pub async fn run(self: Arc<Self>, s: AppState) {
        let mut feed = s.store.audit_feed();
        let mut poll = tokio::time::interval(POLL);
        loop {
            tokio::select! {
                _ = poll.tick() => {}
                r = feed.recv() => {
                    if matches!(r, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                        return;
                    }
                    tokio::time::sleep(DEBOUNCE).await;
                    while feed.try_recv().is_ok() {}
                }
            }
            if let Err(e) = self.tick(&s, now_unix()).await {
                tracing::warn!(error = %e, "audit forwarding pass failed");
            }
        }
    }

    fn due(&self, id: i64, now: i64) -> bool {
        self.backoff
            .lock()
            .expect("backoff lock")
            .get(&id)
            .is_none_or(|(at, _)| now >= *at)
    }

    fn failed(&self, id: i64, now: i64) {
        let mut b = self.backoff.lock().expect("backoff lock");
        let delay = b.get(&id).map_or(FIRST_DELAY, |(_, d)| *d);
        b.insert(id, (now + delay, (delay * 2).min(MAX_DELAY)));
    }

    /// Forgets a deleted sink's backoff.
    pub fn forget(&self, id: i64) {
        self.backoff.lock().expect("backoff lock").remove(&id);
    }

    /// Sends one sink's backlog, up to [`MAX_BATCHES_PER_TICK`] batches. The
    /// sink is read again before every batch, so an edit applies to the next
    /// batch and a delete or disable stops it.
    async fn drain(&self, s: &AppState, id: i64, now: i64) -> Result<()> {
        for _ in 0..MAX_BATCHES_PER_TICK {
            let (sink, secrets) = match db::get(&s.store, id).await {
                Ok(x) => x,
                Err(fleetops_core::Error::NotFound(_)) => return Ok(()),
                Err(e) => {
                    db::fail(&s.store, id, &e.to_string(), now).await?;
                    self.failed(id, now);
                    return Ok(());
                }
            };
            if !sink.enabled {
                return Ok(());
            }
            let rows = match s.store.audit_range(None, None, sink.cursor, BATCH).await {
                Ok(r) => r,
                Err(e) => {
                    db::fail(&s.store, id, &e.to_string(), now).await?;
                    self.failed(id, now);
                    return Ok(());
                }
            };
            let Some(last) = rows.last().map(|r| r.id) else {
                return Ok(());
            };
            // Rows are only ever removed oldest first, so a hole after the
            // cursor is rows retention took before this sink sent them.
            let gap = (rows[0].id - sink.cursor - 1).max(0);
            match self.sender.send(&sink, &secrets, &rows).await {
                Ok(()) => {
                    db::advance(&s.store, id, last, gap, now).await?;
                    self.succeeded(id);
                }
                Err(e) => {
                    let msg = match e {
                        fleetops_core::Error::Upstream { message, .. } => message,
                        other => other.to_string(),
                    };
                    db::fail(&s.store, id, &msg, now).await?;
                    self.failed(id, now);
                    return Ok(());
                }
            }
            if (rows.len() as i64) < BATCH {
                return Ok(());
            }
        }
        Ok(())
    }

    fn succeeded(&self, id: i64) {
        self.backoff.lock().expect("backoff lock").remove(&id);
    }

    /// One pass over every enabled sink that is due. Nothing is sent while
    /// the license does not cover audit forwarding; cursors hold.
    pub async fn tick(&self, s: &AppState, now: i64) -> Result<()> {
        let _one = self.pass.lock().await;
        if !s.entitlements.has(Feature::AuditSinks) {
            return Ok(());
        }
        for sink in db::list(&s.store).await? {
            if !sink.enabled || !self.due(sink.id, now) {
                continue;
            }
            self.drain(s, sink.id, now).await?;
        }
        Ok(())
    }
}
