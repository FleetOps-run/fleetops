//! Port-forward tickets and credentials, kept in memory (a restart voids
//! them). A ticket is minted in the browser and redeemed once by
//! `fleetops-cli` for a credential; each local TCP connection then opens a
//! stream with that credential. Only SHA-256 hashes are kept.

use crate::auth::token::{generate_token, hash_token};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

pub const TICKET_PREFIX: &str = "fpt_";
pub const CREDENTIAL_PREFIX: &str = "fpc_";
/// A ticket must be redeemed within this long.
pub const TICKET_SECS: i64 = 300;
/// A credential works for this long after redeem.
pub const CREDENTIAL_SECS: i64 = 8 * 3600;
/// Concurrent streams per credential.
pub const MAX_STREAMS: usize = 16;
/// Live credentials per user; the oldest goes first.
pub const MAX_PER_USER: usize = 10;
/// The default re-check interval (`ApiConfig::forward_recheck`).
pub const RECHECK: Duration = Duration::from_secs(60);
/// The header `fleetops-cli` sends the credential in. Browsers cannot set
/// it on a websocket, so a page elsewhere cannot open a stream.
pub const FORWARD_HEADER: &str = "x-fleetops-forward";

/// What a ticket or credential reaches, and for whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub user_id: i64,
    pub env_id: i64,
    pub env: String,
    pub ns: String,
    pub pod: String,
    pub port: u16,
}

struct Entry {
    target: Target,
    expires_at: i64,
    created_at: i64,
    /// Credentials only: open streams.
    streams: Arc<()>,
}

#[derive(Default)]
pub struct Forwards {
    tickets: Mutex<HashMap<String, Entry>>,
    credentials: Mutex<HashMap<String, Entry>>,
}

fn prune(map: &mut HashMap<String, Entry>, now: i64) {
    map.retain(|_, e| e.expires_at > now);
}

/// Holds one stream slot; dropping it frees the slot.
pub struct StreamGuard(#[allow(dead_code)] Arc<()>);

impl Forwards {
    /// A new single-use ticket for `t`, valid for [`TICKET_SECS`].
    pub fn mint(&self, t: Target, now: i64) -> String {
        let ticket = format!("{TICKET_PREFIX}{}", generate_token());
        let mut map = self.tickets.lock().expect("forward lock");
        prune(&mut map, now);
        map.insert(
            hash_token(&ticket),
            Entry {
                target: t,
                expires_at: now + TICKET_SECS,
                created_at: now,
                streams: Arc::new(()),
            },
        );
        ticket
    }

    /// Consumes `ticket`: a credential, its target and when it expires.
    pub fn redeem(&self, ticket: &str, now: i64) -> Option<(String, Target, i64)> {
        let entry = {
            let mut map = self.tickets.lock().expect("forward lock");
            prune(&mut map, now);
            map.remove(&hash_token(ticket))?
        };
        let credential = format!("{CREDENTIAL_PREFIX}{}", generate_token());
        let expires_at = now + CREDENTIAL_SECS;
        let mut map = self.credentials.lock().expect("forward lock");
        prune(&mut map, now);
        let user = entry.target.user_id;
        let mut mine: Vec<(String, i64)> = map
            .iter()
            .filter(|(_, e)| e.target.user_id == user)
            .map(|(k, e)| (k.clone(), e.created_at))
            .collect();
        if mine.len() >= MAX_PER_USER {
            mine.sort_by_key(|m| m.1);
            for (k, _) in mine.iter().take(mine.len() + 1 - MAX_PER_USER) {
                map.remove(k);
            }
        }
        map.insert(
            hash_token(&credential),
            Entry {
                target: entry.target.clone(),
                expires_at,
                created_at: now,
                streams: Arc::new(()),
            },
        );
        Some((credential, entry.target, expires_at))
    }

    /// A live credential's target and expiry.
    pub fn lookup(&self, credential: &str, now: i64) -> Option<(Target, i64)> {
        let mut map = self.credentials.lock().expect("forward lock");
        prune(&mut map, now);
        map.get(&hash_token(credential))
            .map(|e| (e.target.clone(), e.expires_at))
    }

    /// A stream slot on `credential`; `None` when [`MAX_STREAMS`] are open
    /// or the credential is gone.
    pub fn open_stream(&self, credential: &str) -> Option<StreamGuard> {
        let map = self.credentials.lock().expect("forward lock");
        let e = map.get(&hash_token(credential))?;
        // The map holds one reference; each open stream holds another.
        if Arc::strong_count(&e.streams) > MAX_STREAMS {
            return None;
        }
        Some(StreamGuard(e.streams.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(user: i64) -> Target {
        Target {
            user_id: user,
            env_id: 1,
            env: "k".into(),
            ns: "apps".into(),
            pod: "db".into(),
            port: 5432,
        }
    }

    #[test]
    fn ticket_expires() {
        let f = Forwards::default();
        let tk = f.mint(t(1), 100);
        assert!(tk.starts_with("fpt_"));
        assert!(f.redeem(&tk, 100 + TICKET_SECS + 1).is_none());
    }

    #[test]
    fn redeem_is_single_use() {
        let f = Forwards::default();
        let tk = f.mint(t(1), 100);
        let (cred, target, exp) = f.redeem(&tk, 101).unwrap();
        assert!(cred.starts_with("fpc_"));
        assert_eq!(target, t(1));
        assert_eq!(exp, 101 + CREDENTIAL_SECS);
        assert!(f.redeem(&tk, 102).is_none());
        assert_eq!(f.lookup(&cred, 102).unwrap().0, t(1));
        assert!(f.lookup(&cred, exp).is_none(), "expired");
    }

    #[test]
    fn oldest_credential_goes_past_the_per_user_limit() {
        let f = Forwards::default();
        let creds: Vec<String> = (0..=MAX_PER_USER as i64)
            .map(|i| f.redeem(&f.mint(t(1), i), i).unwrap().0)
            .collect();
        assert!(f.lookup(&creds[0], 20).is_none());
        assert!(f.lookup(&creds[1], 20).is_some());
        let other = f.redeem(&f.mint(t(2), 0), 0).unwrap().0;
        assert!(f.lookup(&other, 20).is_some(), "other users unaffected");
    }

    #[test]
    fn stream_slots_are_limited_and_freed() {
        let f = Forwards::default();
        let cred = f.redeem(&f.mint(t(1), 0), 0).unwrap().0;
        let mut held: Vec<_> = (0..MAX_STREAMS)
            .map(|_| f.open_stream(&cred).unwrap())
            .collect();
        assert!(f.open_stream(&cred).is_none());
        held.pop();
        assert!(f.open_stream(&cred).is_some());
    }
}
