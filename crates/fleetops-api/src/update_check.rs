//! Tells admins when a newer FleetOps release is out. The server asks a
//! [`ReleaseSource`] (GitHub, supplied by the server crate) once a day; the
//! request carries nothing about this install. `--update-check false`
//! turns it off.

use std::sync::RwLock;

/// Parses `vX.Y.Z` or `X.Y.Z`; anything else (prereleases included) is `None`.
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.strip_prefix('v').unwrap_or(s).split('.');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let v = (next()?, next()?, next()?);
    parts.next().is_none().then_some(v)
}

/// Whether `latest` is a newer release than `current`. Unparseable versions
/// are never newer.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// A published release: its tag (`v1.6.0`) and its page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub url: String,
}

/// Where the newest release is looked up; GitHub in the server.
#[async_trait::async_trait]
pub trait ReleaseSource: Send + Sync {
    async fn latest(&self) -> Result<Release, String>;
}

/// The newest release seen and when (unix seconds); empty until the first
/// successful check.
#[derive(Default)]
pub struct UpdateStatus {
    latest: RwLock<Option<(Release, i64)>>,
}

impl UpdateStatus {
    pub fn record(&self, r: Release) {
        *self.latest.write().unwrap_or_else(|e| e.into_inner()) =
            Some((r, fleetops_core::now_unix()));
    }

    pub fn get(&self) -> Option<(Release, i64)> {
        self.latest
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v_prefix() {
        assert_eq!(parse_version("v1.5.0"), Some((1, 5, 0)));
        assert_eq!(parse_version("1.5.0"), Some((1, 5, 0)));
    }

    #[test]
    fn newer_minor_and_patch() {
        assert!(is_newer("v1.6.0", "1.5.0"));
        assert!(is_newer("v1.5.1", "1.5.0"));
        assert!(is_newer("v2.0.0", "1.9.9"));
        assert!(is_newer("v1.10.0", "1.9.0"));
    }

    #[test]
    fn older_or_equal_is_not_newer() {
        assert!(!is_newer("v1.5.0", "1.5.0"));
        assert!(!is_newer("v1.5.0", "1.6.0"));
    }

    #[test]
    fn ignores_unparseable() {
        assert!(!is_newer("v1.6.0-rc1", "1.5.0"));
        assert!(!is_newer("latest", "1.5.0"));
        assert!(!is_newer("v1.6", "1.5.0"));
        assert!(!is_newer("v1.6.0.1", "1.5.0"));
    }
}
