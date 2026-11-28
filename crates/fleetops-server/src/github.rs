//! The update check's release source: GitHub's newest published release
//! (drafts and prereleases excluded). The request sends only a generic
//! `fleetops/<version>` user agent.

use fleetops_api::update_check::{Release, ReleaseSource};
use std::time::Duration;

pub const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/FleetOps-run/fleetops/releases/latest";

pub struct GitHubReleases {
    client: reqwest::Client,
}

impl GitHubReleases {
    pub fn new() -> anyhow::Result<Self> {
        crate::tls::install_crypto_provider();
        let client = reqwest::Client::builder()
            .user_agent(concat!("fleetops/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { client })
    }
}

#[derive(serde::Deserialize)]
struct LatestRelease {
    tag_name: String,
    html_url: String,
}

#[async_trait::async_trait]
impl ReleaseSource for GitHubReleases {
    async fn latest(&self) -> Result<Release, String> {
        let r: LatestRelease = self
            .client
            .get(LATEST_RELEASE_URL)
            .header("accept", "application/vnd.github+json")
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(Release {
            tag: r.tag_name,
            url: r.html_url,
        })
    }
}
