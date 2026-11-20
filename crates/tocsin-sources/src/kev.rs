//! CISA Known Exploited Vulnerabilities catalog (spec section 9.2: a listed
//! vulnerability is raised to `critical`).

use crate::cache::Cache;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub const URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CACHE_KEY: &str = "kev.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    pub date_added: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    /// "Known" or "Unknown".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_ransomware_campaign_use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulnerability_name: Option<String>,
}

impl Entry {
    pub fn used_by_ransomware(&self) -> bool {
        self.known_ransomware_campaign_use.as_deref() == Some("Known")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Feed {
    #[serde(default)]
    catalog_version: Option<String>,
    vulnerabilities: Vec<Entry>,
}

#[derive(Debug, Clone, Default)]
pub struct Catalog {
    pub version: Option<String>,
    entries: HashMap<String, Entry>,
    /// Set when the download failed and an older cached copy is used.
    pub stale: bool,
}

impl Catalog {
    pub fn from_json(text: &str) -> Result<Self> {
        let feed: Feed = serde_json::from_str(text).context("invalid KEV catalog")?;
        Ok(Catalog {
            version: feed.catalog_version,
            entries: feed
                .vulnerabilities
                .into_iter()
                .map(|e| (e.cve_id.clone(), e))
                .collect(),
            stale: false,
        })
    }

    pub fn get(&self, cve: &str) -> Option<&Entry> {
        self.entries.get(cve)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The cached catalog whatever its age, without any download. It is
    /// marked stale when older than `max_age`.
    pub fn from_cache(cache: &Cache, max_age: Duration) -> Option<Self> {
        let mut catalog = Catalog::from_json(&cache.get(CACHE_KEY)?).ok()?;
        catalog.stale = cache.age(CACHE_KEY).is_none_or(|age| age >= max_age);
        Some(catalog)
    }

    /// The catalog from the cache if younger than `max_age`, else downloaded.
    /// When the download fails, an older cached copy is used and marked stale.
    pub fn load(agent: &ureq::Agent, cache: Option<&Cache>, max_age: Duration) -> Result<Self> {
        if let Some(cache) = cache
            && cache.age(CACHE_KEY).is_some_and(|age| age < max_age)
            && let Some(catalog) = cache
                .get(CACHE_KEY)
                .and_then(|text| Catalog::from_json(&text).ok())
        {
            return Ok(catalog);
        }
        let downloaded = agent
            .get(URL)
            .call()
            .map_err(anyhow::Error::from)
            .and_then(|response| Ok(response.into_string()?));
        match downloaded {
            Ok(text) => {
                let catalog = Catalog::from_json(&text)?;
                if let Some(cache) = cache {
                    cache.put(CACHE_KEY, &text);
                }
                Ok(catalog)
            }
            Err(error) => {
                let mut catalog = cache
                    .and_then(|c| c.get(CACHE_KEY))
                    .and_then(|text| Catalog::from_json(&text).ok())
                    .ok_or(error)
                    .context("cannot download the CISA KEV catalog")?;
                catalog.stale = true;
                Ok(catalog)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_cisa_feed_format() {
        let feed = r#"{"title":"CISA Catalog of Known Exploited Vulnerabilities","catalogVersion":"2026.11.18","count":2,
            "vulnerabilities":[
              {"cveID":"CVE-2024-3094","vendorProject":"XZ","product":"XZ Utils","vulnerabilityName":"XZ Utils Embedded Malicious Code",
               "dateAdded":"2024-04-01","dueDate":"2024-04-22","knownRansomwareCampaignUse":"Unknown","cwes":["CWE-506"]},
              {"cveID":"CVE-2023-4966","dateAdded":"2023-10-18","knownRansomwareCampaignUse":"Known"}]}"#;
        let catalog = Catalog::from_json(feed).unwrap();
        assert_eq!(catalog.version.as_deref(), Some("2026.11.18"));
        assert_eq!(catalog.len(), 2);
        assert_eq!(
            catalog.get("CVE-2024-3094").unwrap().date_added,
            "2024-04-01"
        );
        assert!(!catalog.get("CVE-2024-3094").unwrap().used_by_ransomware());
        assert!(catalog.get("CVE-2023-4966").unwrap().used_by_ransomware());
        assert!(catalog.get("CVE-1999-0001").is_none());
    }
}
