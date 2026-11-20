//! OSV.dev client: batch queries, pagination, and full advisories fetched in
//! parallel with an on-disk cache keyed by modification date.

use crate::cache::Cache;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tocsin_core::Advisory;

pub const API: &str = "https://api.osv.dev/v1";
/// Maximum number of queries per `querybatch` request, set by OSV.dev.
const BATCH_SIZE: usize = 1000;

/// What to ask OSV.dev about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Query {
    /// A purl including its version, for language ecosystems (npm, crates.io, PyPI…).
    Purl(String),
    /// A distribution package, with the release-specific ecosystem
    /// (`Ubuntu:26.04:LTS`) so that other releases do not match.
    Package {
        ecosystem: String,
        name: String,
        version: String,
    },
}

impl Query {
    fn to_json(&self, page_token: Option<&str>) -> Value {
        let mut query = match self {
            Query::Purl(purl) => json!({ "package": { "purl": purl } }),
            Query::Package {
                ecosystem,
                name,
                version,
            } => {
                json!({ "package": { "ecosystem": ecosystem, "name": name }, "version": version })
            }
        };
        if let Some(token) = page_token {
            query["page_token"] = json!(token);
        }
        query
    }
}

/// A vulnerability matched by a query, as returned by `querybatch`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct VulnRef {
    pub id: String,
    #[serde(default)]
    pub modified: String,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
    #[serde(default)]
    next_page_token: Option<String>,
}

pub struct Client {
    agent: ureq::Agent,
    base: String,
    cache: Option<Cache>,
}

/// Advisory identifiers are used in URLs and cache file names.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

impl Client {
    pub fn new(agent: ureq::Agent, cache: Option<Cache>) -> Self {
        Client {
            agent,
            base: API.to_owned(),
            cache,
        }
    }

    /// Vulnerabilities matching each query, in the order of `queries`.
    pub fn query_batch(&self, queries: &[Query]) -> Result<Vec<Vec<VulnRef>>> {
        let mut results = vec![Vec::new(); queries.len()];
        for (chunk_index, chunk) in queries.chunks(BATCH_SIZE).enumerate() {
            let offset = chunk_index * BATCH_SIZE;
            let mut pending: Vec<(usize, Option<String>)> =
                (0..chunk.len()).map(|i| (offset + i, None)).collect();
            while !pending.is_empty() {
                let body = json!({
                    "queries": pending.iter().map(|(i, token)| queries[*i].to_json(token.as_deref())).collect::<Vec<_>>()
                });
                let response: BatchResponse = self
                    .agent
                    .post(&format!("{}/querybatch", self.base))
                    .send_json(body)
                    .context("OSV.dev querybatch request failed")?
                    .into_json()
                    .context("invalid OSV.dev querybatch response")?;
                if response.results.len() != pending.len() {
                    bail!(
                        "OSV.dev returned {} results for {} queries",
                        response.results.len(),
                        pending.len()
                    );
                }
                let mut next = Vec::new();
                for ((index, _), result) in pending.iter().zip(response.results) {
                    results[*index].extend(result.vulns);
                    if let Some(token) = result.next_page_token {
                        next.push((*index, Some(token)));
                    }
                }
                pending = next;
            }
        }
        Ok(results)
    }

    /// Full advisory, from the cache when its modification date is unchanged.
    pub fn fetch(&self, vuln: &VulnRef) -> Result<Advisory> {
        if !valid_id(&vuln.id) {
            bail!("refusing unexpected advisory id {:?}", vuln.id);
        }
        let key = format!("osv/{}.json", vuln.id);
        if let Some(cache) = &self.cache
            && let Some(text) = cache.get(&key)
            && let Ok(advisory) = Advisory::from_json(&text)
            && !vuln.modified.is_empty()
            && advisory.modified == vuln.modified
        {
            return Ok(advisory);
        }
        let text = self
            .agent
            .get(&format!("{}/vulns/{}", self.base, vuln.id))
            .call()
            .with_context(|| format!("cannot fetch {} from OSV.dev", vuln.id))?
            .into_string()?;
        let advisory =
            Advisory::from_json(&text).with_context(|| format!("invalid advisory {}", vuln.id))?;
        if let Some(cache) = &self.cache {
            cache.put(&key, &text);
        }
        Ok(advisory)
    }

    /// Fetches advisories with `workers` threads. `progress(done, total)` is
    /// called after each one. Failures are returned, not fatal.
    pub fn fetch_all(
        &self,
        vulns: &[VulnRef],
        workers: usize,
        progress: &(dyn Fn(usize, usize) + Sync),
    ) -> (Vec<Advisory>, Vec<String>) {
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let advisories = Mutex::new(Vec::with_capacity(vulns.len()));
        let errors = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..workers.max(1) {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(vuln) = vulns.get(index) else { break };
                        match self.fetch(vuln) {
                            Ok(advisory) => advisories.lock().unwrap().push(advisory),
                            Err(error) => errors.lock().unwrap().push(format!("{error:#}")),
                        }
                        progress(done.fetch_add(1, Ordering::Relaxed) + 1, vulns.len());
                    }
                });
            }
        });
        (
            advisories.into_inner().unwrap(),
            errors.into_inner().unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_json() {
        let package = Query::Package {
            ecosystem: "Ubuntu:26.04:LTS".into(),
            name: "openssl".into(),
            version: "3.5.5-1ubuntu3.7".into(),
        };
        assert_eq!(
            package.to_json(None),
            json!({"package": {"ecosystem": "Ubuntu:26.04:LTS", "name": "openssl"}, "version": "3.5.5-1ubuntu3.7"})
        );
        let purl = Query::Purl("pkg:npm/lodash@4.17.15".into());
        assert_eq!(
            purl.to_json(Some("tok")),
            json!({"package": {"purl": "pkg:npm/lodash@4.17.15"}, "page_token": "tok"})
        );
    }

    #[test]
    fn batch_response_parsing() {
        let response: BatchResponse = serde_json::from_str(
            r#"{"results":[{"vulns":[{"id":"GHSA-1","modified":"2026-01-01T00:00:00Z"}],"next_page_token":"t"},{}]}"#,
        )
        .unwrap();
        assert_eq!(response.results[0].vulns[0].id, "GHSA-1");
        assert_eq!(response.results[0].next_page_token.as_deref(), Some("t"));
        assert!(response.results[1].vulns.is_empty());
    }

    #[test]
    fn advisory_ids_are_checked() {
        assert!(valid_id("UBUNTU-CVE-2024-13176"));
        assert!(valid_id("PYSEC-2021-1"));
        assert!(!valid_id("../../etc/passwd"));
        assert!(!valid_id("GHSA x"));
        assert!(!valid_id(""));
    }
}
