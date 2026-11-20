//! Offline OSV: advisories taken from the public OSV exports and matched
//! locally, so that the inventory never leaves the machine.
//!
//! OSV publishes, per ecosystem, a zip of every record (`<ecosystem>/all.zip`),
//! a list of records by modification date (`modified_id.csv`) and each record
//! on its own (`<ecosystem>/<id>.json`). Release-specific exports such as
//! `Ubuntu:24.04:LTS/all.zip` are no longer updated, so the export of the base
//! ecosystem (`Ubuntu`) is downloaded once and filtered locally; afterwards
//! only the records modified since are fetched.
//!
//! What leaves the machine: the names of the ecosystems (`Ubuntu`, `npm`…),
//! never a package name or version.
//!
//! The local database holds, per exact ecosystem (`Ubuntu:24.04:LTS`), the
//! advisories concerning it, reduced to the fields the agent models.

use crate::osv::Query;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tocsin_core::Advisory;
use tocsin_core::advisory::{Affected, Event, Match, RangeKind, normalize_pypi};
use tocsin_core::version::Scheme;

pub const EXPORTS: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// Beyond this many modified records, the whole export is downloaded again.
const INCREMENTAL_LIMIT: usize = 3000;
/// Format of the database files; a different value forces a full download.
const FORMAT: u32 = 1;

/// When to contact the export server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    /// Check for updates when the last check is older than this.
    After(Duration),
    /// Never download: use the local database as it is (air-gapped machines).
    Never,
}

/// The OSV ecosystem, package name and version a query is about.
pub fn query_target(query: &Query) -> Option<(String, String, String)> {
    match query {
        Query::Package {
            ecosystem,
            name,
            version,
        } => Some((ecosystem.clone(), name.clone(), version.clone())),
        Query::Purl(purl) => {
            let purl: tocsin_core::Purl = purl.parse().ok()?;
            let ecosystem = match purl.ty.as_str() {
                "npm" => "npm",
                "cargo" => "crates.io",
                "pypi" => "PyPI",
                "gem" => "RubyGems",
                "golang" => "Go",
                "maven" => "Maven",
                "nuget" => "NuGet",
                "composer" => "Packagist",
                _ => return None,
            };
            // OSV names: `@scope/name` (npm), `vendor/name` (Packagist),
            // `group:artifact` (Maven), `host/path` (Go).
            let name = match (&purl.namespace, purl.ty.as_str()) {
                (Some(ns), "maven") => format!("{ns}:{}", purl.name),
                (Some(ns), _) => format!("{ns}/{}", purl.name),
                (None, _) => purl.name.clone(),
            };
            Some((ecosystem.to_owned(), name, purl.version?))
        }
    }
}

/// The export holding an ecosystem: the part before the first `:`.
pub fn export_name(ecosystem: &str) -> &str {
    ecosystem.split(':').next().unwrap_or(ecosystem)
}

#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    format: u32,
    ecosystem: String,
    /// Newest modification date among the records of the export, truncated
    /// to the second: the next update fetches records modified since.
    synced: String,
    /// Unix time of the last successful check with the server.
    checked: u64,
    advisories: Vec<Advisory>,
}

/// The advisories of one ecosystem, indexed by package name.
#[derive(Debug)]
pub struct Database {
    pub ecosystem: String,
    /// Newest record modification date taken into account.
    pub synced: String,
    /// Set when an update was due but failed: the data may be outdated.
    pub stale: bool,
    advisories: Vec<Advisory>,
    by_name: HashMap<String, Vec<usize>>,
}

impl Database {
    fn new(stored: Stored, stale: bool) -> Self {
        let mut db = Database {
            ecosystem: stored.ecosystem,
            synced: stored.synced,
            stale,
            advisories: stored.advisories,
            by_name: HashMap::new(),
        };
        for (index, advisory) in db.advisories.iter().enumerate() {
            let mut names: Vec<String> = advisory
                .affected
                .iter()
                .filter_map(|a| a.package.as_ref())
                .filter(|p| p.ecosystem.as_deref() == Some(db.ecosystem.as_str()))
                .filter_map(|p| p.name.as_deref())
                .map(|n| name_key(&db.ecosystem, n))
                .collect();
            names.sort_unstable();
            names.dedup();
            for name in names {
                db.by_name.entry(name).or_default().push(index);
            }
        }
        db
    }

    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Advisories concerning `name` at `version`, with how they match
    /// (`Affected` or `Undetermined`; non-matching ones are left out).
    pub fn query(&self, name: &str, version: &str) -> Vec<(&Advisory, Match)> {
        let Some(indexes) = self.by_name.get(&name_key(&self.ecosystem, name)) else {
            return Vec::new();
        };
        indexes
            .iter()
            .map(|&i| &self.advisories[i])
            .filter(|a| a.withdrawn.is_none())
            .filter_map(|a| match a.affects(&self.ecosystem, name, version) {
                Match::NotAffected => None,
                m => Some((a, m)),
            })
            .collect()
    }
}

fn name_key(ecosystem: &str, name: &str) -> String {
    if ecosystem == "PyPI" {
        normalize_pypi(name)
    } else {
        name.to_owned()
    }
}

/// Reduces a record to what concerns `ecosystem`; `None` when nothing does
/// or when it was withdrawn.
fn reduce(mut advisory: Advisory, ecosystem: &str) -> Option<Advisory> {
    if advisory.withdrawn.is_some() {
        return None;
    }
    advisory.affected.retain(|a| {
        a.package
            .as_ref()
            .is_some_and(|p| p.ecosystem.as_deref() == Some(ecosystem))
    });
    let scheme = Scheme::for_ecosystem(ecosystem);
    for affected in &mut advisory.affected {
        // Matching is by ecosystem and name here; purls are not needed.
        if let Some(package) = &mut affected.package {
            package.purl = None;
        }
        // Distributions enumerate every affected version: most of the size
        // of a record, and redundant when the ranges can be evaluated.
        if ranges_evaluable(affected, scheme) {
            affected.versions = Vec::new();
        }
    }
    (!advisory.affected.is_empty()).then_some(advisory)
}

/// True when the entry has ranges and every non-GIT one can be ordered.
fn ranges_evaluable(affected: &Affected, scheme: Option<Scheme>) -> bool {
    let mut ranges = affected
        .ranges
        .iter()
        .filter(|r| r.kind != RangeKind::Git)
        .peekable();
    ranges.peek().is_some()
        && ranges.all(|range| {
            let scheme = match range.kind {
                RangeKind::Semver => Scheme::Semver,
                RangeKind::Ecosystem => match scheme {
                    Some(s) => s,
                    None => return false,
                },
                _ => return false,
            };
            range.events.iter().all(|event| {
                let (Event::Introduced(v)
                | Event::Fixed(v)
                | Event::LastAffected(v)
                | Event::Limit(v)) = event;
                v == "0" || scheme.compare(v, v).is_some()
            })
        })
}

/// `2026-11-20T16:56:07.880125747Z` → `2026-11-20T16:56:07`, so that dates
/// with and without fractions compare correctly as strings.
fn second(date: &str) -> &str {
    date.get(..19).unwrap_or(date)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Export and record URLs: the ecosystem is a path segment (`Rocky Linux`).
fn segment(s: &str) -> String {
    s.replace('%', "%25").replace(' ', "%20")
}

/// Database file names: ecosystems contain `:` and spaces.
fn file_name(ecosystem: &str) -> Option<String> {
    let safe = !ecosystem.is_empty()
        && ecosystem
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " .:_-".contains(c))
        && !ecosystem.starts_with('.');
    safe.then(|| format!("{}.json", ecosystem.replace([' ', ':'], "_")))
}

/// What happened while opening a database, for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// Used as is (recently checked, or refresh disabled).
    Local,
    /// Updated with this many modified records.
    Incremental(usize),
    /// Built from the full export.
    Full,
    /// The update failed; the local database is used.
    Failed(String),
}

pub struct Store {
    dir: PathBuf,
    base: String,
    agent: ureq::Agent,
    workers: usize,
    /// Called with progress messages (downloads can take minutes).
    log: Box<dyn Fn(&str) + Sync>,
}

impl Store {
    /// A store in `dir` (typically `<cache>/osv-offline`).
    pub fn new(dir: impl Into<PathBuf>, agent: ureq::Agent) -> Self {
        Store {
            dir: dir.into(),
            base: EXPORTS.to_owned(),
            agent,
            workers: 16,
            log: Box::new(|_| {}),
        }
    }

    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    pub fn with_log(mut self, log: impl Fn(&str) + Sync + 'static) -> Self {
        self.log = Box::new(log);
        self
    }

    #[cfg(test)]
    fn with_base(mut self, base: &str) -> Self {
        self.base = base.to_owned();
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, ecosystem: &str) -> Result<PathBuf> {
        let name = file_name(ecosystem)
            .with_context(|| format!("unexpected ecosystem name {ecosystem:?}"))?;
        Ok(self.dir.join(name))
    }

    fn load(&self, ecosystem: &str) -> Option<Stored> {
        let text = std::fs::read_to_string(self.path(ecosystem).ok()?).ok()?;
        let stored: Stored = serde_json::from_str(&text).ok()?;
        (stored.format == FORMAT && stored.ecosystem == ecosystem).then_some(stored)
    }

    fn save(&self, stored: &Stored) -> Result<()> {
        let path = self.path(&stored.ecosystem)?;
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        let file = std::fs::File::create(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer(&mut writer, stored)?;
        writer.flush()?;
        drop(writer);
        std::fs::rename(&tmp, &path).with_context(|| format!("cannot write {}", path.display()))
    }

    /// The database of `ecosystem`, updated according to `refresh`.
    pub fn open(&self, ecosystem: &str, refresh: Refresh) -> Result<(Database, Update)> {
        let local = self.load(ecosystem);
        let max_age = match refresh {
            Refresh::Never => {
                let stored = local.with_context(|| {
                    format!(
                        "no local OSV database for {ecosystem} in {} (downloads disabled)",
                        self.dir.display()
                    )
                })?;
                return Ok((Database::new(stored, false), Update::Local));
            }
            Refresh::After(max_age) => max_age,
        };
        let Some(mut stored) = local else {
            let stored = self.full(ecosystem)?;
            self.save(&stored)?;
            return Ok((Database::new(stored, false), Update::Full));
        };
        if now().saturating_sub(stored.checked) < max_age.as_secs() {
            return Ok((Database::new(stored, false), Update::Local));
        }
        let result = match self.incremental(&mut stored) {
            Ok(Some(count)) => Ok(Update::Incremental(count)),
            Ok(None) => self.full(ecosystem).map(|full| {
                stored = full;
                Update::Full
            }),
            Err(error) => Err(error),
        };
        match result {
            Ok(sync) => {
                self.save(&stored)?;
                Ok((Database::new(stored, false), sync))
            }
            Err(error) => {
                let message = format!("{error:#}");
                Ok((Database::new(stored, true), Update::Failed(message)))
            }
        }
    }

    /// Downloads `<export>/all.zip` and keeps the records concerning `ecosystem`.
    fn full(&self, ecosystem: &str) -> Result<Stored> {
        let export = export_name(ecosystem);
        let url = format!("{}/{}/all.zip", self.base, segment(export));
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let zip_path = self
            .dir
            .join(format!("download-{}.zip", std::process::id()));
        let downloaded = self.download(&url, &zip_path, export);
        let result = downloaded.and_then(|()| {
            (self.log)(&format!("reading the {export} export for {ecosystem}"));
            let file = std::fs::File::open(&zip_path)?;
            read_export(file, ecosystem)
        });
        let _ = std::fs::remove_file(&zip_path);
        let (advisories, synced) = result?;
        Ok(Stored {
            format: FORMAT,
            ecosystem: ecosystem.to_owned(),
            synced,
            checked: now(),
            advisories,
        })
    }

    fn download(&self, url: &str, path: &Path, export: &str) -> Result<()> {
        let response = self
            .agent
            .get(url)
            .timeout(Duration::from_secs(3600))
            .call()
            .with_context(|| format!("cannot download {url}"))?;
        let size = response
            .header("content-length")
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| format!(" ({} MB)", n / 1_000_000))
            .unwrap_or_default();
        (self.log)(&format!(
            "downloading the OSV export of {export}{size}, done once, then updated incrementally"
        ));
        let mut file = std::fs::File::create(path)
            .with_context(|| format!("cannot write {}", path.display()))?;
        std::io::copy(&mut response.into_reader(), &mut file)
            .with_context(|| format!("download of {url} interrupted"))?;
        Ok(())
    }

    /// Applies the records modified since the last update. `Ok(None)` when
    /// there are too many and a full download is preferable.
    fn incremental(&self, stored: &mut Stored) -> Result<Option<usize>> {
        let export = export_name(&stored.ecosystem).to_owned();
        let url = format!("{}/{}/modified_id.csv", self.base, segment(&export));
        let csv = self
            .agent
            .get(&url)
            .call()
            .with_context(|| format!("cannot download {url}"))?
            .into_reader();
        let mut text = String::new();
        // modified_id.csv is a few MB at most; the limit guards against a broken server.
        csv.take(256 * 1024 * 1024).read_to_string(&mut text)?;
        let since = stored.synced.clone();
        let changed = modified_since(&text, &since)?;
        if changed.len() > INCREMENTAL_LIMIT {
            return Ok(None);
        }
        (self.log)(&format!(
            "updating {}: {} record(s) modified since {since}",
            stored.ecosystem,
            changed.len()
        ));
        let records = self.fetch_records(&export, &changed)?;
        let mut newest = since;
        for (id, modified) in &changed {
            if second(modified) > newest.as_str() {
                newest = second(modified).to_owned();
            }
            stored.advisories.retain(|a| &a.id != id);
        }
        for record in records {
            if let Some(advisory) = reduce(record, &stored.ecosystem) {
                stored.advisories.push(advisory);
            }
        }
        stored.synced = newest;
        stored.checked = now();
        Ok(Some(changed.len()))
    }

    fn fetch_records(&self, export: &str, ids: &[(String, String)]) -> Result<Vec<Advisory>> {
        let next = AtomicUsize::new(0);
        let records = Mutex::new(Vec::with_capacity(ids.len()));
        let errors = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..self.workers.min(ids.len()).max(1) {
                scope.spawn(|| {
                    while let Some((id, _)) = ids.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let url = format!("{}/{}/{}.json", self.base, segment(export), id);
                        let fetched = self
                            .agent
                            .get(&url)
                            .call()
                            .map_err(anyhow::Error::from)
                            .and_then(|r| Ok(r.into_string()?))
                            .and_then(|text| Ok(Advisory::from_json(&text)?));
                        match fetched {
                            Ok(advisory) => records.lock().unwrap().push(advisory),
                            Err(error) => errors.lock().unwrap().push(format!("{id}: {error:#}")),
                        }
                    }
                });
            }
        });
        let errors = errors.into_inner().unwrap();
        if let Some(first) = errors.first() {
            // Applying a partial update would lose records for good.
            bail!(
                "{} record(s) could not be fetched, first: {first}",
                errors.len()
            );
        }
        Ok(records.into_inner().unwrap())
    }
}

/// Valid OSV identifiers, used in URLs.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

/// Records of `modified_id.csv` (newest first) modified at or after `since`.
/// Records of the boundary second are fetched again: that is harmless.
fn modified_since(csv: &str, since: &str) -> Result<Vec<(String, String)>> {
    let mut changed = Vec::new();
    for line in csv.lines().filter(|l| !l.trim().is_empty()) {
        let Some((modified, id)) = line.trim().split_once(',') else {
            bail!("unexpected line in modified_id.csv: {line:?}");
        };
        if second(modified) < since {
            break;
        }
        // The ecosystem-wide list may name records by path (`Ubuntu/ID`).
        let id = id.rsplit('/').next().unwrap_or(id);
        if !valid_id(id) {
            bail!("unexpected record id in modified_id.csv: {id:?}");
        }
        changed.push((id.to_owned(), modified.to_owned()));
    }
    Ok(changed)
}

/// Reads an export zip: the records concerning `ecosystem`, reduced, and the
/// newest modification date of all records.
fn read_export<R: Read + std::io::Seek>(
    reader: R,
    ecosystem: &str,
) -> Result<(Vec<Advisory>, String)> {
    let mut archive = zip::ZipArchive::new(reader).context("invalid OSV export archive")?;
    // Cheap pre-filter before parsing: the ecosystem appears quoted in the JSON.
    let needle = format!("\"{ecosystem}\"");
    let mut advisories = Vec::new();
    let mut newest = String::new();
    let mut text = String::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name()?.into_owned();
        if !entry.is_file() || !name.ends_with(".json") {
            continue;
        }
        text.clear();
        // Single records are small; the limit guards against a zip bomb.
        (&mut entry)
            .take(64 * 1024 * 1024)
            .read_to_string(&mut text)
            .with_context(|| format!("cannot read {name} in the export"))?;
        let Ok(advisory) = Advisory::from_json(&text) else {
            continue;
        };
        if second(&advisory.modified) > newest.as_str() {
            newest = second(&advisory.modified).to_owned();
        }
        if !text.contains(&needle) {
            continue;
        }
        if let Some(advisory) = reduce(advisory, ecosystem) {
            advisories.push(advisory);
        }
    }
    if newest.is_empty() {
        bail!("the OSV export contains no record");
    }
    Ok((advisories, newest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const UBUNTU_REC: &str = r#"{"id":"UBUNTU-CVE-2023-4911","modified":"2026-01-02T03:04:05.123Z",
        "upstream":["CVE-2023-4911"],"severity":[{"type":"Ubuntu","score":"high"}],
        "affected":[
          {"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"glibc"},
           "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.35-0ubuntu3.4"}]}]},
          {"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"glibc"},
           "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#;
    const OTHER_REC: &str = r#"{"id":"UBUNTU-CVE-2020-1","modified":"2026-01-01T00:00:00Z",
        "affected":[{"package":{"ecosystem":"Ubuntu:20.04:LTS","name":"zlib"},
           "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#;

    fn export(records: &[(&str, &str)]) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in records {
            zip.start_file(*name, options).unwrap();
            zip.write_all(content.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
        buffer.into_inner()
    }

    #[test]
    fn export_is_filtered_and_reduced() {
        let zip = export(&[
            ("UBUNTU-CVE-2023-4911.json", UBUNTU_REC),
            ("UBUNTU-CVE-2020-1.json", OTHER_REC),
        ]);
        let (advisories, newest) = read_export(Cursor::new(zip), "Ubuntu:22.04:LTS").unwrap();
        assert_eq!(newest, "2026-01-02T03:04:05");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].affected.len(), 1, "other releases dropped");

        let db = Database::new(
            Stored {
                format: FORMAT,
                ecosystem: "Ubuntu:22.04:LTS".into(),
                synced: newest,
                checked: 0,
                advisories,
            },
            false,
        );
        let hits = db.query("glibc", "2.35-0ubuntu3.1");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.id, "UBUNTU-CVE-2023-4911");
        assert_eq!(hits[0].1, Match::Affected);
        assert!(db.query("glibc", "2.35-0ubuntu3.4").is_empty());
        assert!(db.query("zlib", "1.0").is_empty());
    }

    #[test]
    fn reduction_drops_redundant_versions() {
        let record = |ranges: &str| {
            Advisory::from_json(&format!(
                r#"{{"id":"X-1","modified":"x","affected":[{{"package":{{"ecosystem":"npm","name":"w","purl":"pkg:npm/w"}},
                "ranges":[{ranges}],"versions":["1.0.0","1.0.1"]}}]}}"#
            ))
            .unwrap()
        };
        let evaluable = reduce(
            record(r#"{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.2"}]}"#),
            "npm",
        )
        .unwrap();
        assert!(evaluable.affected[0].versions.is_empty());
        assert_eq!(evaluable.affected[0].package.as_ref().unwrap().purl, None);
        for kept in [
            r#"{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"not-semver"}]}"#,
            r#"{"type":"GIT","events":[{"introduced":"abc"}]}"#,
        ] {
            let reduced = reduce(record(kept), "npm").unwrap();
            assert_eq!(reduced.affected[0].versions.len(), 2, "{kept}");
        }
    }

    #[test]
    fn modified_list_parsing() {
        let csv = "2026-11-20T16:56:07.880125747Z,GHSA-a\n\
                   2026-11-20T16:56:07Z,Ubuntu/USN-1\n\
                   2026-11-19T10:00:00Z,GHSA-b\n\
                   2026-11-18T10:00:00Z,GHSA-c\n";
        let changed = modified_since(csv, "2026-11-19T10:00:00").unwrap();
        let ids: Vec<&str> = changed.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["GHSA-a", "USN-1", "GHSA-b"]);
        assert!(modified_since("2026-11-20T00:00:00Z,bad id\n", "2026").is_err());
    }

    #[test]
    fn query_targets() {
        let t = |q: Query| query_target(&q).unwrap();
        assert_eq!(
            t(Query::Purl("pkg:npm/%40babel/core@7.0.0".into())),
            ("npm".into(), "@babel/core".into(), "7.0.0".into())
        );
        assert_eq!(
            t(Query::Purl("pkg:cargo/serde@1.0.200".into())),
            ("crates.io".into(), "serde".into(), "1.0.200".into())
        );
        assert_eq!(t(Query::Purl("pkg:pypi/django@4.2".into())).0, "PyPI");
        assert!(query_target(&Query::Purl("pkg:npm/no-version".into())).is_none());
    }

    #[test]
    fn names_and_urls() {
        assert_eq!(export_name("Rocky Linux:9"), "Rocky Linux");
        assert_eq!(segment("Rocky Linux"), "Rocky%20Linux");
        assert_eq!(
            file_name("Ubuntu:24.04:LTS").as_deref(),
            Some("Ubuntu_24.04_LTS.json")
        );
        assert_eq!(file_name("../etc"), None);
        assert_eq!(file_name("a/b"), None);
    }

    /// A tiny HTTP server serving fixed paths, for the update logic.
    fn serve(routes: Vec<(String, Vec<u8>)>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = [0u8; 4096];
                let n = stream.read(&mut request).unwrap_or(0);
                let line = String::from_utf8_lossy(&request[..n]);
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                let response = match routes.iter().find(|(p, _)| *p == path) {
                    Some((_, body)) => {
                        let mut r = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        r.extend_from_slice(body);
                        r
                    }
                    None => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                };
                let _ = stream.write_all(&response);
            }
        });
        format!("http://{address}")
    }

    #[test]
    fn full_then_incremental_update() {
        let fixed = UBUNTU_REC
            .replace("2026-01-02T03:04:05.123Z", "2026-02-01T00:00:00Z")
            .replace(
                r#"{"introduced":"0"}]}]}]}"#,
                r#"{"introduced":"0"},{"fixed":"2.39-0ubuntu8.1"}]}]}]}"#,
            );
        let withdrawn = r#"{"id":"UBUNTU-CVE-2024-2","modified":"2026-02-01T00:00:00Z","withdrawn":"2026-02-01T00:00:00Z",
            "affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"glibc"}}]}"#;
        let base = serve(vec![
            (
                "/Ubuntu/all.zip".into(),
                export(&[
                    ("UBUNTU-CVE-2023-4911.json", UBUNTU_REC),
                    ("UBUNTU-CVE-2020-1.json", OTHER_REC),
                ]),
            ),
            (
                "/Ubuntu/modified_id.csv".into(),
                b"2026-02-01T00:00:00Z,UBUNTU-CVE-2023-4911\n2026-02-01T00:00:00Z,UBUNTU-CVE-2024-2\n2026-01-02T03:04:05.123Z,UBUNTU-CVE-2020-1\n".to_vec(),
            ),
            ("/Ubuntu/UBUNTU-CVE-2023-4911.json".into(), fixed.into_bytes()),
            ("/Ubuntu/UBUNTU-CVE-2024-2.json".into(), withdrawn.as_bytes().to_vec()),
            ("/Ubuntu/UBUNTU-CVE-2020-1.json".into(), OTHER_REC.as_bytes().to_vec()),
        ]);
        let dir = std::env::temp_dir().join(format!("tocsin-offline-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(&dir, crate::http_agent()).with_base(&base);
        let eco = "Ubuntu:24.04:LTS";

        assert!(
            store.open(eco, Refresh::Never).is_err(),
            "nothing local yet"
        );
        let (db, sync) = store
            .open(eco, Refresh::After(Duration::from_secs(3600)))
            .unwrap();
        assert_eq!(sync, Update::Full);
        assert_eq!(db.query("glibc", "2.39-0ubuntu8").len(), 1);

        // Checked recently: used as is.
        let (_, sync) = store
            .open(eco, Refresh::After(Duration::from_secs(3600)))
            .unwrap();
        assert_eq!(sync, Update::Local);

        // Due: the modified records are applied (boundary record fetched again).
        let (db, sync) = store.open(eco, Refresh::After(Duration::ZERO)).unwrap();
        assert_eq!(sync, Update::Incremental(3));
        assert_eq!(db.synced, "2026-02-01T00:00:00");
        assert!(db.query("glibc", "2.39-0ubuntu8.1").is_empty(), "now fixed");
        assert_eq!(db.query("glibc", "2.39-0ubuntu8").len(), 1);
        assert_eq!(db.len(), 1, "withdrawn record not added");

        // Server gone: the local database is used, marked stale.
        let offline = Store::new(&dir, crate::http_agent()).with_base("http://127.0.0.1:9");
        let (db, sync) = offline.open(eco, Refresh::After(Duration::ZERO)).unwrap();
        assert!(matches!(sync, Update::Failed(_)));
        assert!(db.stale);
        assert_eq!(db.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
