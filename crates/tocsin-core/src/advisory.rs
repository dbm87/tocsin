//! OSV advisories carrying the `tocsin` extension (spec section 6).
//!
//! Only the OSV fields the agent needs are modelled; unknown fields are
//! ignored so that any valid OSV document can be read.

use crate::priority::Urgency;
use crate::purl::Purl;
use crate::version::Scheme;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub modified: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    /// Set when the advisory was retracted: it must then be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Upstream identifiers the advisory derives from (e.g. the CVE behind a
    /// distribution advisory).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity: Vec<Severity>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<DatabaseSpecific>,
}

/// An OSV severity entry: `{"type": "CVSS_V3", "score": "CVSS:3.1/…"}`, or a
/// distribution's own rating such as `{"type": "Ubuntu", "score": "medium"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Severity {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Affected {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Range>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Package {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub kind: RangeKind,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RangeKind {
    Semver,
    Ecosystem,
    Git,
    #[serde(other)]
    Other,
}

/// An OSV range event: `{"introduced": "1.0.0"}`, `{"fixed": "1.2.3"}`…
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseSpecific {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tocsin: Option<TocsinExtension>,
    /// Other database-specific data, kept untouched.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// The `database_specific.tocsin` extension (spec section 6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TocsinExtension {
    pub urgency: Urgency,
    #[serde(default)]
    pub exploited: bool,
    #[serde(default)]
    pub network_reachable: bool,
    #[serde(default)]
    pub mitigations: Vec<Mitigation>,
}

/// Declarative mitigation (spec section 6.3). Never a command or a script.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Mitigation {
    Upgrade {
        to: String,
    },
    BlockHttpPath {
        pattern: String,
    },
    BlockPort {
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },
    DisableFeature {
        setting: String,
        value: serde_json::Value,
    },
    RestrictNetwork {
        scope: String,
    },
    StopService {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        when: Option<String>,
    },
    /// A type this agent does not know: ignored and reported, never fatal.
    #[serde(other)]
    Unknown,
}

impl Mitigation {
    /// The `type` value as written in advisories and policies.
    pub fn kind(&self) -> &'static str {
        match self {
            Mitigation::Upgrade { .. } => "upgrade",
            Mitigation::BlockHttpPath { .. } => "block_http_path",
            Mitigation::BlockPort { .. } => "block_port",
            Mitigation::DisableFeature { .. } => "disable_feature",
            Mitigation::RestrictNetwork { .. } => "restrict_network",
            Mitigation::StopService { .. } => "stop_service",
            Mitigation::Unknown => "unknown",
        }
    }

    /// Every mitigation type defined by the specification.
    pub const KNOWN_KINDS: [&'static str; 6] = [
        "upgrade",
        "block_http_path",
        "block_port",
        "disable_feature",
        "restrict_network",
        "stop_service",
    ];
}

#[derive(Debug, thiserror::Error)]
pub enum AdvisoryError {
    #[error("invalid advisory JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the advisory has an empty `{0}` field")]
    EmptyField(&'static str),
}

/// Result of matching an advisory against an installed component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Affected,
    NotAffected,
    /// The package matches but its version could not be compared
    /// (no version given, or a range type this agent cannot evaluate).
    Undetermined,
}

impl Advisory {
    pub fn from_json(input: &str) -> Result<Self, AdvisoryError> {
        let advisory: Advisory = serde_json::from_str(input)?;
        advisory.validate()?;
        Ok(advisory)
    }

    pub fn validate(&self) -> Result<(), AdvisoryError> {
        if self.id.trim().is_empty() {
            return Err(AdvisoryError::EmptyField("id"));
        }
        if self.modified.trim().is_empty() {
            return Err(AdvisoryError::EmptyField("modified"));
        }
        Ok(())
    }

    /// The Tocsin extension, if the publisher provided one.
    pub fn tocsin(&self) -> Option<&TocsinExtension> {
        self.database_specific.as_ref()?.tocsin.as_ref()
    }

    /// CVE identifiers of this advisory: its own id, aliases and upstream ids.
    pub fn cve_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = std::iter::once(&self.id)
            .chain(&self.aliases)
            .chain(&self.upstream)
            .map(String::as_str)
            .filter(|id| id.starts_with("CVE-"))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// The first CVSS v3 vector of the advisory, parsed.
    pub fn cvss_v3(&self) -> Option<crate::cvss::CvssV3> {
        self.severity
            .iter()
            .filter(|s| s.kind == "CVSS_V3")
            .find_map(|s| crate::cvss::CvssV3::parse(&s.score))
    }

    /// Urgency stated or implied by the advisory, in order of preference: the
    /// Tocsin extension, a textual rating (distribution, GitHub), then the
    /// CVSS v3 base score. `None` when the advisory gives no severity at all.
    pub fn stated_urgency(&self) -> Option<Urgency> {
        if let Some(ext) = self.tocsin() {
            return Some(ext.urgency);
        }
        let textual = self
            .severity
            .iter()
            .filter(|s| !s.kind.starts_with("CVSS"))
            .find_map(|s| Urgency::from_label(&s.score))
            .or_else(|| {
                let other = &self.database_specific.as_ref()?.other;
                Urgency::from_label(other.get("severity")?.as_str()?)
            });
        textual.or_else(|| self.cvss_v3().map(|cvss| cvss.urgency()))
    }

    /// Exploitable remotely: stated by the Tocsin extension, or `AV:N` in CVSS.
    pub fn network_reachable(&self) -> bool {
        self.tocsin().is_some_and(|ext| ext.network_reachable)
            || self.cvss_v3().is_some_and(|cvss| cvss.network)
    }

    /// Versions fixing the advisory for a package, by OSV package name and,
    /// when given, ecosystem: a distribution advisory lists every release,
    /// and another release's fix does not apply.
    pub fn fixed_versions(&self, package_name: &str, ecosystem: Option<&str>) -> Vec<&str> {
        let mut fixed: Vec<&str> = self
            .affected
            .iter()
            .filter(|a| {
                a.package.as_ref().is_some_and(|p| {
                    p.name.as_deref() == Some(package_name)
                        && ecosystem.is_none_or(|e| p.ecosystem.as_deref() == Some(e))
                })
            })
            .flat_map(|a| &a.ranges)
            .flat_map(|r| &r.events)
            .filter_map(|event| match event {
                Event::Fixed(version) => Some(version.as_str()),
                _ => None,
            })
            .collect();
        fixed.sort_unstable();
        fixed.dedup();
        fixed
    }

    /// Does this advisory affect the given component (purl with a version)?
    pub fn matches(&self, component: &Purl) -> Match {
        let mut result = Match::NotAffected;
        for affected in &self.affected {
            let Some(package_purl) = affected
                .package
                .as_ref()
                .and_then(|p| p.purl.as_deref())
                .and_then(|p| p.parse::<Purl>().ok())
            else {
                continue;
            };
            if !package_purl.same_package(component) {
                continue;
            }
            let Some(version) = component.version.as_deref() else {
                result = Match::Undetermined;
                continue;
            };
            match affected.evaluate(version, Some(Scheme::Semver)) {
                Match::Affected => return Match::Affected,
                Match::Undetermined => result = Match::Undetermined,
                Match::NotAffected => {}
            }
        }
        result
    }

    /// Does this advisory affect `version` of the package `name` in the OSV
    /// `ecosystem` (e.g. `Ubuntu:24.04:LTS`, `npm`)? Versions are ordered
    /// with the ecosystem's scheme: this is how OSV.dev answers a query, done
    /// locally.
    pub fn affects(&self, ecosystem: &str, name: &str, version: &str) -> Match {
        let scheme = Scheme::for_ecosystem(ecosystem);
        let mut result = Match::NotAffected;
        for affected in &self.affected {
            let Some(package) = &affected.package else {
                continue;
            };
            if package.ecosystem.as_deref() != Some(ecosystem)
                || !package
                    .name
                    .as_deref()
                    .is_some_and(|n| same_name(ecosystem, n, name))
            {
                continue;
            }
            match affected.evaluate(version, scheme) {
                Match::Affected => return Match::Affected,
                Match::Undetermined => result = Match::Undetermined,
                Match::NotAffected => {}
            }
        }
        result
    }
}

/// Package names are compared as the ecosystem does: PyPI normalises them
/// (PEP 503), others compare them exactly.
pub fn same_name(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem == "PyPI" {
        normalize_pypi(a) == normalize_pypi(b)
    } else {
        a == b
    }
}

/// PEP 503 name normalisation.
pub fn normalize_pypi(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

impl Affected {
    /// Evaluates the listed versions and ranges for `version`, ordering
    /// `ECOSYSTEM` ranges with `scheme`. `GIT` ranges are ignored, as OSV.dev
    /// does for version queries. When a range cannot be evaluated but the
    /// entry enumerates affected versions, the enumeration is trusted.
    fn evaluate(&self, version: &str, scheme: Option<Scheme>) -> Match {
        if self.versions.iter().any(|v| v == version) {
            return Match::Affected;
        }
        let mut result = Match::NotAffected;
        let mut evaluable = 0;
        for range in &self.ranges {
            let scheme = match range.kind {
                RangeKind::Semver => Some(Scheme::Semver),
                RangeKind::Ecosystem => scheme,
                RangeKind::Git => continue,
                RangeKind::Other => None,
            };
            evaluable += 1;
            match scheme.and_then(|s| range_affects(range, version, s)) {
                Some(true) => return Match::Affected,
                Some(false) => {}
                None if self.versions.is_empty() => result = Match::Undetermined,
                None => {}
            }
        }
        if evaluable == 0 && self.versions.is_empty() {
            // No version data this agent can use (none at all, or only GIT ranges).
            return Match::Undetermined;
        }
        result
    }
}

/// `introduced: "0"` means "from the very first version" in every ecosystem.
fn compare_event(scheme: Scheme, event: &str, version: &str) -> Option<Ordering> {
    if event == "0" {
        return Some(if version == "0" {
            Ordering::Equal
        } else {
            Ordering::Less
        });
    }
    scheme.compare(event, version)
}

/// Evaluates an OSV range for a version. `None` when a version of the range
/// cannot be ordered with `scheme`.
fn range_affects(range: &Range, version: &str, scheme: Scheme) -> Option<bool> {
    let mut events = Vec::with_capacity(range.events.len());
    for event in &range.events {
        let raw = match event {
            Event::Introduced(v) | Event::Fixed(v) | Event::LastAffected(v) | Event::Limit(v) => v,
        };
        // Position of the event relative to the version being evaluated.
        events.push((raw.as_str(), compare_event(scheme, raw, version)?, event));
    }
    events.sort_by(|a, b| match (a.0 == "0", b.0 == "0") {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => scheme.compare(a.0, b.0).unwrap_or(Ordering::Equal),
    });

    let mut affected = false;
    for (_, position, event) in events {
        match event {
            Event::Introduced(_) if position != Ordering::Greater => affected = true,
            Event::Fixed(_) if position != Ordering::Greater => affected = false,
            Event::LastAffected(_) if position == Ordering::Less => affected = false,
            _ => {}
        }
    }
    Some(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory(ranges: &str) -> Advisory {
        let json = format!(
            r#"{{"id":"T-1","modified":"2026-11-20T00:00:00Z",
                "affected":[{{"package":{{"purl":"pkg:npm/widget"}},"ranges":[{ranges}]}}]}}"#
        );
        Advisory::from_json(&json).unwrap()
    }

    fn purl(s: &str) -> Purl {
        s.parse().unwrap()
    }

    #[test]
    fn introduced_and_fixed() {
        let a =
            advisory(r#"{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.4.7"}]}"#);
        assert_eq!(a.matches(&purl("pkg:npm/widget@1.9.9")), Match::NotAffected);
        assert_eq!(a.matches(&purl("pkg:npm/widget@2.0.0")), Match::Affected);
        assert_eq!(a.matches(&purl("pkg:npm/widget@2.4.6")), Match::Affected);
        assert_eq!(a.matches(&purl("pkg:npm/widget@2.4.7")), Match::NotAffected);
    }

    #[test]
    fn introduced_zero_and_last_affected() {
        let a = advisory(
            r#"{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"1.2.0"}]}"#,
        );
        assert_eq!(a.matches(&purl("pkg:npm/widget@0.1.0")), Match::Affected);
        assert_eq!(a.matches(&purl("pkg:npm/widget@1.2.0")), Match::Affected);
        assert_eq!(a.matches(&purl("pkg:npm/widget@1.2.1")), Match::NotAffected);
    }

    #[test]
    fn several_intervals() {
        let a = advisory(
            r#"{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.5"},{"introduced":"2.0.0"},{"fixed":"2.1.0"}]}"#,
        );
        assert_eq!(a.matches(&purl("pkg:npm/widget@1.0.4")), Match::Affected);
        assert_eq!(a.matches(&purl("pkg:npm/widget@1.5.0")), Match::NotAffected);
        assert_eq!(a.matches(&purl("pkg:npm/widget@2.0.3")), Match::Affected);
    }

    #[test]
    fn other_package_or_missing_version() {
        let a = advisory(r#"{"type":"SEMVER","events":[{"introduced":"0"}]}"#);
        assert_eq!(a.matches(&purl("pkg:npm/other@1.0.0")), Match::NotAffected);
        assert_eq!(a.matches(&purl("pkg:npm/widget")), Match::Undetermined);
    }

    #[test]
    fn git_ranges_are_undetermined() {
        let a = advisory(r#"{"type":"GIT","events":[{"introduced":"abc123"}]}"#);
        assert_eq!(
            a.matches(&purl("pkg:npm/widget@1.0.0")),
            Match::Undetermined
        );
    }

    #[test]
    fn unknown_mitigation_does_not_break_parsing() {
        let json = r#"{"id":"T-2","modified":"2026-11-20T00:00:00Z","database_specific":{"tocsin":{
            "urgency":"high","mitigations":[{"type":"teleport","where":"mars"},{"type":"upgrade","to":"1.0.1"}]}}}"#;
        let a = Advisory::from_json(json).unwrap();
        let kinds: Vec<_> = a
            .tocsin()
            .unwrap()
            .mitigations
            .iter()
            .map(Mitigation::kind)
            .collect();
        assert_eq!(kinds, ["unknown", "upgrade"]);
    }

    #[test]
    fn empty_id_is_rejected() {
        let json = r#"{"id":" ","modified":"2026-11-20T00:00:00Z"}"#;
        assert!(matches!(
            Advisory::from_json(json),
            Err(AdvisoryError::EmptyField("id"))
        ));
    }

    // Shapes taken from real OSV.dev records.
    const UBUNTU: &str = r#"{"id":"UBUNTU-CVE-2024-13176","modified":"2026-01-01T00:00:00Z",
        "upstream":["CVE-2024-13176"],
        "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},{"type":"Ubuntu","score":"low"}],
        "affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.5"}]}]}]}"#;
    const GHSA: &str = r#"{"id":"GHSA-29mw-wpgm-hmr9","modified":"2026-01-01T00:00:00Z",
        "aliases":["CVE-2020-28500"],
        "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
        "database_specific":{"severity":"MODERATE","github_reviewed":true}}"#;

    #[test]
    fn distribution_rating_is_preferred_to_cvss() {
        let a = Advisory::from_json(UBUNTU).unwrap();
        assert_eq!(a.cve_ids(), ["CVE-2024-13176"]);
        // CVSS alone would say medium (4.6); Ubuntu rates it low in context.
        assert_eq!(a.stated_urgency(), Some(Urgency::Low));
        assert!(!a.network_reachable());
        assert_eq!(a.fixed_versions("openssl", None), ["3.0.13-0ubuntu3.5"]);
        assert_eq!(
            a.fixed_versions("openssl", Some("Ubuntu:24.04:LTS")),
            ["3.0.13-0ubuntu3.5"]
        );
        assert!(
            a.fixed_versions("openssl", Some("Ubuntu:22.04:LTS"))
                .is_empty()
        );
        assert!(a.fixed_versions("libssl3t64", None).is_empty());
    }

    #[test]
    fn github_rating_and_network_vector() {
        let a = Advisory::from_json(GHSA).unwrap();
        assert_eq!(a.cve_ids(), ["CVE-2020-28500"]);
        assert_eq!(a.stated_urgency(), Some(Urgency::Medium));
        assert!(a.network_reachable());
    }

    #[test]
    fn cvss_only_and_no_severity() {
        let cvss_only = r#"{"id":"RUSTSEC-2020-0071","modified":"x","aliases":["CVE-2020-26235"],
            "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}"#;
        assert_eq!(
            Advisory::from_json(cvss_only).unwrap().stated_urgency(),
            Some(Urgency::Critical)
        );
        let none = r#"{"id":"X-1","modified":"x"}"#;
        assert_eq!(Advisory::from_json(none).unwrap().stated_urgency(), None);
    }

    #[test]
    fn affects_orders_distribution_versions() {
        let a = Advisory::from_json(UBUNTU).unwrap();
        let eco = "Ubuntu:24.04:LTS";
        assert_eq!(
            a.affects(eco, "openssl", "3.0.13-0ubuntu3"),
            Match::Affected
        );
        assert_eq!(
            a.affects(eco, "openssl", "3.0.13-0ubuntu3.4"),
            Match::Affected
        );
        // dpkg ordering, not string ordering: 3.10 > 3.5.
        assert_eq!(
            a.affects(eco, "openssl", "3.0.13-0ubuntu3.10"),
            Match::NotAffected
        );
        assert_eq!(
            a.affects(eco, "openssl", "3.0.13-0ubuntu3.5"),
            Match::NotAffected
        );
        assert_eq!(
            a.affects("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1"),
            Match::NotAffected,
            "another release"
        );
        assert_eq!(
            a.affects(eco, "libssl3t64", "3.0.13-0ubuntu3"),
            Match::NotAffected
        );
    }

    #[test]
    fn affects_rpm_and_last_affected() {
        let a = Advisory::from_json(
            r#"{"id":"ALSA-1","modified":"x","affected":[{"package":{"ecosystem":"AlmaLinux:9","name":"glibc"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.34-60.el9"}]}]}]}"#,
        )
        .unwrap();
        assert_eq!(
            a.affects("AlmaLinux:9", "glibc", "2.34-60.el9"),
            Match::Affected
        );
        assert_eq!(
            a.affects("AlmaLinux:9", "glibc", "2.34-8.el9"),
            Match::Affected
        );
        assert_eq!(
            a.affects("AlmaLinux:9", "glibc", "2.34-100.el9"),
            Match::NotAffected
        );
    }

    #[test]
    fn affects_pypi_names_and_enumerated_versions() {
        let a = Advisory::from_json(
            r#"{"id":"PYSEC-1","modified":"x","affected":[{"package":{"ecosystem":"PyPI","name":"Django_Rest.Framework"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.15.2"}]}],
            "versions":["3.15.0","3.15.1"]}]}"#,
        )
        .unwrap();
        assert_eq!(
            a.affects("PyPI", "django-rest-framework", "3.15.1"),
            Match::Affected
        );
        assert_eq!(
            a.affects("PyPI", "django-rest-framework", "3.14.0rc1"),
            Match::Affected,
            "range evaluated with PEP 440"
        );
        assert_eq!(
            a.affects("PyPI", "django-rest-framework", "3.15.2"),
            Match::NotAffected
        );
        // An unparsable version falls back to the enumeration.
        assert_eq!(
            a.affects("PyPI", "django-rest-framework", "weird"),
            Match::NotAffected
        );
    }

    #[test]
    fn withdrawn_is_parsed() {
        let a = Advisory::from_json(
            r#"{"id":"GHSA-x","modified":"x","withdrawn":"2026-11-20T16:33:06Z"}"#,
        )
        .unwrap();
        assert!(a.withdrawn.is_some());
    }
}
