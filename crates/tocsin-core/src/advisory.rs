//! OSV advisories carrying the `tocsin` extension (spec section 6).
//!
//! Only the OSV fields the agent needs are modelled; unknown fields are
//! ignored so that any valid OSV document can be read.

use crate::priority::Urgency;
use crate::purl::Purl;
use serde::{Deserialize, Serialize};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<DatabaseSpecific>,
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
            if affected.versions.iter().any(|v| v == version) {
                return Match::Affected;
            }
            for range in &affected.ranges {
                match range_affects(range, version) {
                    Some(true) => return Match::Affected,
                    Some(false) => {}
                    None => result = Match::Undetermined,
                }
            }
        }
        result
    }
}

fn parse_version(raw: &str) -> Option<semver::Version> {
    let raw = raw.trim().trim_start_matches('v');
    if raw == "0" {
        return Some(semver::Version::new(0, 0, 0));
    }
    semver::Version::parse(raw).ok()
}

/// Evaluates an OSV range for a version. `None` when it cannot be evaluated.
///
/// SEMVER ranges are evaluated; ECOSYSTEM ranges are evaluated only when all
/// their versions happen to be valid semver (common for npm and crates.io).
fn range_affects(range: &Range, version: &str) -> Option<bool> {
    if !matches!(range.kind, RangeKind::Semver | RangeKind::Ecosystem) {
        return None;
    }
    let target = parse_version(version)?;
    let mut events = Vec::with_capacity(range.events.len());
    for event in &range.events {
        let raw = match event {
            Event::Introduced(v) | Event::Fixed(v) | Event::LastAffected(v) | Event::Limit(v) => v,
        };
        events.push((parse_version(raw)?, event));
    }
    events.sort_by(|a, b| a.0.cmp(&b.0));

    let mut affected = false;
    for (at, event) in events {
        match event {
            Event::Introduced(_) if at <= target => affected = true,
            Event::Fixed(_) if at <= target => affected = false,
            Event::LastAffected(_) if at < target => affected = false,
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
}
