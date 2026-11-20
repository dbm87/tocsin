//! Effective priority of an advisory on a given machine (spec section 9.2).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Urgency levels, ordered from least to most urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Urgency {
    Low,
    Medium,
    High,
    Critical,
}

impl Urgency {
    /// Reads the textual ratings found in advisories: Tocsin's own levels,
    /// distribution ratings (Ubuntu "negligible", Red Hat "important"…) and
    /// GitHub's ("MODERATE"). Case-insensitive.
    pub fn from_label(label: &str) -> Option<Self> {
        match label.trim().to_ascii_lowercase().as_str() {
            "negligible" | "low" | "minor" => Some(Urgency::Low),
            "medium" | "moderate" => Some(Urgency::Medium),
            "high" | "important" => Some(Urgency::High),
            "critical" => Some(Urgency::Critical),
            _ => None,
        }
    }

    /// One level up, capped at `Critical`.
    pub fn raise(self) -> Self {
        match self {
            Urgency::Low => Urgency::Medium,
            Urgency::Medium => Urgency::High,
            Urgency::High | Urgency::Critical => Urgency::Critical,
        }
    }

    /// One level down, floored at `Low`.
    pub fn lower(self) -> Self {
        match self {
            Urgency::Critical => Urgency::High,
            Urgency::High => Urgency::Medium,
            Urgency::Medium | Urgency::Low => Urgency::Low,
        }
    }
}

impl fmt::Display for Urgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Urgency::Low => "low",
            Urgency::Medium => "medium",
            Urgency::High => "high",
            Urgency::Critical => "critical",
        })
    }
}

/// What the agent knows about an advisory and the machine when it prioritises.
#[derive(Debug, Clone, PartialEq)]
pub struct Signals {
    /// The vulnerability is listed in the CISA KEV catalog.
    pub in_kev: bool,
    /// The advisory states a known real-world exploitation.
    pub exploited: bool,
    /// At least one affected service is reachable from the Internet.
    pub internet_exposed: bool,
    /// The advisory states the flaw is exploitable remotely without authentication.
    pub network_reachable: bool,
    /// EPSS score, when known (0.0 to 1.0).
    pub epss: Option<f64>,
    /// EPSS score from which the priority is raised.
    pub epss_threshold: f64,
    /// The affected component is used by at least one active service.
    pub used_by_active_service: bool,
    /// A VEX statement from the publisher declares this configuration not affected.
    pub vex_not_affected: bool,
}

impl Default for Signals {
    fn default() -> Self {
        Signals {
            in_kev: false,
            exploited: false,
            internet_exposed: false,
            network_reachable: false,
            epss: None,
            // Provisional value: default thresholds are an open question (spec 12.1).
            epss_threshold: 0.1,
            used_by_active_service: true,
            vex_not_affected: false,
        }
    }
}

/// Applies the rules of spec section 9.2, in order.
///
/// Returns `None` when the agent must not notify at all (VEX "not affected").
pub fn effective_priority(base: Urgency, signals: &Signals) -> Option<Urgency> {
    if signals.vex_not_affected {
        return None;
    }
    let mut priority = base;
    if signals.in_kev || signals.exploited {
        priority = Urgency::Critical;
    }
    let exposed = signals.internet_exposed && signals.network_reachable;
    let likely = signals
        .epss
        .is_some_and(|score| score >= signals.epss_threshold);
    if exposed || likely {
        priority = priority.raise();
    }
    if !signals.used_by_active_service {
        priority = priority.lower();
    }
    Some(priority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_matches_urgency() {
        assert!(Urgency::Critical > Urgency::High);
        assert!(Urgency::Low < Urgency::Medium);
    }

    #[test]
    fn kev_or_exploited_forces_critical() {
        let signals = Signals {
            in_kev: true,
            ..Signals::default()
        };
        assert_eq!(
            effective_priority(Urgency::Low, &signals),
            Some(Urgency::Critical)
        );
        let signals = Signals {
            exploited: true,
            ..Signals::default()
        };
        assert_eq!(
            effective_priority(Urgency::Medium, &signals),
            Some(Urgency::Critical)
        );
    }

    #[test]
    fn exposure_needs_both_internet_and_network_reachable() {
        let only_internet = Signals {
            internet_exposed: true,
            ..Signals::default()
        };
        assert_eq!(
            effective_priority(Urgency::Medium, &only_internet),
            Some(Urgency::Medium)
        );
        let both = Signals {
            internet_exposed: true,
            network_reachable: true,
            ..Signals::default()
        };
        assert_eq!(
            effective_priority(Urgency::Medium, &both),
            Some(Urgency::High)
        );
    }

    #[test]
    fn epss_above_threshold_raises() {
        let signals = Signals {
            epss: Some(0.5),
            ..Signals::default()
        };
        assert_eq!(
            effective_priority(Urgency::High, &signals),
            Some(Urgency::Critical)
        );
        let below = Signals {
            epss: Some(0.01),
            ..Signals::default()
        };
        assert_eq!(
            effective_priority(Urgency::High, &below),
            Some(Urgency::High)
        );
    }

    #[test]
    fn unused_component_is_lowered() {
        let signals = Signals {
            used_by_active_service: false,
            ..Signals::default()
        };
        assert_eq!(
            effective_priority(Urgency::High, &signals),
            Some(Urgency::Medium)
        );
    }

    #[test]
    fn vex_not_affected_silences() {
        let signals = Signals {
            vex_not_affected: true,
            in_kev: true,
            ..Signals::default()
        };
        assert_eq!(effective_priority(Urgency::Critical, &signals), None);
    }
}
