//! CVSS v3.x base score, computed from a vector string.
//!
//! Advisories often carry only the vector (`CVSS:3.1/AV:N/AC:L/…`); the score
//! is needed to derive an urgency when no textual severity is given.

use crate::priority::Urgency;

/// Base metrics of a CVSS v3.0 or v3.1 vector.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CvssV3 {
    attack_vector: f64,
    attack_complexity: f64,
    privileges_required: f64,
    user_interaction: f64,
    scope_changed: bool,
    confidentiality: f64,
    integrity: f64,
    availability: f64,
    /// `AV:N`: exploitable over the network.
    pub network: bool,
}

impl CvssV3 {
    /// Parses a `CVSS:3.0/…` or `CVSS:3.1/…` vector. `None` when a base metric
    /// is missing or unknown, or for another CVSS version.
    pub fn parse(vector: &str) -> Option<Self> {
        let rest = vector
            .strip_prefix("CVSS:3.1/")
            .or_else(|| vector.strip_prefix("CVSS:3.0/"))?;
        let metric = |name: &str| {
            rest.split('/')
                .filter_map(|part| part.split_once(':'))
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value)
        };
        let scope_changed = match metric("S")? {
            "U" => false,
            "C" => true,
            _ => return None,
        };
        let impact = |value| match value {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        };
        let attack_vector_code = metric("AV")?;
        Some(CvssV3 {
            attack_vector: match attack_vector_code {
                "N" => 0.85,
                "A" => 0.62,
                "L" => 0.55,
                "P" => 0.2,
                _ => return None,
            },
            attack_complexity: match metric("AC")? {
                "L" => 0.77,
                "H" => 0.44,
                _ => return None,
            },
            privileges_required: match (metric("PR")?, scope_changed) {
                ("N", _) => 0.85,
                ("L", false) => 0.62,
                ("L", true) => 0.68,
                ("H", false) => 0.27,
                ("H", true) => 0.5,
                _ => return None,
            },
            user_interaction: match metric("UI")? {
                "N" => 0.85,
                "R" => 0.62,
                _ => return None,
            },
            scope_changed,
            confidentiality: impact(metric("C")?)?,
            integrity: impact(metric("I")?)?,
            availability: impact(metric("A")?)?,
            network: attack_vector_code == "N",
        })
    }

    /// Base score, from 0.0 to 10.0 (CVSS v3.1 specification, section 7.1).
    pub fn base_score(&self) -> f64 {
        let iss =
            1.0 - (1.0 - self.confidentiality) * (1.0 - self.integrity) * (1.0 - self.availability);
        let impact = if self.scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
        } else {
            6.42 * iss
        };
        if impact <= 0.0 {
            return 0.0;
        }
        let exploitability = 8.22
            * self.attack_vector
            * self.attack_complexity
            * self.privileges_required
            * self.user_interaction;
        let total = if self.scope_changed {
            1.08 * (impact + exploitability)
        } else {
            impact + exploitability
        };
        round_up(total.min(10.0))
    }

    /// Qualitative rating of the base score (CVSS v3.1 specification, section 5).
    pub fn urgency(&self) -> Urgency {
        match self.base_score() {
            s if s >= 9.0 => Urgency::Critical,
            s if s >= 7.0 => Urgency::High,
            s if s >= 4.0 => Urgency::Medium,
            _ => Urgency::Low,
        }
    }
}

/// The CVSS v3.1 "Roundup" function, which avoids floating-point surprises.
fn round_up(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        (scaled / 10_000 + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(vector: &str) -> f64 {
        CvssV3::parse(vector).unwrap().base_score()
    }

    #[test]
    fn reference_scores() {
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"), 5.3);
        assert_eq!(score("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 6.2);
        assert_eq!(score("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 4.6);
        assert_eq!(score("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"), 5.4);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
    }

    #[test]
    fn urgency_and_network_flag() {
        let cvss = CvssV3::parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(cvss.urgency(), Urgency::Critical);
        assert!(cvss.network);
        let local = CvssV3::parse("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H").unwrap();
        assert_eq!(local.urgency(), Urgency::Medium);
        assert!(!local.network);
    }

    #[test]
    fn rejects_other_versions_and_garbage() {
        assert!(
            CvssV3::parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
                .is_none()
        );
        assert!(CvssV3::parse("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_none());
        assert!(CvssV3::parse("CVSS:3.1/AV:N").is_none());
    }
}
