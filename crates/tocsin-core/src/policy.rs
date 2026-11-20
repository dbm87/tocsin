//! The administrator's reaction policy (spec section 9.3).

use crate::advisory::Mitigation;
use crate::priority::Urgency;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub when: Condition,
    pub action: Action,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub notify: Vec<String>,
}

/// Every field left out matches anything.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Vec<Urgency>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<Exposure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    Local,
    Internet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Log,
    Notify,
    Propose,
    Mitigate,
}

/// What the agent knows when it applies the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub priority: Urgency,
    pub exposure: Exposure,
    /// The advisory signature was verified against the channel's declared signer.
    pub signed: bool,
}

/// Outcome of the policy for one advisory.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// Name of the rule that applied; `None` for the built-in default.
    pub rule: Option<String>,
    pub action: Action,
    /// Mitigations the agent may apply, in the advisory's order.
    pub mitigations: Vec<Mitigation>,
    pub notify: Vec<String>,
    /// Set when the decision was made safer than the rule asked, and why.
    pub downgraded: Option<&'static str>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid policy: {}", .0.join("; "))]
    Invalid(Vec<String>),
}

impl Condition {
    fn matches(&self, ctx: &Context) -> bool {
        self.priority
            .as_ref()
            .is_none_or(|p| p.contains(&ctx.priority))
            && self.exposure.is_none_or(|e| e == ctx.exposure)
            && self.signed.is_none_or(|s| s == ctx.signed)
    }
}

impl Policy {
    pub fn from_toml(input: &str) -> Result<Self, PolicyError> {
        let policy: Policy = toml::from_str(input)?;
        policy.validate()?;
        Ok(policy)
    }

    /// The policy shipped by default: notify only (spec section 9.3).
    pub fn default_policy() -> Self {
        Policy {
            rules: vec![Rule {
                name: "default".into(),
                when: Condition::default(),
                action: Action::Notify,
                allow: Vec::new(),
                notify: Vec::new(),
            }],
        }
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut problems = Vec::new();
        for rule in &self.rules {
            for kind in &rule.allow {
                if !Mitigation::KNOWN_KINDS.contains(&kind.as_str()) {
                    problems.push(format!(
                        "rule `{}`: unknown mitigation type `{kind}`",
                        rule.name
                    ));
                }
            }
            if rule.action == Action::Mitigate && rule.allow.is_empty() {
                problems.push(format!(
                    "rule `{}`: `mitigate` needs a non-empty `allow` list",
                    rule.name
                ));
            }
            if rule.action != Action::Mitigate && !rule.allow.is_empty() {
                problems.push(format!(
                    "rule `{}`: `allow` is only used by `mitigate`",
                    rule.name
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::Invalid(problems))
        }
    }

    /// Applies the first matching rule. Without any, the agent notifies.
    ///
    /// `mitigate` is downgraded to `propose` when the advisory is not signed,
    /// whatever the rule says (spec sections 9.3 and 10).
    pub fn decide(&self, ctx: &Context, offered: &[Mitigation]) -> Decision {
        let Some(rule) = self.rules.iter().find(|r| r.when.matches(ctx)) else {
            return Decision {
                rule: None,
                action: Action::Notify,
                mitigations: Vec::new(),
                notify: Vec::new(),
                downgraded: None,
            };
        };
        let mut decision = Decision {
            rule: Some(rule.name.clone()),
            action: rule.action,
            mitigations: Vec::new(),
            notify: rule.notify.clone(),
            downgraded: None,
        };
        if rule.action == Action::Mitigate {
            decision.mitigations = offered
                .iter()
                .filter(|m| rule.allow.iter().any(|kind| kind == m.kind()))
                .cloned()
                .collect();
            if !ctx.signed {
                decision.action = Action::Propose;
                decision.downgraded = Some("advisory not signed: automatic mitigation refused");
            } else if decision.mitigations.is_empty() {
                decision.action = Action::Propose;
                decision.downgraded = Some("no offered mitigation is allowed by this rule");
            }
        }
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
[[rule]]
name   = "critical exposed"
when   = { priority = ["critical"], exposure = "internet" }
action = "mitigate"
allow  = ["block_http_path"]
notify = ["email:admin"]

[[rule]]
name   = "fallback"
action = "notify"
"#;

    fn offered() -> Vec<Mitigation> {
        vec![
            Mitigation::Upgrade { to: "2.4.7".into() },
            Mitigation::BlockHttpPath {
                pattern: "/api/import*".into(),
            },
        ]
    }

    #[test]
    fn first_matching_rule_wins_and_filters_mitigations() {
        let policy = Policy::from_toml(POLICY).unwrap();
        let ctx = Context {
            priority: Urgency::Critical,
            exposure: Exposure::Internet,
            signed: true,
        };
        let d = policy.decide(&ctx, &offered());
        assert_eq!(d.rule.as_deref(), Some("critical exposed"));
        assert_eq!(d.action, Action::Mitigate);
        assert_eq!(
            d.mitigations,
            vec![Mitigation::BlockHttpPath {
                pattern: "/api/import*".into()
            }]
        );
    }

    #[test]
    fn unsigned_advisory_is_never_mitigated() {
        let policy = Policy::from_toml(POLICY).unwrap();
        let ctx = Context {
            priority: Urgency::Critical,
            exposure: Exposure::Internet,
            signed: false,
        };
        let d = policy.decide(&ctx, &offered());
        assert_eq!(d.action, Action::Propose);
        assert!(d.downgraded.is_some());
    }

    #[test]
    fn falls_through_to_next_rule() {
        let policy = Policy::from_toml(POLICY).unwrap();
        let ctx = Context {
            priority: Urgency::Critical,
            exposure: Exposure::Local,
            signed: true,
        };
        assert_eq!(
            policy.decide(&ctx, &offered()).rule.as_deref(),
            Some("fallback")
        );
    }

    #[test]
    fn default_policy_only_notifies() {
        let ctx = Context {
            priority: Urgency::Critical,
            exposure: Exposure::Internet,
            signed: true,
        };
        assert_eq!(
            Policy::default_policy().decide(&ctx, &offered()).action,
            Action::Notify
        );
    }

    #[test]
    fn rejects_invalid_rules() {
        let bad = "[[rule]]\nname = \"x\"\naction = \"mitigate\"\nallow = [\"teleport\"]\n";
        assert!(matches!(
            Policy::from_toml(bad),
            Err(PolicyError::Invalid(_))
        ));
        let typo = "[[rule]]\nname = \"x\"\naction = \"notify\"\nwhenn = {}\n";
        assert!(matches!(Policy::from_toml(typo), Err(PolicyError::Toml(_))));
    }
}
