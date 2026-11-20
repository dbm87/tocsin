//! The example files shipped in `examples/` must stay valid.

use std::path::PathBuf;
use tocsin_core::advisory::Match;
use tocsin_core::policy::Context;
use tocsin_core::{
    Action, Advisory, Declaration, Exposure, Policy, Purl, Signals, Urgency, effective_priority,
};

fn example(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn example_declaration_is_valid() {
    let declaration = Declaration::from_json_manifest(&example("declaration.json")).unwrap();
    assert!(declaration.allows_automatic_actions());
}

#[test]
fn example_policy_is_valid() {
    assert_eq!(
        Policy::from_toml(&example("policy.toml"))
            .unwrap()
            .rules
            .len(),
        3
    );
}

#[test]
fn end_to_end_on_examples() {
    let advisory = Advisory::from_json(&example("advisory.json")).unwrap();
    let policy = Policy::from_toml(&example("policy.toml")).unwrap();
    let ext = advisory
        .tocsin()
        .expect("example carries the tocsin extension");

    let installed: Purl = "pkg:npm/example-widget@2.3.1".parse().unwrap();
    assert_eq!(advisory.matches(&installed), Match::Affected);

    let signals = Signals {
        exploited: ext.exploited,
        network_reachable: ext.network_reachable,
        internet_exposed: true,
        ..Signals::default()
    };
    let priority = effective_priority(ext.urgency, &signals).unwrap();
    assert_eq!(priority, Urgency::Critical);

    let ctx = Context {
        priority,
        exposure: Exposure::Internet,
        signed: true,
    };
    let decision = policy.decide(&ctx, &ext.mitigations);
    assert_eq!(decision.action, Action::Mitigate);
    let kinds: Vec<_> = decision.mitigations.iter().map(|m| m.kind()).collect();
    // stop_service is offered by the advisory but not allowed by the policy.
    assert_eq!(kinds, ["upgrade", "block_http_path"]);
}
