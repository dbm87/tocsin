//! Correlation of the inventory with fallback sources (spec sections 9 and 11):
//! which advisory affects which component, used by which service, exposed how,
//! with which effective priority and policy decision.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use tocsin_core::advisory::Match;
use tocsin_core::policy::Context;
use tocsin_core::{Action, Advisory, Policy, Signals, Urgency, effective_priority};
use tocsin_inventory::Exposure;
use tocsin_inventory::model::{Inventory, Origin};
use tocsin_sources::osv::{Query, VulnRef};
use tocsin_sources::{kev, offline};

/// The OSV.dev queries for an inventory, deduplicated: binary packages built
/// from the same source package share one query.
#[derive(Debug, Default)]
pub struct Plan {
    pub queries: Vec<Query>,
    /// For each query: indexes of the inventory components it covers.
    pub components: Vec<Vec<usize>>,
    /// For each query: package name as OSV knows it, and the version asked.
    pub packages: Vec<(String, String)>,
    /// System packages skipped because OSV.dev has no data for this distribution.
    pub unsupported: usize,
}

pub fn plan(inventory: &Inventory) -> Plan {
    let mut grouped: BTreeMap<Query, (Vec<usize>, String, String)> = BTreeMap::new();
    let mut unsupported = 0;
    for (index, component) in inventory.components.iter().enumerate() {
        let (query, name, version) = match &component.origin {
            Origin::Dpkg | Origin::Rpm => {
                let Some(ecosystem) = &inventory.host.osv_ecosystem else {
                    unsupported += 1;
                    continue;
                };
                let (name, version) = match &component.source {
                    Some(source) => (source.name.clone(), source.version.clone()),
                    None => (component.name.clone(), component.version.clone()),
                };
                let query = Query::Package {
                    ecosystem: ecosystem.clone(),
                    name: name.clone(),
                    version: version.clone(),
                };
                (query, name, version)
            }
            Origin::Lockfile { .. } => (
                Query::Purl(component.purl.clone()),
                component.name.clone(),
                component.version.clone(),
            ),
        };
        grouped
            .entry(query)
            .or_insert_with(|| (Vec::new(), name, version))
            .0
            .push(index);
    }
    let mut plan = Plan {
        unsupported,
        ..Plan::default()
    };
    for (query, (components, name, version)) in grouped {
        plan.queries.push(query);
        plan.components.push(components);
        plan.packages.push((name, version));
    }
    plan
}

/// State of a local OSV database used by an offline scan.
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseInfo {
    pub ecosystem: String,
    /// Newest record modification date taken into account.
    pub synced: String,
    pub advisories: usize,
    /// The update failed or was skipped while due: the data may be outdated.
    pub stale: bool,
}

/// What an offline lookup found, in the shape of the online one.
#[derive(Debug, Default)]
pub struct OfflineLookup {
    pub matches: Vec<Vec<VulnRef>>,
    pub advisories: HashMap<String, Advisory>,
    pub databases: Vec<DatabaseInfo>,
    /// `package version: advisory` pairs whose versions could not be compared.
    pub undetermined: Vec<String>,
    pub warnings: Vec<String>,
}

/// Matches the plan against the local OSV databases, one per ecosystem,
/// updating them first according to `refresh`. Nothing about the inventory
/// is sent anywhere.
pub fn lookup_offline(
    plan: &Plan,
    store: &offline::Store,
    refresh: offline::Refresh,
) -> OfflineLookup {
    let mut lookup = OfflineLookup {
        matches: vec![Vec::new(); plan.queries.len()],
        ..OfflineLookup::default()
    };
    let targets: Vec<Option<(String, String, String)>> =
        plan.queries.iter().map(offline::query_target).collect();
    let mut ecosystems: Vec<&str> = targets.iter().flatten().map(|t| t.0.as_str()).collect();
    ecosystems.sort_unstable();
    ecosystems.dedup();

    let mut databases = HashMap::new();
    for ecosystem in ecosystems {
        match store.open(ecosystem, refresh) {
            Ok((db, update)) => {
                if let offline::Update::Failed(error) = update {
                    lookup.warnings.push(format!(
                        "OSV database for {ecosystem} not updated ({error}); using data up to {}",
                        db.synced
                    ));
                }
                lookup.databases.push(DatabaseInfo {
                    ecosystem: ecosystem.to_owned(),
                    synced: db.synced.clone(),
                    advisories: db.len(),
                    stale: db.stale,
                });
                databases.insert(ecosystem.to_owned(), db);
            }
            Err(error) => lookup
                .warnings
                .push(format!("{ecosystem} packages not looked up: {error:#}")),
        }
    }

    let unsupported = targets.iter().filter(|t| t.is_none()).count();
    if unsupported > 0 {
        lookup.warnings.push(format!(
            "{unsupported} package(s) of an ecosystem the offline mode does not handle"
        ));
    }
    for (index, target) in targets.iter().enumerate() {
        let Some((ecosystem, name, version)) = target else {
            continue;
        };
        let Some(db) = databases.get(ecosystem) else {
            continue;
        };
        for (advisory, matched) in db.query(name, version) {
            match matched {
                Match::Affected => {
                    lookup.matches[index].push(VulnRef {
                        id: advisory.id.clone(),
                        modified: advisory.modified.clone(),
                    });
                    lookup
                        .advisories
                        .entry(advisory.id.clone())
                        .or_insert_with(|| advisory.clone());
                }
                _ => lookup
                    .undetermined
                    .push(format!("{name} {version}: {}", advisory.id)),
            }
        }
    }
    lookup
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceUse {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<Exposure>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub advisory: String,
    /// Other advisories about the same CVEs for this package (e.g. an Ubuntu
    /// Security Notice grouping several per-CVE records): merged here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
    pub cves: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Package as OSV knows it (the source package for distributions).
    pub package: String,
    pub version: String,
    /// Installed components covered (binary packages, or the library itself).
    pub components: Vec<String>,
    pub fixed_in: Vec<String>,
    /// Severity given by the advisory; `None` when it states none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stated_urgency: Option<Urgency>,
    pub priority: Urgency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev: Option<kev::Entry>,
    pub network_reachable: bool,
    pub services: Vec<ServiceUse>,
    pub action: Action,
}

impl Finding {
    pub fn widest_exposure(&self) -> Option<Exposure> {
        self.services.iter().filter_map(|s| s.exposure).max()
    }
}

/// Builds the findings, most urgent first.
pub fn correlate(
    inventory: &Inventory,
    plan: &Plan,
    matches: &[Vec<VulnRef>],
    advisories: &HashMap<String, Advisory>,
    kev: &kev::Catalog,
    policy: &Policy,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (query_index, vulns) in matches.iter().enumerate() {
        let components = &plan.components[query_index];
        let (package, version) = &plan.packages[query_index];
        let ecosystem = match &plan.queries[query_index] {
            Query::Package { ecosystem, .. } => Some(ecosystem.as_str()),
            Query::Purl(_) => None,
        };
        let mut found: Vec<Finding> = Vec::new();
        let mut services: Vec<ServiceUse> = Vec::new();
        for &component in components {
            for service in inventory.services_using(&inventory.components[component].purl) {
                if !services.iter().any(|s| s.id == service.id) {
                    services.push(ServiceUse {
                        id: service.id.clone(),
                        name: service.name.clone(),
                        exposure: service.exposure(),
                    });
                }
            }
        }
        services.sort_by(|a, b| b.exposure.cmp(&a.exposure).then(a.name.cmp(&b.name)));
        let internet = services
            .iter()
            .filter_map(|s| s.exposure)
            .any(|e| e.to_policy() == tocsin_core::Exposure::Internet);

        for vuln in vulns {
            let Some(advisory) = advisories.get(&vuln.id) else {
                continue;
            };
            let cves: Vec<String> = advisory.cve_ids().into_iter().map(str::to_owned).collect();
            let kev_entry = cves.iter().find_map(|cve| kev.get(cve)).cloned();
            let stated_urgency = advisory.stated_urgency();
            let signals = Signals {
                in_kev: kev_entry.is_some(),
                exploited: advisory.tocsin().is_some_and(|ext| ext.exploited),
                internet_exposed: internet,
                network_reachable: advisory.network_reachable(),
                used_by_active_service: !services.is_empty(),
                ..Signals::default()
            };
            // An advisory without any severity is treated as medium.
            let base = stated_urgency.unwrap_or(Urgency::Medium);
            let priority = effective_priority(base, &signals).unwrap_or(base);
            let context = Context {
                priority,
                exposure: if internet {
                    tocsin_core::Exposure::Internet
                } else {
                    tocsin_core::Exposure::Local
                },
                // Fallback sources are never signed by the publisher (spec section 11).
                signed: false,
            };
            let offered = advisory
                .tocsin()
                .map(|ext| ext.mitigations.as_slice())
                .unwrap_or_default();
            let decision = policy.decide(&context, offered);
            found.push(Finding {
                advisory: advisory.id.clone(),
                related: Vec::new(),
                cves,
                summary: advisory.summary.clone(),
                package: package.clone(),
                version: version.clone(),
                components: components
                    .iter()
                    .map(|&i| inventory.components[i].name.clone())
                    .collect(),
                fixed_in: advisory
                    .fixed_versions(package, ecosystem)
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                stated_urgency,
                priority,
                kev: kev_entry,
                network_reachable: signals.network_reachable,
                services: services.clone(),
                action: decision.action,
            });
        }
        findings.extend(merge_same_cves(found));
    }
    findings.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.kev.is_some().cmp(&a.kev.is_some()))
            .then(b.widest_exposure().cmp(&a.widest_exposure()))
            .then(a.package.cmp(&b.package))
            .then(a.advisory.cmp(&b.advisory))
    });
    findings
}

/// For one package, drops advisories whose CVEs are all covered by other
/// advisories, and lists them as `related` there. Narrow advisories (one CVE)
/// are kept in preference to grouped notices; advisories without any CVE are
/// always kept.
fn merge_same_cves(mut found: Vec<Finding>) -> Vec<Finding> {
    found.sort_by_key(|f| (f.cves.is_empty(), f.cves.len()));
    let mut kept: Vec<Finding> = Vec::new();
    for finding in found {
        let covered = !finding.cves.is_empty()
            && finding
                .cves
                .iter()
                .all(|cve| kept.iter().any(|k| k.cves.contains(cve)));
        if !covered {
            kept.push(finding);
            continue;
        }
        for target in kept
            .iter_mut()
            .filter(|k| k.cves.iter().any(|cve| finding.cves.contains(cve)))
        {
            target.related.push(finding.advisory.clone());
            if target.summary.is_none() {
                target.summary.clone_from(&finding.summary);
            }
            if target.fixed_in.is_empty() {
                target.fixed_in.clone_from(&finding.fixed_in);
            }
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use tocsin_inventory::model::{
        Component, Evidence, Host, Listener, Service, ServiceKind, SourcePackage, Usage,
    };

    fn component(name: &str, source: Option<&str>, origin: Origin) -> Component {
        let purl = match origin {
            Origin::Lockfile { .. } => format!("pkg:npm/{name}@1.0.0"),
            _ => format!("pkg:deb/ubuntu/{name}@3.0.13-0ubuntu3?arch=amd64"),
        };
        Component {
            purl,
            name: name.into(),
            version: if matches!(origin, Origin::Lockfile { .. }) {
                "1.0.0".into()
            } else {
                "3.0.13-0ubuntu3".into()
            },
            origin,
            declaration: None,
            source: source.map(|s| SourcePackage {
                name: s.into(),
                version: "3.0.13-0ubuntu3".into(),
            }),
        }
    }

    fn inventory() -> Inventory {
        let components = vec![
            component("libssl3t64", Some("openssl"), Origin::Dpkg),
            component("openssl", Some("openssl"), Origin::Dpkg),
            component(
                "left-pad",
                None,
                Origin::Lockfile {
                    file: "/srv/app/package-lock.json".into(),
                },
            ),
        ];
        let sshd = Service {
            id: "systemd:ssh.service".into(),
            kind: ServiceKind::SystemdUnit,
            name: "ssh.service".into(),
            pids: vec![1],
            listening: vec![Listener {
                protocol: "tcp",
                address: "0.0.0.0".into(),
                port: 22,
                exposure: Exposure::AllInterfaces,
            }],
            uses: vec![Usage {
                purl: components[0].purl.clone(),
                evidence: Evidence::LoadedFile {
                    path: "/usr/lib/x86_64-linux-gnu/libssl.so.3".into(),
                    replaced_on_disk: false,
                },
            }],
            partial: false,
            separate_filesystem: false,
        };
        Inventory {
            host: Host {
                osv_ecosystem: Some("Ubuntu:24.04:LTS".into()),
                ..Host::default()
            },
            components,
            services: vec![sshd],
            warnings: vec![],
        }
    }

    #[test]
    fn plan_groups_binaries_by_source_package() {
        let plan = plan(&inventory());
        assert_eq!(
            plan.queries.len(),
            2,
            "libssl3t64 and openssl share the openssl source"
        );
        let openssl = plan
            .queries
            .iter()
            .position(|q| matches!(q, Query::Package { name, .. } if name == "openssl"))
            .unwrap();
        assert_eq!(plan.components[openssl], [0, 1]);
        assert!(
            plan.queries
                .contains(&Query::Purl("pkg:npm/left-pad@1.0.0".into()))
        );
    }

    #[test]
    fn unknown_distribution_skips_system_packages() {
        let mut inventory = inventory();
        inventory.host.osv_ecosystem = None;
        let plan = plan(&inventory);
        assert_eq!(plan.unsupported, 2);
        assert_eq!(plan.queries.len(), 1);
    }

    #[test]
    fn kev_and_exposure_drive_priority() {
        let inventory = inventory();
        let plan = plan(&inventory);
        let openssl = plan
            .queries
            .iter()
            .position(|q| matches!(q, Query::Package { .. }))
            .unwrap();
        let mut matches = vec![Vec::new(); plan.queries.len()];
        matches[openssl] = vec![
            VulnRef {
                id: "UBUNTU-CVE-2026-0001".into(),
                modified: String::new(),
            },
            VulnRef {
                id: "UBUNTU-CVE-2026-0002".into(),
                modified: String::new(),
            },
        ];
        let advisory = |id: &str, cve: &str, rating: &str| {
            Advisory::from_json(&format!(
                r#"{{"id":"{id}","modified":"x","upstream":["{cve}"],"severity":[{{"type":"Ubuntu","score":"{rating}"}}],
                    "affected":[{{"package":{{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"}},
                    "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"3.0.13-0ubuntu3.9"}}]}}]}}]}}"#
            ))
            .unwrap()
        };
        let advisories: HashMap<String, Advisory> = [
            advisory("UBUNTU-CVE-2026-0001", "CVE-2026-0001", "low"),
            advisory("UBUNTU-CVE-2026-0002", "CVE-2026-0002", "medium"),
        ]
        .into_iter()
        .map(|a| (a.id.clone(), a))
        .collect();
        let kev = kev::Catalog::from_json(
            r#"{"catalogVersion":"t","vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":"2026-11-01"}]}"#,
        )
        .unwrap();

        let findings = correlate(
            &inventory,
            &plan,
            &matches,
            &advisories,
            &kev,
            &Policy::default_policy(),
        );
        assert_eq!(findings.len(), 2);
        // Rated low by Ubuntu, but actively exploited: critical, and listed first.
        assert_eq!(findings[0].advisory, "UBUNTU-CVE-2026-0001");
        assert_eq!(findings[0].priority, Urgency::Critical);
        assert_eq!(findings[0].components, ["libssl3t64", "openssl"]);
        assert_eq!(findings[0].fixed_in, ["3.0.13-0ubuntu3.9"]);
        assert_eq!(findings[0].services[0].name, "ssh.service");
        assert_eq!(findings[0].action, Action::Notify);
        // Medium, used by a service but not remotely exploitable per its data: unchanged.
        assert_eq!(findings[1].priority, Urgency::Medium);
    }

    fn finding(advisory: &str, cves: &[&str], fixed: &[&str]) -> Finding {
        Finding {
            advisory: advisory.into(),
            related: Vec::new(),
            cves: cves.iter().map(|c| (*c).into()).collect(),
            summary: None,
            package: "glibc".into(),
            version: "2.35-0ubuntu3.1".into(),
            components: vec!["libc6".into()],
            fixed_in: fixed.iter().map(|f| (*f).into()).collect(),
            stated_urgency: None,
            priority: Urgency::Medium,
            kev: None,
            network_reachable: false,
            services: Vec::new(),
            action: Action::Notify,
        }
    }

    #[test]
    fn grouped_notices_merge_into_per_cve_advisories() {
        let merged = merge_same_cves(vec![
            finding(
                "USN-6409-1",
                &["CVE-2023-4806", "CVE-2023-4911"],
                &["2.35-0ubuntu3.4"],
            ),
            finding("UBUNTU-CVE-2023-4911", &["CVE-2023-4911"], &[]),
            finding(
                "UBUNTU-CVE-2023-4806",
                &["CVE-2023-4806"],
                &["2.35-0ubuntu3.4"],
            ),
            finding("GHSA-no-cve", &[], &[]),
        ]);
        let ids: Vec<&str> = merged.iter().map(|f| f.advisory.as_str()).collect();
        assert_eq!(
            ids,
            [
                "UBUNTU-CVE-2023-4911",
                "UBUNTU-CVE-2023-4806",
                "GHSA-no-cve"
            ]
        );
        assert_eq!(merged[0].related, ["USN-6409-1"]);
        assert_eq!(
            merged[0].fixed_in,
            ["2.35-0ubuntu3.4"],
            "taken from the notice"
        );
        assert_eq!(merged[1].related, ["USN-6409-1"]);
        // A notice with a CVE no other advisory covers is kept.
        let kept = merge_same_cves(vec![
            finding("USN-1", &["CVE-1", "CVE-2"], &[]),
            finding("UBUNTU-CVE-1", &["CVE-1"], &[]),
        ]);
        assert_eq!(kept.len(), 2);
    }
}
