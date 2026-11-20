//! Export of the inventory as a CycloneDX 1.5 JSON document (spec section 8.1),
//! so that other tools can read the registry.

use crate::model::Inventory;
use serde_json::{Value, json};

fn property(name: &str, value: impl Into<String>) -> Value {
    json!({ "name": name, "value": value.into() })
}

pub fn to_cyclonedx(inventory: &Inventory) -> Value {
    let components: Vec<Value> = inventory
        .components
        .iter()
        .map(|c| {
            json!({
                "type": "library",
                "bom-ref": c.purl,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "properties": [property("tocsin:origin", c.origin.label())],
            })
        })
        .collect();

    let services: Vec<Value> = inventory
        .services
        .iter()
        .map(|s| {
            let mut properties = vec![property(
                "tocsin:kind",
                serde_json::to_value(s.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default(),
            )];
            for listener in &s.listening {
                let exposure = serde_json::to_value(listener.exposure)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                properties.push(property(
                    "tocsin:listen",
                    format!(
                        "{}/{}:{} {exposure}",
                        listener.protocol, listener.address, listener.port
                    ),
                ));
            }
            if s.needs_restart() {
                properties.push(property("tocsin:needs-restart", "true"));
            }
            json!({ "bom-ref": s.id, "name": s.name, "properties": properties })
        })
        .collect();

    let dependencies: Vec<Value> = inventory
        .services
        .iter()
        .filter(|s| !s.uses.is_empty())
        .map(|s| json!({ "ref": s.id, "dependsOn": s.uses.iter().map(|u| u.purl.as_str()).collect::<Vec<_>>() }))
        .collect();

    let mut host_properties = Vec::new();
    if let Some(os) = &inventory.host.os_id {
        host_properties.push(property("tocsin:os", os.as_str()));
    }
    if let Some(version) = &inventory.host.os_version {
        host_properties.push(property("tocsin:os-version", version.as_str()));
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": { "components": [{ "type": "application", "name": "tocsin", "version": env!("CARGO_PKG_VERSION") }] },
            "component": {
                "type": "device",
                "bom-ref": "host",
                "name": inventory.host.hostname.clone().unwrap_or_else(|| "unknown".into()),
                "properties": host_properties,
            },
        },
        "components": components,
        "services": services,
        "dependencies": dependencies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn exports_components_services_and_dependencies() {
        let inventory = Inventory {
            host: Host {
                hostname: Some("srv-web-01".into()),
                os_id: Some("ubuntu".into()),
                os_version: None,
            },
            components: vec![Component {
                purl: "pkg:deb/ubuntu/nginx@1.24".into(),
                name: "nginx".into(),
                version: "1.24".into(),
                origin: Origin::Dpkg,
                declaration: None,
            }],
            services: vec![Service {
                id: "systemd:nginx.service".into(),
                kind: ServiceKind::SystemdUnit,
                name: "nginx.service".into(),
                pids: vec![10],
                listening: vec![Listener {
                    protocol: "tcp",
                    address: "0.0.0.0".into(),
                    port: 80,
                    exposure: Exposure::AllInterfaces,
                }],
                uses: vec![Usage {
                    purl: "pkg:deb/ubuntu/nginx@1.24".into(),
                    evidence: Evidence::Executable {
                        path: "/usr/sbin/nginx".into(),
                        replaced_on_disk: false,
                    },
                }],
                partial: false,
                separate_filesystem: false,
            }],
            warnings: vec![],
        };
        let bom = to_cyclonedx(&inventory);
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["components"][0]["purl"], "pkg:deb/ubuntu/nginx@1.24");
        assert_eq!(
            bom["services"][0]["properties"][1]["value"],
            "tcp/0.0.0.0:80 all_interfaces"
        );
        assert_eq!(
            bom["dependencies"][0]["dependsOn"][0],
            "pkg:deb/ubuntu/nginx@1.24"
        );
    }
}
