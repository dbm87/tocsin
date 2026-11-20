//! Application dependencies from lockfiles (spec section 8.3, step 2).
//!
//! Lockfiles list indirect dependencies too, which is why the agent reads them
//! itself instead of relying on declarations by the parent package.

use crate::model::{Component, Origin};
use std::path::{Path, PathBuf};
use tocsin_core::Declaration;

/// A project directory designated by the administrator.
#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
    pub components: Vec<Component>,
    pub warnings: Vec<String>,
}

const NPM_LOCKFILES: [&str; 2] = ["package-lock.json", "npm-shrinkwrap.json"];

/// Reads every supported lockfile at the root of `dir`.
pub fn scan_project(dir: &Path) -> Result<Project, String> {
    let root = dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut project = Project {
        root: root.clone(),
        components: Vec::new(),
        warnings: Vec::new(),
    };
    let mut found = false;

    for name in NPM_LOCKFILES {
        let file = root.join(name);
        if let Ok(text) = std::fs::read_to_string(&file) {
            found = true;
            match parse_npm_lock(&text, &root, &file) {
                Ok(components) => project.components.extend(components),
                Err(e) => project.warnings.push(format!("{}: {e}", file.display())),
            }
            break;
        }
    }
    for (name, parse) in [
        (
            "Cargo.lock",
            parse_cargo_lock as fn(&str, &Path) -> Result<Vec<Component>, String>,
        ),
        ("poetry.lock", parse_poetry_lock),
    ] {
        let file = root.join(name);
        if let Ok(text) = std::fs::read_to_string(&file) {
            found = true;
            match parse(&text, &file) {
                Ok(components) => project.components.extend(components),
                Err(e) => project.warnings.push(format!("{}: {e}", file.display())),
            }
        }
    }
    if !found {
        return Err(format!(
            "{}: no supported lockfile (package-lock.json, npm-shrinkwrap.json, Cargo.lock, poetry.lock)",
            root.display()
        ));
    }
    Ok(project)
}

fn npm_purl(name: &str, version: &str) -> String {
    match name.strip_prefix('@') {
        Some(scoped) => format!("pkg:npm/%40{scoped}@{version}"),
        None => format!("pkg:npm/{name}@{version}"),
    }
}

/// `package-lock.json` version 2 or 3 (npm 7 and later).
pub fn parse_npm_lock(text: &str, root: &Path, file: &Path) -> Result<Vec<Component>, String> {
    let lock: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let packages = lock
        .get("packages")
        .and_then(|p| p.as_object())
        .ok_or("lockfileVersion 1 is not supported (regenerate it with npm 7 or later)")?;
    let mut components = Vec::new();
    for (key, entry) in packages {
        if key.is_empty() || entry.get("link").and_then(|l| l.as_bool()) == Some(true) {
            continue; // the project itself, or a symlinked workspace package
        }
        let name = match entry.get("name").and_then(|n| n.as_str()) {
            Some(name) => name,
            None => key.rsplit("node_modules/").next().unwrap_or(key),
        };
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        // A package may declare its own channel in its package.json (spec 5.2).
        let declaration = std::fs::read_to_string(root.join(key).join("package.json"))
            .ok()
            .and_then(|manifest| Declaration::from_json_manifest(&manifest).ok());
        components.push(Component {
            purl: npm_purl(name, version),
            name: name.to_owned(),
            version: version.to_owned(),
            origin: Origin::Lockfile {
                file: file.to_owned(),
            },
            declaration,
        });
    }
    Ok(components)
}

fn toml_packages(text: &str) -> Result<Vec<(String, String, bool)>, String> {
    let lock: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let Some(packages) = lock.get("package").and_then(|p| p.as_array()) else {
        return Ok(Vec::new());
    };
    Ok(packages
        .iter()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_owned();
            let version = p.get("version")?.as_str()?.to_owned();
            Some((name, version, p.get("source").is_some()))
        })
        .collect())
}

/// `Cargo.lock`. Packages without `source` are local workspace members: skipped.
pub fn parse_cargo_lock(text: &str, file: &Path) -> Result<Vec<Component>, String> {
    Ok(toml_packages(text)?
        .into_iter()
        .filter(|(_, _, has_source)| *has_source)
        .map(|(name, version, _)| Component {
            purl: format!("pkg:cargo/{name}@{version}"),
            name,
            version,
            origin: Origin::Lockfile {
                file: file.to_owned(),
            },
            declaration: None,
        })
        .collect())
}

/// `poetry.lock`. Names are normalised as PyPI does (PEP 503).
pub fn parse_poetry_lock(text: &str, file: &Path) -> Result<Vec<Component>, String> {
    Ok(toml_packages(text)?
        .into_iter()
        .map(|(name, version, _)| {
            let normalized = name.to_ascii_lowercase().replace(['_', '.'], "-");
            Component {
                purl: format!("pkg:pypi/{normalized}@{version}"),
                name,
                version,
                origin: Origin::Lockfile {
                    file: file.to_owned(),
                },
                declaration: None,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_lock_v3() {
        let lock = r#"{"name":"app","lockfileVersion":3,"packages":{
            "":{"name":"app","version":"1.0.0"},
            "node_modules/express":{"version":"4.19.2"},
            "node_modules/@angular/core":{"version":"17.0.0"},
            "node_modules/express/node_modules/debug":{"version":"2.6.9"},
            "packages/local":{"version":"0.0.1","link":true}}}"#;
        let components = parse_npm_lock(
            lock,
            Path::new("/nowhere"),
            Path::new("/nowhere/package-lock.json"),
        )
        .unwrap();
        let mut purls: Vec<_> = components.iter().map(|c| c.purl.as_str()).collect();
        purls.sort_unstable(); // JSON object order is not significant
        assert_eq!(
            purls,
            [
                "pkg:npm/%40angular/core@17.0.0",
                "pkg:npm/debug@2.6.9",
                "pkg:npm/express@4.19.2"
            ]
        );
        assert_eq!(components[0].origin.label(), "npm");
    }

    #[test]
    fn npm_lock_v1_is_reported() {
        let err = parse_npm_lock(
            r#"{"lockfileVersion":1,"dependencies":{}}"#,
            Path::new("/"),
            Path::new("/x"),
        )
        .unwrap_err();
        assert!(err.contains("lockfileVersion 1"));
    }

    #[test]
    fn cargo_lock_skips_workspace_members() {
        let lock = "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let components = parse_cargo_lock(lock, Path::new("/p/Cargo.lock")).unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].purl, "pkg:cargo/serde@1.0.200");
        assert_eq!(components[0].origin.label(), "cargo");
    }

    #[test]
    fn poetry_lock_normalises_names() {
        let lock = "[[package]]\nname = \"Django_REST.framework\"\nversion = \"3.15.1\"\n";
        let components = parse_poetry_lock(lock, Path::new("/p/poetry.lock")).unwrap();
        assert_eq!(components[0].purl, "pkg:pypi/django-rest-framework@3.15.1");
    }
}
