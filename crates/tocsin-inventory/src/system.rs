//! System package databases: dpkg (Debian, Ubuntu…) and rpm (Fedora, RHEL, SUSE…).

use crate::model::{Component, Origin, SourcePackage};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// `/etc/os-release` fields the inventory uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub id: Option<String>,
    pub version_id: Option<String>,
    /// Human-readable version, e.g. "26.04.1 LTS (Resolute Raccoon)".
    pub version: Option<String>,
}

impl OsRelease {
    /// The OSV.dev ecosystem of this distribution's packages, e.g.
    /// `Ubuntu:26.04:LTS` or `Debian:12`. `None` when OSV has no data for it.
    pub fn osv_ecosystem(&self) -> Option<String> {
        let version_id = self.version_id.as_deref()?;
        let major = version_id.split('.').next().unwrap_or(version_id);
        match self.id.as_deref()? {
            "ubuntu" => {
                let lts = self.version.as_deref().is_some_and(|v| v.contains("LTS"));
                Some(format!(
                    "Ubuntu:{version_id}{}",
                    if lts { ":LTS" } else { "" }
                ))
            }
            "debian" => Some(format!("Debian:{major}")),
            "almalinux" => Some(format!("AlmaLinux:{major}")),
            "rocky" => Some(format!("Rocky Linux:{major}")),
            _ => None,
        }
    }
}

pub fn parse_os_release(text: &str) -> OsRelease {
    let mut os = OsRelease::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'').to_owned();
        match key.trim() {
            "ID" => os.id = Some(value),
            "VERSION_ID" => os.version_id = Some(value),
            "VERSION" => os.version = Some(value),
            _ => {}
        }
    }
    os
}

/// An installed package, before conversion into a [`Component`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
    /// Source package, when it differs from the binary package (dpkg `Source:`).
    pub source: Option<SourcePackage>,
}

impl Package {
    pub fn into_component(self, ty: &str, distro: &str, origin: Origin) -> Component {
        let mut purl = format!("pkg:{ty}/{distro}/{}@{}", self.name, self.version);
        if let Some(arch) = &self.arch {
            purl.push_str("?arch=");
            purl.push_str(arch);
        }
        Component {
            purl,
            name: self.name,
            version: self.version,
            origin,
            declaration: None,
            source: self.source,
        }
    }
}

/// Parses a dpkg `Source:` field, `openssl` or `openssl (3.0.13-0ubuntu3)`.
/// Without an explicit version, the source has the binary package's version.
fn parse_dpkg_source(value: &str, binary_version: &str) -> SourcePackage {
    match value.split_once(' ') {
        Some((name, version)) => SourcePackage {
            name: name.to_owned(),
            version: version
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .to_owned(),
        },
        None => SourcePackage {
            name: value.to_owned(),
            version: binary_version.to_owned(),
        },
    }
}

/// Parses `/var/lib/dpkg/status`, keeping only installed packages.
pub fn parse_dpkg_status(text: &str) -> Vec<Package> {
    let mut packages = Vec::new();
    for paragraph in text.split("\n\n") {
        let (mut name, mut version, mut arch, mut installed) = (None, None, None, false);
        let mut source: Option<String> = None;
        for line in paragraph.lines() {
            if line.starts_with([' ', '\t']) {
                continue; // continuation of a multi-line field
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Package" => name = Some(value.to_owned()),
                "Version" => version = Some(value.to_owned()),
                "Architecture" => arch = Some(value.to_owned()),
                "Source" => source = Some(value.to_owned()),
                "Status" => installed = value.split_whitespace().nth(2) == Some("installed"),
                _ => {}
            }
        }
        if let (true, Some(name), Some(version)) = (installed, name, version) {
            let source = source.map(|s| parse_dpkg_source(&s, &version));
            packages.push(Package {
                name,
                version,
                arch,
                source,
            });
        }
    }
    packages
}

/// Maps every file installed by dpkg to its package name, from `info/*.list`.
pub fn dpkg_file_index(info_dir: &Path) -> std::io::Result<HashMap<String, String>> {
    let mut index = HashMap::new();
    for entry in std::fs::read_dir(info_dir)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".list") else {
            continue;
        };
        // Multi-arch packages are listed as `name:arch.list`.
        let package = stem.split(':').next().unwrap_or(stem).to_owned();
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if !line.is_empty() && line != "/." {
                index.insert(line.to_owned(), package.clone());
            }
        }
    }
    Ok(index)
}

const RPM_QUERY: &str = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n";
const RPM_FILES_QUERY: &str = "[%{FILENAMES}\t%{NAME}\n]";

/// Parses the output of `rpm -qa --qf RPM_QUERY`.
pub fn parse_rpm_packages(output: &str) -> Vec<Package> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let (name, epoch, version, release) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            let arch = fields.next().filter(|a| !a.is_empty() && *a != "(none)");
            let version = match epoch {
                "" | "0" => format!("{version}-{release}"),
                epoch => format!("{epoch}:{version}-{release}"),
            };
            Some(Package {
                name: name.to_owned(),
                version,
                arch: arch.map(str::to_owned),
                source: None,
            })
        })
        .collect()
}

/// Parses the output of `rpm -qa --qf RPM_FILES_QUERY`.
pub fn parse_rpm_files(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(file, name)| (file.to_owned(), name.to_owned()))
        .collect()
}

fn run_rpm(query: &str) -> Result<String, String> {
    let output = Command::new("rpm")
        .args(["-qa", "--qf", query])
        .output()
        .map_err(|e| format!("cannot run rpm: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "rpm failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Installed rpm packages and their file index, by running `rpm`.
pub fn rpm_inventory() -> Result<(Vec<Package>, HashMap<String, String>), String> {
    Ok((
        parse_rpm_packages(&run_rpm(RPM_QUERY)?),
        parse_rpm_files(&run_rpm(RPM_FILES_QUERY)?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release() {
        let os = parse_os_release(
            "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"26.04\"\nVERSION=\"26.04.1 LTS (Resolute Raccoon)\"\n",
        );
        assert_eq!(os.id.as_deref(), Some("ubuntu"));
        assert_eq!(os.version_id.as_deref(), Some("26.04"));
        assert_eq!(os.osv_ecosystem().as_deref(), Some("Ubuntu:26.04:LTS"));
    }

    #[test]
    fn osv_ecosystems() {
        let os = |id: &str, version_id: &str, version: &str| OsRelease {
            id: Some(id.into()),
            version_id: Some(version_id.into()),
            version: Some(version.into()),
        };
        assert_eq!(
            os("ubuntu", "25.10", "25.10 (Questing Quokka)")
                .osv_ecosystem()
                .as_deref(),
            Some("Ubuntu:25.10")
        );
        assert_eq!(
            os("debian", "12", "12 (bookworm)")
                .osv_ecosystem()
                .as_deref(),
            Some("Debian:12")
        );
        assert_eq!(
            os("rocky", "9.4", "9.4 (Blue Onyx)")
                .osv_ecosystem()
                .as_deref(),
            Some("Rocky Linux:9")
        );
        assert_eq!(os("gentoo", "2.15", "").osv_ecosystem(), None);
    }

    #[test]
    fn dpkg_status_keeps_installed_packages_only() {
        let status = "\
Package: libssl3t64
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.13-0ubuntu3
Description: Secure Sockets Layer toolkit
 multi-line description

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: nginx-core
Status: install ok installed
Architecture: amd64
Version: 1:1.24.0-2ubuntu7
";
        let packages = parse_dpkg_status(status);
        assert_eq!(packages.len(), 2);
        assert_eq!(
            packages[0].source,
            Some(SourcePackage {
                name: "openssl".into(),
                version: "3.0.13-0ubuntu3".into()
            })
        );
        assert_eq!(packages[1].source, None);
        assert_eq!(
            parse_dpkg_source("glibc (2.39-0ubuntu8)", "1:2.39"),
            SourcePackage {
                name: "glibc".into(),
                version: "2.39-0ubuntu8".into()
            }
        );
        let component = packages[1]
            .clone()
            .into_component("deb", "ubuntu", Origin::Dpkg);
        assert_eq!(
            component.purl,
            "pkg:deb/ubuntu/nginx-core@1:1.24.0-2ubuntu7?arch=amd64"
        );
    }

    #[test]
    fn rpm_output() {
        let packages = parse_rpm_packages(
            "openssl-libs\t1\t3.0.7\t27.el9\tx86_64\ngpg-pubkey\t0\tabc\tdef\t(none)\n",
        );
        assert_eq!(packages[0].version, "1:3.0.7-27.el9");
        assert_eq!(packages[1].arch, None);
        let files = parse_rpm_files("/usr/lib64/libssl.so.3\topenssl-libs\n");
        assert_eq!(files["/usr/lib64/libssl.so.3"], "openssl-libs");
    }
}
