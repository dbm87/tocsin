//! What the inventory produces: the content of the local registry (spec section 8.2).

use serde::Serialize;
use std::path::PathBuf;
use tocsin_core::Declaration;

#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub host: Host,
    pub components: Vec<Component>,
    pub services: Vec<Service>,
    /// Problems that make the inventory partial (permissions, unreadable files…).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Host {
    pub hostname: Option<String>,
    pub os_id: Option<String>,
    pub os_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Component {
    /// Package URL including the version.
    pub purl: String,
    pub name: String,
    pub version: String,
    pub origin: Origin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration: Option<Declaration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    Dpkg,
    Rpm,
    Lockfile { file: PathBuf },
}

impl Origin {
    pub fn label(&self) -> &'static str {
        match self {
            Origin::Dpkg => "dpkg",
            Origin::Rpm => "rpm",
            Origin::Lockfile { file } => match file.file_name().and_then(|n| n.to_str()) {
                Some("Cargo.lock") => "cargo",
                Some("poetry.lock") => "poetry",
                _ => "npm",
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Service {
    /// Stable identifier: `systemd:<unit>`, `container:<id>` or `process:<pid>`.
    pub id: String,
    pub kind: ServiceKind,
    pub name: String,
    pub pids: Vec<u32>,
    pub listening: Vec<Listener>,
    pub uses: Vec<Usage>,
    /// Some of its processes could not be inspected (insufficient permissions).
    pub partial: bool,
    /// Some of its processes see another filesystem (container, Flatpak, Snap):
    /// their files are not attributed to host packages, and their own content
    /// is not inventoried yet.
    pub separate_filesystem: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    SystemdUnit,
    Container,
    Process,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Listener {
    pub protocol: &'static str,
    pub address: String,
    pub port: u16,
    pub exposure: Exposure,
}

/// Where a listening socket can be reached from, judged from its bind address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Loopback,
    Lan,
    AllInterfaces,
    Public,
}

impl Exposure {
    /// Conservative mapping to the policy's notion of exposure: a socket bound
    /// to every interface is treated as reachable from the Internet.
    pub fn to_policy(self) -> tocsin_core::Exposure {
        match self {
            Exposure::Loopback | Exposure::Lan => tocsin_core::Exposure::Local,
            Exposure::AllInterfaces | Exposure::Public => tocsin_core::Exposure::Internet,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub purl: String,
    pub evidence: Evidence,
}

/// How the link between a component and a service was established (spec 8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// The service runs this executable.
    Executable {
        path: PathBuf,
        replaced_on_disk: bool,
    },
    /// The service has this file mapped in memory (shared library…).
    LoadedFile {
        path: PathBuf,
        replaced_on_disk: bool,
    },
    /// The service runs from a project directory whose lockfile lists the component.
    WorkingDirectory { project: PathBuf },
}

impl Evidence {
    /// The file in memory is no longer the one on disk: the package was
    /// upgraded but the service still runs the old code until restarted.
    pub fn replaced_on_disk(&self) -> bool {
        matches!(
            self,
            Evidence::Executable {
                replaced_on_disk: true,
                ..
            } | Evidence::LoadedFile {
                replaced_on_disk: true,
                ..
            }
        )
    }
}

impl Service {
    pub fn needs_restart(&self) -> bool {
        self.uses.iter().any(|u| u.evidence.replaced_on_disk())
    }

    /// The widest exposure among its listening sockets.
    pub fn exposure(&self) -> Option<Exposure> {
        self.listening.iter().map(|l| l.exposure).max()
    }
}

impl Inventory {
    /// Services using the component designated by this purl (with version).
    pub fn services_using<'a>(&'a self, purl: &'a str) -> impl Iterator<Item = &'a Service> + 'a {
        self.services
            .iter()
            .filter(move |s| s.uses.iter().any(|u| u.purl == purl))
    }
}
