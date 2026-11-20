//! Linux inventory for the Tocsin agent (spec section 8).
//!
//! Answers the registry's question: which component, in which version, is used
//! by which service, and is that service reachable from the network?
//!
//! Sources: dpkg or rpm databases, lockfiles of designated projects, `/proc`
//! (processes, mapped files, cgroups, sockets). Everything is read-only.

pub mod cyclonedx;
pub mod lockfiles;
pub mod model;
pub mod net;
pub mod procfs;
pub mod system;

use crate::lockfiles::Project;
use crate::model::{
    Component, Evidence, Host, Inventory, Listener, Origin, Service, ServiceKind, Usage,
};
use crate::net::Socket;
use crate::procfs::{Owner, Process};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use tocsin_core::Declaration;

pub use model::Exposure;

#[derive(Debug, Clone)]
pub struct Options {
    /// Root of the filesystem holding package databases (`/` normally).
    pub fs_root: PathBuf,
    /// Mount point of procfs (`/proc` normally).
    pub proc_root: PathBuf,
    /// Project directories whose lockfiles are read (spec 8.3: designated by the administrator).
    pub projects: Vec<PathBuf>,
    /// Query rpm when its database is present.
    pub rpm: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            fs_root: "/".into(),
            proc_root: "/proc".into(),
            projects: Vec::new(),
            rpm: true,
        }
    }
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Builds the inventory of the machine. Never fails: what cannot be read is
/// reported in [`Inventory::warnings`].
pub fn collect(options: &Options) -> Inventory {
    let mut warnings = Vec::new();
    let os = std::fs::read_to_string(options.fs_root.join("etc/os-release"))
        .map(|text| system::parse_os_release(&text))
        .unwrap_or_default();
    let distro = os.id.clone().unwrap_or_else(|| "linux".into());
    let host = Host {
        hostname: read_trimmed(&options.proc_root.join("sys/kernel/hostname")),
        os_id: os.id,
        os_version: os.version_id,
    };

    let mut components = Vec::new();
    // Installed file -> purl of the package that owns it.
    let mut files: HashMap<String, String> = HashMap::new();

    let dpkg_status = options.fs_root.join("var/lib/dpkg/status");
    if let Ok(text) = std::fs::read_to_string(&dpkg_status) {
        let packages = system::parse_dpkg_status(&text);
        let mut purl_by_name = HashMap::new();
        for package in packages {
            let component = package.into_component("deb", &distro, Origin::Dpkg);
            purl_by_name
                .entry(component.name.clone())
                .or_insert_with(|| component.purl.clone());
            components.push(component);
        }
        match system::dpkg_file_index(&options.fs_root.join("var/lib/dpkg/info")) {
            Ok(index) => files.extend(
                index
                    .into_iter()
                    .filter_map(|(file, name)| Some((file, purl_by_name.get(&name)?.clone()))),
            ),
            Err(e) => warnings.push(format!("cannot read the dpkg file lists: {e}")),
        }
    }

    let rpm_db_present = ["var/lib/rpm", "usr/lib/sysimage/rpm"].iter().any(|dir| {
        options.fs_root.join(dir).join("rpmdb.sqlite").exists()
            || options.fs_root.join(dir).join("Packages").exists()
    });
    if options.rpm && rpm_db_present {
        match system::rpm_inventory() {
            Ok((packages, index)) => {
                let mut purl_by_name = HashMap::new();
                for package in packages {
                    let component = package.into_component("rpm", &distro, Origin::Rpm);
                    purl_by_name
                        .entry(component.name.clone())
                        .or_insert_with(|| component.purl.clone());
                    components.push(component);
                }
                files.extend(
                    index
                        .into_iter()
                        .filter_map(|(file, name)| Some((file, purl_by_name.get(&name)?.clone()))),
                );
            }
            Err(e) => warnings.push(e),
        }
    }

    attach_system_declarations(
        &options.fs_root.join("usr/share/tocsin"),
        &mut components,
        &mut warnings,
    );

    let mut projects = Vec::new();
    for dir in &options.projects {
        match lockfiles::scan_project(dir) {
            Ok(mut project) => {
                warnings.append(&mut project.warnings);
                components.extend(project.components.iter().cloned());
                projects.push(project);
            }
            Err(e) => warnings.push(e),
        }
    }

    // The same component may come from several lockfiles: keep the first.
    let mut seen = HashSet::new();
    components.retain(|c| seen.insert(c.purl.clone()));

    let services = match procfs::scan(&options.proc_root) {
        Ok(scan) => {
            if scan.denied > 0 {
                warnings.push(format!(
                    "{} process(es) could not be fully inspected: run as root for a complete inventory",
                    scan.denied
                ));
            }
            let sockets = net::listening_sockets(&options.proc_root, &scan.processes);
            let host_root = procfs::root_id(&options.proc_root.join("1"))
                .or_else(|| procfs::root_id(&options.proc_root.join("self")));
            build_services(&scan.processes, &sockets, &files, &projects, host_root)
        }
        Err(e) => {
            warnings.push(format!("cannot read {}: {e}", options.proc_root.display()));
            Vec::new()
        }
    };

    Inventory {
        host,
        components,
        services,
        warnings,
    }
}

/// `/usr/share/tocsin/<package>.json`, installed by system packages (spec 5.2).
fn attach_system_declarations(
    dir: &Path,
    components: &mut [Component],
    warnings: &mut Vec<String>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for path in entries.filter_map(|e| e.ok().map(|e| e.path())) {
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let declaration = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|text| Declaration::from_json_manifest(&text).map_err(|e| e.to_string()));
        match declaration {
            Ok(declaration) => {
                for component in components
                    .iter_mut()
                    .filter(|c| c.name == name && matches!(c.origin, Origin::Dpkg | Origin::Rpm))
                {
                    component.declaration = Some(declaration.clone());
                }
            }
            Err(e) => warnings.push(format!("{}: {e}", path.display())),
        }
    }
}

/// Finds the package owning a file, tolerating the `/usr` merge: the kernel
/// reports `/usr/lib/…` while dpkg may have recorded `/lib/…`, and conversely.
fn owning_package<'a>(files: &'a HashMap<String, String>, path: &Path) -> Option<&'a String> {
    const MERGED: [(&str, &str); 5] = [
        ("/usr/lib/", "/lib/"),
        ("/usr/lib64/", "/lib64/"),
        ("/usr/lib32/", "/lib32/"),
        ("/usr/bin/", "/bin/"),
        ("/usr/sbin/", "/sbin/"),
    ];
    let path = path.to_str()?;
    if let Some(purl) = files.get(path) {
        return Some(purl);
    }
    MERGED.iter().find_map(|(merged, legacy)| {
        if let Some(rest) = path.strip_prefix(merged) {
            files.get(&format!("{legacy}{rest}"))
        } else {
            path.strip_prefix(legacy)
                .and_then(|rest| files.get(&format!("{merged}{rest}")))
        }
    })
}

struct ServiceBuilder {
    service: Service,
    uses: BTreeMap<String, Evidence>,
}

impl ServiceBuilder {
    fn add(&mut self, purl: &str, evidence: Evidence) {
        match self.uses.get_mut(purl) {
            None => {
                self.uses.insert(purl.to_owned(), evidence);
            }
            // A replaced file is the more important fact: it means "restart needed".
            Some(existing) if evidence.replaced_on_disk() && !existing.replaced_on_disk() => {
                *existing = evidence
            }
            Some(_) => {}
        }
    }
}

/// Groups processes into services and links them to components and sockets.
///
/// Processes outside any systemd unit or container are kept only when they
/// listen on a port or run from a designated project, to avoid listing shells.
///
/// Files are attributed to host packages only for processes that see the
/// host's root directory (`host_root`): a container maps files of its own
/// image, and attributing them to host packages would be wrong.
///
/// systemd (PID 1) holds the sockets of socket-activated units: such a socket
/// is reported under the unit using it, or under "systemd (socket activation)"
/// while no unit has started yet.
pub fn build_services(
    processes: &[Process],
    sockets: &HashMap<u64, Socket>,
    files: &HashMap<String, String>,
    projects: &[Project],
    host_root: Option<procfs::RootId>,
) -> Vec<Service> {
    let owners: Vec<Owner> = processes
        .iter()
        .map(|p| procfs::owner(p.cgroup.as_deref()))
        .collect();
    let held_by_services: HashSet<u64> = processes
        .iter()
        .zip(&owners)
        .filter(|(_, owner)| **owner != Owner::Init)
        .flat_map(|(p, _)| p.socket_inodes.iter().copied())
        .collect();

    let mut builders: BTreeMap<String, ServiceBuilder> = BTreeMap::new();
    for (process, owner) in processes.iter().zip(owners) {
        let host_filesystem = !matches!(owner, Owner::Container(_))
            && match (host_root, process.root) {
                (Some(host), Some(own)) => host == own,
                _ => true,
            };
        let listeners: Vec<Listener> = process
            .socket_inodes
            .iter()
            .filter(|inode| owner != Owner::Init || !held_by_services.contains(inode))
            .filter_map(|inode| sockets.get(inode))
            .map(Listener::from)
            .collect();
        let in_projects: Vec<&Project> = projects
            .iter()
            .filter(|project| {
                host_filesystem
                    && process
                        .cwd
                        .as_ref()
                        .is_some_and(|cwd| cwd.starts_with(&project.root))
            })
            .collect();
        let (id, kind, name) = match owner {
            Owner::Unit(unit) => (format!("systemd:{unit}"), ServiceKind::SystemdUnit, unit),
            Owner::Container(id) => (format!("container:{id}"), ServiceKind::Container, id),
            Owner::Init if listeners.is_empty() => continue,
            Owner::Init => (
                "systemd:init.scope".to_owned(),
                ServiceKind::SystemdUnit,
                "systemd (socket activation)".to_owned(),
            ),
            Owner::Process if listeners.is_empty() && in_projects.is_empty() => continue,
            Owner::Process => (
                format!("process:{}", process.pid),
                ServiceKind::Process,
                process.comm.clone(),
            ),
        };
        let builder = builders
            .entry(id.clone())
            .or_insert_with(|| ServiceBuilder {
                service: Service {
                    id,
                    kind,
                    name,
                    pids: Vec::new(),
                    listening: Vec::new(),
                    uses: Vec::new(),
                    partial: false,
                    separate_filesystem: false,
                },
                uses: BTreeMap::new(),
            });
        builder.service.pids.push(process.pid);
        builder.service.partial |= !process.inspected;
        builder.service.separate_filesystem |= !host_filesystem;
        for listener in listeners {
            if !builder.service.listening.contains(&listener) {
                builder.service.listening.push(listener);
            }
        }
        if !host_filesystem {
            continue;
        }
        if let Some(exe) = &process.exe
            && let Some(purl) = owning_package(files, &exe.path)
        {
            builder.add(
                purl,
                Evidence::Executable {
                    path: exe.path.clone(),
                    replaced_on_disk: exe.deleted,
                },
            );
        }
        for file in &process.mapped {
            if let Some(purl) = owning_package(files, &file.path) {
                builder.add(
                    purl,
                    Evidence::LoadedFile {
                        path: file.path.clone(),
                        replaced_on_disk: file.deleted,
                    },
                );
            }
        }
        for project in in_projects {
            for component in &project.components {
                builder.add(
                    &component.purl,
                    Evidence::WorkingDirectory {
                        project: project.root.clone(),
                    },
                );
            }
        }
    }
    builders
        .into_values()
        .map(|builder| {
            let mut service = builder.service;
            service.listening.sort_by(|a, b| {
                (a.port, a.protocol, &a.address).cmp(&(b.port, b.protocol, &b.address))
            });
            service.uses = builder
                .uses
                .into_iter()
                .map(|(purl, evidence)| Usage { purl, evidence })
                .collect();
            service
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::MappedFile;

    fn process(
        pid: u32,
        cgroup: &str,
        exe: &str,
        mapped: &[(&str, bool)],
        inodes: &[u64],
    ) -> Process {
        Process {
            pid,
            comm: format!("proc{pid}"),
            exe: Some(MappedFile {
                path: exe.into(),
                deleted: false,
            }),
            cwd: Some("/".into()),
            cgroup: Some(cgroup.into()),
            netns: Some("net:[1]".into()),
            root: Some(HOST_ROOT),
            mapped: mapped
                .iter()
                .map(|(p, d)| MappedFile {
                    path: (*p).into(),
                    deleted: *d,
                })
                .collect(),
            socket_inodes: inodes.to_vec(),
            inspected: true,
        }
    }

    #[test]
    fn links_processes_to_units_packages_and_ports() {
        let files: HashMap<String, String> = [
            ("/usr/sbin/nginx", "pkg:deb/ubuntu/nginx@1.24"),
            (
                "/lib/x86_64-linux-gnu/libssl.so.3",
                "pkg:deb/ubuntu/libssl3@3.0.13",
            ),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .collect();
        let sockets: HashMap<u64, Socket> = [(
            7,
            Socket {
                protocol: "tcp",
                address: "0.0.0.0".parse().unwrap(),
                port: 80,
                inode: 7,
            },
        )]
        .into_iter()
        .collect();
        let processes = vec![
            // master and worker of the same unit; the worker still maps the old libssl
            process(
                10,
                "/system.slice/nginx.service",
                "/usr/sbin/nginx",
                &[("/usr/lib/x86_64-linux-gnu/libssl.so.3", false)],
                &[7],
            ),
            process(
                11,
                "/system.slice/nginx.service",
                "/usr/sbin/nginx",
                &[("/usr/lib/x86_64-linux-gnu/libssl.so.3", true)],
                &[],
            ),
            // an interactive shell: not a service
            process(
                20,
                "/user.slice/user-1000.slice/session-2.scope",
                "/usr/bin/bash",
                &[],
                &[],
            ),
        ];
        let services = build_services(&processes, &sockets, &files, &[], Some(HOST_ROOT));
        assert_eq!(services.len(), 1);
        let nginx = &services[0];
        assert_eq!(nginx.id, "systemd:nginx.service");
        assert_eq!(nginx.pids, [10, 11]);
        assert_eq!(nginx.exposure(), Some(Exposure::AllInterfaces));
        assert_eq!(nginx.uses.len(), 2);
        assert!(
            nginx.needs_restart(),
            "the replaced libssl must be reported"
        );
    }

    #[test]
    fn standalone_listener_and_project_directory() {
        let sockets: HashMap<u64, Socket> = [(
            9,
            Socket {
                protocol: "tcp",
                address: "127.0.0.1".parse().unwrap(),
                port: 3000,
                inode: 9,
            },
        )]
        .into_iter()
        .collect();
        let mut node = process(
            30,
            "/user.slice/user-1000.slice/session-2.scope",
            "/usr/bin/node",
            &[],
            &[9],
        );
        node.cwd = Some("/srv/app/src".into());
        let project = Project {
            root: "/srv/app".into(),
            components: vec![Component {
                purl: "pkg:npm/express@4.19.2".into(),
                name: "express".into(),
                version: "4.19.2".into(),
                origin: Origin::Lockfile {
                    file: "/srv/app/package-lock.json".into(),
                },
                declaration: None,
            }],
            warnings: Vec::new(),
        };
        let services = build_services(
            &[node],
            &sockets,
            &HashMap::new(),
            &[project],
            Some(HOST_ROOT),
        );
        assert_eq!(services[0].id, "process:30");
        assert_eq!(services[0].exposure(), Some(Exposure::Loopback));
        assert_eq!(
            services[0].uses[0].evidence,
            Evidence::WorkingDirectory {
                project: "/srv/app".into()
            }
        );
    }

    #[test]
    fn other_filesystems_are_not_attributed_to_host_packages() {
        let files: HashMap<String, String> = [(
            "/usr/lib/x86_64-linux-gnu/libssl.so.3".to_owned(),
            "pkg:deb/ubuntu/libssl3@3.0.13".to_owned(),
        )]
        .into_iter()
        .collect();
        let libssl = [("/usr/lib/x86_64-linux-gnu/libssl.so.3", false)];
        let id = "0123456789abcdef".repeat(4);
        // A container process, and a Flatpak app in its own mount namespace.
        let container = process(
            40,
            &format!("/system.slice/docker-{id}.scope"),
            "/usr/bin/python3",
            &libssl,
            &[],
        );
        let mut flatpak = process(
            41,
            "/system.slice/flatpak-app.service",
            "/app/bin/app",
            &libssl,
            &[],
        );
        flatpak.root = Some((99, 2));
        let services = build_services(
            &[container, flatpak],
            &HashMap::new(),
            &files,
            &[],
            Some(HOST_ROOT),
        );
        assert_eq!(services.len(), 2);
        for service in &services {
            assert!(
                service.uses.is_empty(),
                "{} must not use host packages",
                service.id
            );
            assert!(service.separate_filesystem);
        }
    }

    #[test]
    fn hardened_service_in_own_namespace_keeps_host_packages() {
        // ProtectSystem=strict gives the service its own mount namespace, but
        // its root directory is still the host's: its files are host files.
        let files: HashMap<String, String> = [(
            "/usr/sbin/chronyd".to_owned(),
            "pkg:deb/ubuntu/chrony@4.5".to_owned(),
        )]
        .into_iter()
        .collect();
        let chrony = process(
            50,
            "/system.slice/chrony.service",
            "/usr/sbin/chronyd",
            &[],
            &[],
        );
        let services = build_services(&[chrony], &HashMap::new(), &files, &[], Some(HOST_ROOT));
        assert_eq!(services[0].uses.len(), 1);
        assert!(!services[0].separate_filesystem);
    }

    #[test]
    fn socket_activation_is_reported_under_the_unit() {
        let sockets: HashMap<u64, Socket> = [3, 4]
            .into_iter()
            .map(|inode| {
                let socket = Socket {
                    protocol: "tcp",
                    address: "0.0.0.0".parse().unwrap(),
                    port: if inode == 3 { 22 } else { 9090 },
                    inode,
                };
                (inode, socket)
            })
            .collect();
        // PID 1 holds both sockets; sshd has been started and shares the first.
        let init = process(1, "/init.scope", "/usr/lib/systemd/systemd", &[], &[3, 4]);
        let sshd = process(60, "/system.slice/ssh.service", "/usr/sbin/sshd", &[], &[3]);
        let services = build_services(
            &[init, sshd],
            &sockets,
            &HashMap::new(),
            &[],
            Some(HOST_ROOT),
        );
        let ports = |id: &str| -> Vec<u16> {
            let service = services.iter().find(|s| s.id == id).unwrap();
            service.listening.iter().map(|l| l.port).collect()
        };
        assert_eq!(ports("systemd:ssh.service"), [22]);
        assert_eq!(
            ports("systemd:init.scope"),
            [9090],
            "only the socket no unit has taken yet"
        );
    }

    const HOST_ROOT: procfs::RootId = (2049, 2);

    #[test]
    fn usr_merge_lookup_both_ways() {
        let files: HashMap<String, String> = [
            ("/usr/bin/curl".to_owned(), "curl".to_owned()),
            ("/lib/libz.so.1".to_owned(), "zlib".to_owned()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            owning_package(&files, Path::new("/bin/curl")).map(String::as_str),
            Some("curl")
        );
        assert_eq!(
            owning_package(&files, Path::new("/usr/lib/libz.so.1")).map(String::as_str),
            Some("zlib")
        );
        assert_eq!(owning_package(&files, Path::new("/opt/x")), None);
    }
}
