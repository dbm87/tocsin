//! Running processes, read from `/proc` (spec section 8.3, step 3).

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct Process {
    pub pid: u32,
    pub comm: String,
    pub exe: Option<MappedFile>,
    pub cwd: Option<PathBuf>,
    pub cgroup: Option<String>,
    pub netns: Option<String>,
    /// Identity of the process's root directory. A different root means a
    /// different filesystem (container, Flatpak, Snap…), whose files are not
    /// the host's. A mount namespace alone is not enough: hardened systemd
    /// services (`ProtectSystem=`, `PrivateTmp=`) have their own namespace but
    /// still run the host's files.
    pub root: Option<RootId>,
    pub mapped: Vec<MappedFile>,
    pub socket_inodes: Vec<u64>,
    /// False when permissions prevented reading its executable, memory map or sockets.
    pub inspected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MappedFile {
    pub path: PathBuf,
    /// The kernel reports the file as deleted: it was replaced on disk.
    pub deleted: bool,
}

#[derive(Debug, Default)]
pub struct Scan {
    pub processes: Vec<Process>,
    /// Processes that could not be fully inspected.
    pub denied: usize,
}

const DELETED_SUFFIX: &str = " (deleted)";

fn mapped_file(raw: &str) -> MappedFile {
    match raw.strip_suffix(DELETED_SUFFIX) {
        Some(path) => MappedFile {
            path: PathBuf::from(path),
            deleted: true,
        },
        None => MappedFile {
            path: PathBuf::from(raw),
            deleted: false,
        },
    }
}

/// File paths mapped in memory, from `/proc/<pid>/maps`.
pub fn parse_maps(text: &str) -> Vec<MappedFile> {
    let mut files: Vec<MappedFile> = text
        .lines()
        .filter_map(|line| {
            // address perms offset dev inode pathname (the pathname may contain spaces)
            let path = line
                .split_ascii_whitespace()
                .skip(5)
                .collect::<Vec<_>>()
                .join(" ");
            let interesting =
                path.starts_with('/') && !path.starts_with("/dev/") && !path.starts_with("/memfd:");
            interesting.then(|| mapped_file(&path))
        })
        .collect();
    files.sort();
    files.dedup();
    files
}

/// The cgroup v2 path (`0::/…`), or the first hierarchy's path on cgroup v1.
pub fn parse_cgroup(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let line = lines
        .iter()
        .find(|l| l.starts_with("0::"))
        .or(lines.first())?;
    line.splitn(3, ':').nth(2).map(str::to_owned)
}

fn socket_inode(link: &Path) -> Option<u64> {
    link.to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Identifier of a process namespace, e.g. `mnt:[4026531841]`.
pub fn namespace(process_dir: &Path, kind: &str) -> Option<String> {
    std::fs::read_link(process_dir.join("ns").join(kind))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Device and inode of a filesystem root.
pub type RootId = (u64, u64);

/// Identity of the root directory seen by a process (`/proc/<pid>/root`).
pub fn root_id(process_dir: &Path) -> Option<RootId> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(process_dir.join("root")).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

fn denied<T>(result: &std::io::Result<T>) -> bool {
    matches!(result, Err(e) if e.kind() == ErrorKind::PermissionDenied)
}

/// Reads one process. `None` for kernel threads and processes that just exited.
pub fn read_process(proc_root: &Path, pid: u32) -> Option<Process> {
    let dir = proc_root.join(pid.to_string());
    let comm = std::fs::read_to_string(dir.join("comm"))
        .ok()?
        .trim()
        .to_owned();
    let exe = std::fs::read_link(dir.join("exe"));
    if matches!(&exe, Err(e) if e.kind() == ErrorKind::NotFound) {
        return None; // kernel thread (no executable) or already gone
    }
    let maps = std::fs::read_to_string(dir.join("maps"));
    let fds = std::fs::read_dir(dir.join("fd"));
    let inspected = !(denied(&exe) || denied(&maps) || denied(&fds));

    let mut socket_inodes: Vec<u64> = fds
        .map(|entries| {
            entries
                .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .filter_map(|link| socket_inode(&link))
                .collect()
        })
        .unwrap_or_default();
    socket_inodes.sort_unstable();
    socket_inodes.dedup();

    Some(Process {
        pid,
        comm,
        exe: exe.ok().and_then(|p| p.to_str().map(mapped_file)),
        cwd: std::fs::read_link(dir.join("cwd")).ok(),
        cgroup: std::fs::read_to_string(dir.join("cgroup"))
            .ok()
            .as_deref()
            .and_then(parse_cgroup),
        netns: namespace(&dir, "net"),
        root: root_id(&dir),
        mapped: maps.map(|text| parse_maps(&text)).unwrap_or_default(),
        socket_inodes,
        inspected,
    })
}

pub fn scan(proc_root: &Path) -> std::io::Result<Scan> {
    let mut scan = Scan::default();
    for entry in std::fs::read_dir(proc_root)? {
        let Some(pid) = entry?
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(process) = read_process(proc_root, pid) {
            if !process.inspected {
                scan.denied += 1;
            }
            scan.processes.push(process);
        }
    }
    scan.processes.sort_by_key(|p| p.pid);
    Ok(scan)
}

/// What a process belongs to, deduced from its cgroup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Owner {
    Unit(String),
    Container(String),
    /// systemd itself (PID 1), which holds the sockets of socket-activated units.
    Init,
    Process,
}

fn container_id(segment: &str) -> Option<String> {
    let mut id = segment.strip_suffix(".scope").unwrap_or(segment);
    for prefix in ["docker-", "cri-containerd-", "crio-", "libpod-"] {
        if let Some(rest) = id.strip_prefix(prefix) {
            id = rest;
            break;
        }
    }
    (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id[..12].to_owned())
}

pub fn owner(cgroup: Option<&str>) -> Owner {
    let Some(cgroup) = cgroup else {
        return Owner::Process;
    };
    let segments: Vec<&str> = cgroup.split('/').filter(|s| !s.is_empty()).collect();
    if segments == ["init.scope"] {
        return Owner::Init;
    }
    if let Some(id) = segments.iter().rev().find_map(|s| container_id(s)) {
        return Owner::Container(id);
    }
    match segments.iter().rev().find(|s| s.ends_with(".service")) {
        Some(unit) => Owner::Unit((*unit).to_owned()),
        None => Owner::Process,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_keeps_files_and_flags_deleted_ones() {
        let maps = "\
55d0c0a00000-55d0c0a28000 r--p 00000000 103:02 1234   /usr/sbin/nginx
7f1e2c000000-7f1e2c200000 r-xp 00000000 103:02 5678   /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1e2c400000-7f1e2c401000 rw-p 00000000 00:00 0
7ffd5c000000-7ffd5c021000 rw-p 00000000 00:00 0       [stack]
7f1e2c500000-7f1e2c600000 r--s 00000000 00:05 9       /dev/zero (deleted)
7f1e2c700000-7f1e2c800000 r--p 00000000 103:02 42     /opt/my app/lib.so
55d0c0a28000-55d0c0b00000 r-xp 00028000 103:02 1234   /usr/sbin/nginx
";
        let files = parse_maps(maps);
        assert_eq!(files.len(), 3);
        assert!(files.contains(&MappedFile {
            path: "/usr/lib/x86_64-linux-gnu/libssl.so.3".into(),
            deleted: true
        }));
        assert!(files.contains(&MappedFile {
            path: "/opt/my app/lib.so".into(),
            deleted: false
        }));
    }

    #[test]
    fn cgroup_v2_and_v1() {
        assert_eq!(
            parse_cgroup("0::/system.slice/nginx.service\n").as_deref(),
            Some("/system.slice/nginx.service")
        );
        assert_eq!(
            parse_cgroup("12:pids:/docker/abc\n11:cpu:/docker/abc\n").as_deref(),
            Some("/docker/abc")
        );
    }

    #[test]
    fn owners() {
        let id = "4f6c1a0e9b2d".repeat(5) + "abcd"; // 64 hex characters
        let id = id.as_str();
        assert_eq!(
            owner(Some("/system.slice/nginx.service")),
            Owner::Unit("nginx.service".into())
        );
        assert_eq!(
            owner(Some(&format!("/system.slice/docker-{id}.scope"))),
            Owner::Container(id[..12].into())
        );
        assert_eq!(
            owner(Some(&format!("/docker/{id}"))),
            Owner::Container(id[..12].into())
        );
        assert_eq!(
            owner(Some(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.scope"
            )),
            Owner::Unit("user@1000.service".into())
        );
        assert_eq!(
            owner(Some("/user.slice/user-1000.slice/session-2.scope")),
            Owner::Process
        );
        assert_eq!(owner(None), Owner::Process);
        assert_eq!(owner(Some("/init.scope")), Owner::Init);
    }

    #[test]
    fn reads_own_process() {
        let me =
            read_process(Path::new("/proc"), std::process::id()).expect("own process is readable");
        assert!(me.inspected);
        assert!(me.exe.is_some());
        assert!(!me.mapped.is_empty());
    }
}
