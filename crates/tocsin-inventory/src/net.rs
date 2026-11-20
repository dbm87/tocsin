//! Listening sockets, from `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`.
//!
//! Socket tables are per network namespace, so they are read once for each
//! namespace in use (containers included), through one of its processes.

use crate::model::{Exposure, Listener};
use crate::procfs::Process;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub protocol: &'static str,
    pub address: IpAddr,
    pub port: u16,
    pub inode: u64,
    /// The socket lives in a network namespace other than the host's
    /// (container…): it is reachable only through ports published to the
    /// host, which appear as host sockets of their own (e.g. docker-proxy).
    pub isolated: bool,
}

const TCP_LISTEN: &str = "0A";
const UDP_UNCONNECTED: &str = "07";

/// The kernel prints each 32-bit word of the address in host byte order.
fn parse_address(hex: &str) -> Option<IpAddr> {
    let word = |chunk: &str| u32::from_str_radix(chunk, 16).ok().map(u32::to_ne_bytes);
    match hex.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word(hex)?))),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, out) in bytes.chunks_mut(4).enumerate() {
                out.copy_from_slice(&word(&hex[i * 8..i * 8 + 8])?);
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn parse_endpoint(field: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = field.split_once(':')?;
    Some((parse_address(address)?, u16::from_str_radix(port, 16).ok()?))
}

/// Listening sockets in one table. `udp` selects the UDP notion of "listening".
pub fn parse_table(text: &str, protocol: &'static str, udp: bool) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            let (local, remote, state, inode) = (
                fields.get(1)?,
                fields.get(2)?,
                fields.get(3)?,
                fields.get(9)?,
            );
            let listening = if udp {
                *state == UDP_UNCONNECTED && parse_endpoint(remote)?.1 == 0
            } else {
                *state == TCP_LISTEN
            };
            if !listening {
                return None;
            }
            let (address, port) = parse_endpoint(local)?;
            Some(Socket {
                protocol,
                address,
                port,
                inode: inode.parse().ok()?,
                isolated: false,
            })
        })
        .collect()
}

pub fn exposure(address: IpAddr) -> Exposure {
    match address {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Exposure::Loopback
            } else if v4.is_unspecified() {
                Exposure::AllInterfaces
            } else if v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64
            {
                // RFC 1918, link-local, multicast (not routed over the Internet), carrier-grade NAT
                Exposure::Lan
            } else {
                Exposure::Public
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return exposure(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            if v6.is_loopback() {
                Exposure::Loopback
            } else if v6.is_unspecified() {
                Exposure::AllInterfaces
            } else if first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
                || v6.is_multicast() && first & 0x000f < 0xe
            {
                Exposure::Lan // unique local, link-local, multicast below global scope
            } else {
                Exposure::Public
            }
        }
    }
}

impl From<&Socket> for Listener {
    fn from(socket: &Socket) -> Self {
        Listener {
            protocol: socket.protocol,
            address: socket.address.to_string(),
            port: socket.port,
            exposure: match exposure(socket.address) {
                Exposure::Loopback => Exposure::Loopback,
                _ if socket.isolated => Exposure::ContainerNetwork,
                other => other,
            },
        }
    }
}

/// Listening sockets of every network namespace in use, by socket inode.
pub fn listening_sockets(proc_root: &Path, processes: &[Process]) -> HashMap<u64, Socket> {
    let host_netns = crate::procfs::namespace(&proc_root.join("1"), "net")
        .or_else(|| crate::procfs::namespace(&proc_root.join("self"), "net"));
    let mut sockets = HashMap::new();
    let mut seen = HashSet::new();
    for process in processes.iter().filter(|p| !p.socket_inodes.is_empty()) {
        let Some(netns) = &process.netns else {
            continue;
        };
        if !seen.insert(netns.clone()) {
            continue;
        }
        let isolated = host_netns.as_ref().is_some_and(|host| host != netns);
        let dir = proc_root.join(process.pid.to_string()).join("net");
        for (file, protocol, udp) in [
            ("tcp", "tcp", false),
            ("tcp6", "tcp", false),
            ("udp", "udp", true),
            ("udp6", "udp", true),
        ] {
            if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
                sockets.extend(
                    parse_table(&text, protocol, udp)
                        .into_iter()
                        .map(|s| (s.inode, Socket { isolated, ..s })),
                );
            }
        }
    }
    sockets
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real lines from /proc/net/tcp and tcp6 on a little-endian machine.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0
   2: 0F02000A:D2A4 22D8B85D:01BB 01 00000000:00000000 02:00000A3B 00000000  1000        0 44444 2 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 556 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn tcp_listeners_only() {
        let sockets = parse_table(TCP, "tcp", false);
        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(sockets[0].port, 631);
        assert_eq!(sockets[1].port, 80);
        assert_eq!(sockets[1].inode, 31337);
    }

    #[test]
    fn tcp6_addresses() {
        let sockets = parse_table(TCP6, "tcp", false);
        assert_eq!(sockets[0].address, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(sockets[0].port, 22);
        assert_eq!(sockets[1].address, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn exposure_classes() {
        assert_eq!(exposure("127.0.0.1".parse().unwrap()), Exposure::Loopback);
        assert_eq!(
            exposure("0.0.0.0".parse().unwrap()),
            Exposure::AllInterfaces
        );
        assert_eq!(exposure("192.168.1.10".parse().unwrap()), Exposure::Lan);
        assert_eq!(exposure("100.64.0.1".parse().unwrap()), Exposure::Lan);
        assert_eq!(exposure("93.184.216.34".parse().unwrap()), Exposure::Public);
        assert_eq!(exposure("::".parse().unwrap()), Exposure::AllInterfaces);
        assert_eq!(exposure("fe80::1".parse().unwrap()), Exposure::Lan);
        assert_eq!(exposure("::ffff:10.0.0.1".parse().unwrap()), Exposure::Lan);
        assert_eq!(exposure("2001:db8::1".parse().unwrap()), Exposure::Public);
        assert_eq!(exposure("239.255.255.250".parse().unwrap()), Exposure::Lan);
        assert_eq!(exposure("ff02::c".parse().unwrap()), Exposure::Lan);
        assert_eq!(exposure("ff05::c".parse().unwrap()), Exposure::Lan);
        assert_eq!(exposure("ff0e::1".parse().unwrap()), Exposure::Public);
    }

    #[test]
    fn sockets_inside_a_container_namespace() {
        let socket = |address: &str, isolated| Socket {
            protocol: "tcp",
            address: address.parse().unwrap(),
            port: 8000,
            inode: 1,
            isolated,
        };
        // 0.0.0.0 inside a container is not every interface of the host.
        assert_eq!(
            Listener::from(&socket("0.0.0.0", true)).exposure,
            Exposure::ContainerNetwork
        );
        assert_eq!(
            Listener::from(&socket("127.0.0.1", true)).exposure,
            Exposure::Loopback
        );
        assert_eq!(
            Listener::from(&socket("0.0.0.0", false)).exposure,
            Exposure::AllInterfaces
        );
    }

    #[test]
    fn own_namespace_is_not_isolated() {
        let me = crate::procfs::read_process(Path::new("/proc"), std::process::id()).unwrap();
        let sockets = listening_sockets(Path::new("/proc"), &[me]);
        assert!(sockets.values().all(|s| !s.isolated));
    }
}
