//! OpenBSD interface and route configuration, entirely in-process.
//!
//! Two mechanisms are used, both of which the sandbox permits:
//!
//! * `ioctl(2)` on a control socket. The `route` promise covers reading
//!   interface state (`SIOCGIFADDR`) and `wroute` covers changing it
//!   (`SIOCAIFADDR`, `SIOCDIFADDR`, `SIOCSIFMTU`).
//! * A routing socket opened *before* `pledge(2)`. pledge denies
//!   `socket(AF_ROUTE)` outright, but a descriptor opened beforehand keeps
//!   working — which is what allows route management without ever calling
//!   `exec(2)`.
//!
//! `ifconfig(8)` and `route(8)` are never invoked: the binary has no `exec`
//! promise and therefore cannot spawn subprocesses at all.
//!
//! Note that `tun(4)` marks the interface `IFF_UP | IFF_RUNNING` as part of
//! `open(2)` (see `tunopen()` in `sys/net/if_tun.c`), so bringing the link up
//! needs no ioctl — `SIOCSIFFLAGS` is in fact not granted by any promise.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;

use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};

use super::{Error, IfConfiguerTrait};

// ---------------------------------------------------------------- constants

const AF_ROUTE: i32 = 17;

const SIOCAIFADDR: libc::c_ulong = 0x8040_691a;
const SIOCDIFADDR: libc::c_ulong = 0x8020_6919;
const SIOCSIFMTU: libc::c_ulong = 0x8020_697f;
const SIOCGIFADDR: libc::c_ulong = 0xc020_6921;
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8080_691a;
const SIOCDIFADDR_IN6: libc::c_ulong = 0x8120_6919;

const RTM_VERSION: u8 = 5;
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;

const RTF_UP: i32 = 0x1;
const RTF_STATIC: i32 = 0x800;

const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;

/// `sizeof(struct rt_msghdr)` on OpenBSD.
const RT_MSGHDR_LEN: usize = 96;
const IFNAMSIZ: usize = 16;

// ---------------------------------------------------------------- sockets

/// Routing socket, opened before the sandbox is applied.
static ROUTE_FD: AtomicI32 = AtomicI32::new(-1);
/// Control socket for interface ioctls, opened on first use.
static CTL_FD: OnceLock<i32> = OnceLock::new();

/// Open the routing socket.
///
/// Must be called during startup, before `pledge(2)`: afterwards
/// `socket(AF_ROUTE, ...)` is rejected by the sandbox.
pub fn preopen_route_socket() {
    if ROUTE_FD.load(Ordering::SeqCst) >= 0 {
        return;
    }
    let fd = unsafe { libc::socket(AF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        tracing::warn!(
            "cannot open routing socket: {} (proxy CIDR routes will not be installed)",
            io::Error::last_os_error()
        );
        return;
    }
    ROUTE_FD.store(fd, Ordering::SeqCst);
    tracing::debug!("routing socket pre-opened (fd={fd})");
}

fn route_fd() -> io::Result<i32> {
    let fd = ROUTE_FD.load(Ordering::SeqCst);
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "routing socket was not pre-opened before pledge(2)",
        ));
    }
    Ok(fd)
}

fn ctl_fd() -> io::Result<i32> {
    if let Some(fd) = CTL_FD.get() {
        return Ok(*fd);
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // A concurrent initialisation may win the race; drop the loser.
    match CTL_FD.set(fd) {
        Ok(()) => Ok(fd),
        Err(_) => {
            unsafe { libc::close(fd) };
            Ok(*CTL_FD.get().expect("control socket set"))
        }
    }
}

// ---------------------------------------------------------------- helpers

fn ifreq(name: &str) -> libc::ifreq {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    let n = bytes.len().min(IFNAMSIZ - 1);
    for (i, b) in bytes[..n].iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    req
}

fn ctl_ioctl(com: libc::c_ulong, req: &mut libc::ifreq) -> io::Result<()> {
    let fd = ctl_fd()?;
    let rc = unsafe { libc::ioctl(fd, com, req as *mut libc::ifreq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ioctl_raw(com: libc::c_ulong, buf: &mut [u8]) -> io::Result<()> {
    let fd = ctl_fd()?;
    let rc = unsafe { libc::ioctl(fd, com, buf.as_mut_ptr() as *mut libc::c_void) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Treat "there is nothing to remove" as success.
///
/// `remove_ip(None)` / `remove_ipv6(None)` are called unconditionally at the
/// start of address assignment, before any address exists. `SIOCDIFADDR` with a
/// zeroed address is a no-op only when the interface already has an address to
/// drop; on a fresh interface the kernel answers `EADDRNOTAVAIL`, and callers
/// upstream treat any error as fatal — the instance would fail to start with a
/// bare "io error" and the TUN device it just created would be torn down.
fn ignore_missing(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => Ok(()),
        other => other,
    }
}

/// `struct sockaddr_in` (16 bytes).
fn sa_in(addr: Ipv4Addr) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = 16; // sin_len
    b[1] = libc::AF_INET as u8; // sin_family
    b[4..8].copy_from_slice(&addr.octets());
    b
}

/// `struct sockaddr_in6` (28 bytes).
fn sa_in6(addr: Ipv6Addr) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0] = 28; // sin6_len
    b[1] = libc::AF_INET6 as u8; // sin6_family
    b[8..24].copy_from_slice(&addr.octets());
    b
}

fn prefix_mask4(prefix: u8) -> Ipv4Addr {
    let bits: u32 = if prefix >= 32 {
        u32::MAX
    } else {
        (!0u32) << (32 - prefix)
    };
    Ipv4Addr::from(bits)
}

fn prefix_mask6(prefix: u8) -> [u8; 16] {
    let mut m = [0u8; 16];
    for (i, byte) in m.iter_mut().enumerate() {
        let bits = (prefix as usize).saturating_sub(i * 8);
        *byte = if bits >= 8 {
            0xff
        } else if bits == 0 {
            0x00
        } else {
            (0xffu16 << (8 - bits)) as u8
        };
    }
    m
}

/// `struct ifaliasreq` (64 bytes): name, addr, dstaddr, mask.
fn ifaliasreq(name: &str, addr: Ipv4Addr, dst: Ipv4Addr, mask: Ipv4Addr) -> [u8; 64] {
    let mut b = [0u8; 64];
    let n = name.as_bytes().len().min(IFNAMSIZ - 1);
    b[..n].copy_from_slice(&name.as_bytes()[..n]);
    b[16..32].copy_from_slice(&sa_in(addr));
    b[32..48].copy_from_slice(&sa_in(dst));
    b[48..64].copy_from_slice(&sa_in(mask));
    b
}

/// `struct in6_aliasreq` (128 bytes): name, addr, dstaddr, prefixmask,
/// flags, lifetime.
fn in6_aliasreq(name: &str, addr: Ipv6Addr, mask: [u8; 16]) -> [u8; 128] {
    let mut b = [0u8; 128];
    let n = name.as_bytes().len().min(IFNAMSIZ - 1);
    b[..n].copy_from_slice(&name.as_bytes()[..n]);
    b[16..44].copy_from_slice(&sa_in6(addr));
    b[44..72].copy_from_slice(&sa_in6(addr));
    let mut pm = sa_in6(Ipv6Addr::UNSPECIFIED);
    pm[8..24].copy_from_slice(&mask);
    b[72..100].copy_from_slice(&pm);
    b
}

/// Primary IPv4 address assigned to `name`; used as the gateway of an
/// interface route on a point-to-point link.
fn iface_ipv4(name: &str) -> io::Result<Ipv4Addr> {
    let mut req = ifreq(name);
    ctl_ioctl(SIOCGIFADDR, &mut req)?;
    // struct sockaddr_in: len, family, port, then the four address octets
    let mut octets = [0u8; 4];
    unsafe {
        let sa = std::ptr::addr_of!(req.ifr_ifru.ifru_addr) as *const u8;
        std::ptr::copy_nonoverlapping(sa.add(4), octets.as_mut_ptr(), 4);
    }
    Ok(Ipv4Addr::from(octets))
}

// ---------------------------------------------------------------- routes

fn write_route(
    msg_type: u8,
    dst: &[u8],
    gateway: Option<&[u8]>,
    mask: Option<&[u8]>,
) -> io::Result<()> {
    let fd = route_fd()?;

    let mut addrs = RTA_DST;
    let mut payload: Vec<u8> = Vec::with_capacity(84);
    payload.extend_from_slice(dst);
    if let Some(gw) = gateway {
        addrs |= RTA_GATEWAY;
        payload.extend_from_slice(gw);
    }
    if let Some(m) = mask {
        addrs |= RTA_NETMASK;
        payload.extend_from_slice(m);
    }

    let mut msg = vec![0u8; RT_MSGHDR_LEN];
    let msglen = (RT_MSGHDR_LEN + payload.len()) as u16;
    msg[0..2].copy_from_slice(&msglen.to_ne_bytes()); // rtm_msglen
    msg[2] = RTM_VERSION; // rtm_version
    msg[3] = msg_type; // rtm_type
    msg[4..6].copy_from_slice(&(RT_MSGHDR_LEN as u16).to_ne_bytes()); // rtm_hdrlen
    msg[12..16].copy_from_slice(&addrs.to_ne_bytes()); // rtm_addrs
    let flags = RTF_UP | RTF_STATIC;
    msg[16..20].copy_from_slice(&flags.to_ne_bytes()); // rtm_flags
    msg[24..28].copy_from_slice(&std::process::id().to_ne_bytes()); // rtm_pid
    msg.extend_from_slice(&payload);

    let n = unsafe { libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------- configer

pub struct OpenBsdIfConfiger {}

#[async_trait]
impl IfConfiguerTrait for OpenBsdIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        _cost: Option<i32>,
    ) -> Result<(), Error> {
        let gateway = iface_ipv4(name)?;
        let mask = prefix_mask4(cidr_prefix);
        write_route(
            RTM_ADD,
            &sa_in(address),
            Some(&sa_in(gateway)),
            Some(&sa_in(mask)),
        )?;
        tracing::debug!("route add {address}/{cidr_prefix} via {gateway} dev {name}");
        Ok(())
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mask = prefix_mask4(cidr_prefix);
        write_route(RTM_DELETE, &sa_in(address), None, Some(&sa_in(mask)))?;
        tracing::debug!("route delete {address}/{cidr_prefix} dev {name}");
        Ok(())
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut req = ifaliasreq(name, address, address, prefix_mask4(cidr_prefix));
        ioctl_raw(SIOCAIFADDR, &mut req)?;
        Ok(())
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        // A zeroed address removes every IPv4 address on the interface.
        let addr = ip.map(|i| i.address()).unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mut req = ifaliasreq(name, addr, addr, Ipv4Addr::UNSPECIFIED);
        ignore_missing(ioctl_raw(SIOCDIFADDR, &mut req))?;
        Ok(())
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut req = in6_aliasreq(name, address, prefix_mask6(cidr_prefix));
        ioctl_raw(SIOCAIFADDR_IN6, &mut req)?;
        Ok(())
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        let addr = ip.map(|i| i.address()).unwrap_or(Ipv6Addr::UNSPECIFIED);
        let mut req = in6_aliasreq(name, addr, [0u8; 16]);
        ignore_missing(ioctl_raw(SIOCDIFADDR_IN6, &mut req))?;
        Ok(())
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
        _cost: Option<i32>,
    ) -> Result<(), Error> {
        let mut mask = sa_in6(Ipv6Addr::UNSPECIFIED);
        mask[8..24].copy_from_slice(&prefix_mask6(cidr_prefix));
        write_route(RTM_ADD, &sa_in6(address), None, Some(&mask))?;
        tracing::debug!("route add -inet6 {address}/{cidr_prefix} dev {name}");
        Ok(())
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut mask = sa_in6(Ipv6Addr::UNSPECIFIED);
        mask[8..24].copy_from_slice(&prefix_mask6(cidr_prefix));
        write_route(RTM_DELETE, &sa_in6(address), None, Some(&mask))?;
        tracing::debug!("route delete -inet6 {address}/{cidr_prefix} dev {name}");
        Ok(())
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        // tun(4) already sets IFF_UP | IFF_RUNNING in tunopen(), and
        // SIOCSIFFLAGS is not granted by any promise, so this is a no-op.
        tracing::debug!("set_link_status({name}, {up}): tun(4) is already up on open");
        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        let mut req = ifreq(name);
        req.ifr_ifru.ifru_metric = mtu as libc::c_int;
        ctl_ioctl(SIOCSIFMTU, &mut req)?;
        Ok(())
    }

    async fn wait_interface_show(&self, _name: &str) -> Result<(), Error> {
        // The interface exists as soon as /dev/tunN is opened.
        Ok(())
    }
}
