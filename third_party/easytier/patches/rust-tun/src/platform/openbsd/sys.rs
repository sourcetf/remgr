//! Bindings to internal OpenBSD stuff.

use libc::{c_char, c_uint, c_ushort, ifreq, sockaddr, IFNAMSIZ};
use nix::{ioctl_read, ioctl_readwrite, ioctl_write_ptr};

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaliasreq {
    pub ifra_name: [c_char; IFNAMSIZ],
    pub addr: sockaddr,
    pub dstaddr: sockaddr,
    pub mask: sockaddr,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tuninfo {
    pub mtu: c_uint,
    pub type_: c_ushort,
    pub flags: c_ushort,
    pub baudrate: c_uint,
}

ioctl_write_ptr!(siocsifflags, b'i', 16, ifreq);
ioctl_readwrite!(siocgifflags, b'i', 17, ifreq);

ioctl_write_ptr!(siocsifaddr, b'i', 12, ifreq);
ioctl_readwrite!(siocgifaddr, b'i', 33, ifreq);

ioctl_write_ptr!(siocsifdstaddr, b'i', 14, ifreq);
ioctl_readwrite!(siocgifdstaddr, b'i', 34, ifreq);

ioctl_write_ptr!(siocsifbrdaddr, b'i', 19, ifreq);
ioctl_readwrite!(siocgifbrdaddr, b'i', 35, ifreq);

ioctl_write_ptr!(siocsifnetmask, b'i', 22, ifreq);
ioctl_readwrite!(siocgifnetmask, b'i', 37, ifreq);

// NOTE: SIOCAIFADDR is request 26 on OpenBSD (43 on FreeBSD).
ioctl_write_ptr!(siocaifaddr, b'i', 26, ifaliasreq);
ioctl_write_ptr!(siocdifaddr, b'i', 25, ifreq);

// MTU of a tun(4) device is managed through tuninfo (TUNSIFINFO/TUNGIFINFO).
ioctl_write_ptr!(tunsifinfo, b't', 91, tuninfo);
ioctl_read!(tungifinfo, b't', 92, tuninfo);
