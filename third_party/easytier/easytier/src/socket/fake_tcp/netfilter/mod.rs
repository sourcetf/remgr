pub mod pnet;

use std::{io, net::SocketAddr, sync::Arc};

#[cfg(target_os = "linux")]
pub mod linux_bpf;

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
pub mod macos_bpf;

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
pub mod windivert;

#[cfg(target_os = "linux")]
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Arc<dyn super::stack::Tun>> {
    match linux_bpf::LinuxBpfTun::new(interface_name, src_addr, dst_addr) {
        Ok(tun) => Ok(Arc::new(tun)),
        Err(e) => {
            tracing::warn!(
                ?e,
                interface_name,
                "LinuxBpfTun init failed, falling back to PnetTun"
            );
            Ok(Arc::new(pnet::PnetTun::new(
                interface_name,
                pnet::create_packet_filter(src_addr, dst_addr),
            )?))
        }
    }
}

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Arc<dyn super::stack::Tun>> {
    match macos_bpf::MacosBpfTun::new(interface_name, src_addr, dst_addr) {
        Ok(tun) => Ok(Arc::new(tun)),
        Err(e) => {
            tracing::warn!(
                ?e,
                interface_name,
                "MacosBpfTun init failed, falling back to PnetTun"
            );
            Ok(Arc::new(pnet::PnetTun::new(
                interface_name,
                pnet::create_packet_filter(src_addr, dst_addr),
            )?))
        }
    }
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Arc<dyn super::stack::Tun>> {
    match windivert::WinDivertTun::new(src_addr, dst_addr) {
        Ok(tun) => Ok(Arc::new(tun)),
        Err(e) => {
            tracing::warn!(
                ?e,
                ?dst_addr,
                "WinDivertTun init failed, falling back to PnetTun"
            );
            Ok(Arc::new(pnet::PnetTun::new(
                interface_name,
                pnet::create_packet_filter(src_addr, dst_addr),
            )?))
        }
    }
}

#[cfg(not(any(
    target_os = "linux",
    all(target_os = "macos", not(feature = "macos-ne")),
    all(windows, any(target_arch = "x86_64", target_arch = "x86"))
)))]
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Arc<dyn super::stack::Tun>> {
    Ok(Arc::new(pnet::PnetTun::new(
        interface_name,
        pnet::create_packet_filter(src_addr, dst_addr),
    )?))
}
