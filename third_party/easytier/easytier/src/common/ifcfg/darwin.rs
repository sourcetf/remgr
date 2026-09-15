use std::net::Ipv4Addr;

use super::{Error, IfConfiguerTrait, cidr_to_subnet_mask, run_shell_cmd};
use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};

// On OpenBSD, an interface route needs the gateway to be an address assigned to
// the interface (route(8) -iface flag), and does not support -hopcount.
#[cfg(target_os = "openbsd")]
fn get_iface_ipv4_cmd(name: &str) -> String {
    format!("ifconfig {} | awk '/inet /{{print $2; exit}}'", name)
}

#[cfg(target_os = "openbsd")]
fn get_iface_ipv6_cmd(name: &str) -> String {
    format!("ifconfig {} | awk '/inet6 /{{print $2; exit}}'", name)
}

pub struct MacIfConfiger {}
#[async_trait]
impl IfConfiguerTrait for MacIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        #[cfg(target_os = "openbsd")]
        let cmd = format!(
            "route -n add {}/{} $( {} ) -iface",
            address,
            cidr_prefix,
            get_iface_ipv4_cmd(name)
        );
        #[cfg(not(target_os = "openbsd"))]
        let cmd = format!(
            "route -n add {} -netmask {} -interface {} -hopcount {}",
            address,
            cidr_to_subnet_mask(cidr_prefix),
            name,
            cost.unwrap_or(7)
        );
        let _ = cost;
        run_shell_cmd(cmd.as_str()).await
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        #[cfg(target_os = "openbsd")]
        let cmd = format!("route -n delete {}/{}", address, cidr_prefix);
        #[cfg(not(target_os = "openbsd"))]
        let cmd = format!(
            "route -n delete {} -netmask {} -interface {}",
            address,
            cidr_to_subnet_mask(cidr_prefix),
            name
        );
        let _ = name;
        run_shell_cmd(cmd.as_str()).await
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "ifconfig {} {:?}/{:?} {:?} up",
                name, address, cidr_prefix, address,
            )
            .as_str(),
        )
        .await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} {}", name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet {} delete", name, ip.address()).as_str()).await
        } else {
            run_shell_cmd(format!("ifconfig {} inet delete", name).as_str()).await
        }
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} mtu {}", name, mtu).as_str()).await
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        #[cfg(target_os = "openbsd")]
        let cmd = format!("ifconfig {} inet6 {}/{} alias", name, address, cidr_prefix);
        #[cfg(not(target_os = "openbsd"))]
        let cmd = format!("ifconfig {} inet6 {}/{} add", name, address, cidr_prefix);
        run_shell_cmd(cmd.as_str()).await
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet6 {} delete", name, ip.address()).as_str()).await
        } else {
            // Remove all IPv6 addresses is more complex on macOS, just succeed
            Ok(())
        }
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        #[cfg(target_os = "openbsd")]
        let cmd = format!(
            "route -n add -inet6 {}/{} $( {} ) -iface",
            address,
            cidr_prefix,
            get_iface_ipv6_cmd(name)
        );
        #[cfg(not(target_os = "openbsd"))]
        let cmd = if let Some(cost) = cost {
            format!(
                "route -n add -inet6 {}/{} -interface {} -hopcount {}",
                address, cidr_prefix, name, cost
            )
        } else {
            format!(
                "route -n add -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
        };
        let _ = cost;
        run_shell_cmd(cmd.as_str()).await
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        #[cfg(target_os = "openbsd")]
        let cmd = format!("route -n delete -inet6 {}/{}", address, cidr_prefix);
        #[cfg(not(target_os = "openbsd"))]
        let cmd = format!(
            "route -n delete -inet6 {}/{} -interface {}",
            address, cidr_prefix, name
        );
        let _ = name;
        run_shell_cmd(cmd.as_str()).await
    }
}
