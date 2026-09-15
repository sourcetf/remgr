//! frp server-side protocol implementation (wire-compatible with fatedier/frp).
//!
//! Implemented protocol surface (frp "wire v1", the default for all current
//! frpc releases):
//! - `[1-byte msg type][8-byte BE length][JSON body]` framing, 10 KiB cap
//! - token auth: `privilege_key = hex(md5(token + timestamp))`
//! - `tcp_mux` (yamux) multiplexing: control stream + work-conn streams
//! - plain (non-mux) work connections over separate TCP streams
//! - optional TLS: frpc sends `0x16` as custom first byte, then TLS handshake
//! - proxy types: `tcp`, `udp`; other types are rejected with a protocol error
//!
//! frp wire protocol v2 (magic `FRP\0\x02\r\n`) is detected and rejected with a
//! clear log message; no current frpc defaults to it.

pub mod config;
pub mod crypto;
pub mod msg;
pub mod server;

pub use config::FrpsConfig;
pub use server::{FrpsServer, ProxyInfo, ServerStats};
#[cfg(test)]
mod crypto_ref_test {
    include!("crypto_ref_test.rs");
    use crate::crypto::Cfb;
}
#[cfg(test)]

#[cfg(test)]
mod chunk_test;
