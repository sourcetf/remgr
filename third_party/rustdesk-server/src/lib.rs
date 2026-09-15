//! rustdesk-server as an embeddable library.
//!
//! `rendezvous_server` (hbbs) and `relay_server` (hbbr) are exposed so host
//! applications can run the RustDesk ID/relay servers in-process.

mod rendezvous_server;
pub use rendezvous_server::*;
pub mod common;
mod database;
mod peer;
mod version;
mod relay_server;
pub use relay_server::*;
