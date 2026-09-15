//! easytier-web as an embeddable library.
//!
//! The original crate is a thin `main.rs` around these modules; `start.rs`
//! exposes the whole stack (sqlite db + config server + REST api) as one
//! async call so host applications (ReMgr) can embed easytier-web in-process.

#![allow(dead_code)]

#[macro_use]
extern crate rust_i18n;

pub mod client_manager;
pub mod db;
pub mod migrator;
pub mod restful;
pub mod start;
pub mod webhook;

#[cfg(feature = "embed")]
pub mod web;

rust_i18n::i18n!("locales", fallback = "en");

/// Moved verbatim from main.rs so the lib modules can share it.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct FeatureFlags {
    /// Whether user registration via the web UI is disabled.
    #[arg(
        long,
        env = "ET_DISABLE_REGISTRATION",
        default_value = "false",
        help = t!("cli.disable_registration").to_string()
    )]
    pub disable_registration: bool,

    /// Whether to auto-create users when they connect via heartbeat with an unknown token.
    #[arg(
        long,
        env = "ET_ALLOW_AUTO_CREATE_USER",
        default_value = "false",
        help = t!("cli.allow_auto_create_user").to_string()
    )]
    pub allow_auto_create_user: bool,
}
