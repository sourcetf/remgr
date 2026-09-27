//! Windows: make the Npcap dependency optional at *start-up*.
//!
//! `pnet_sys` — reached through the vendored EasyTier faketcp netfilter — imports
//! `Packet.dll` and `wpcap.dll` from Npcap. A normal import is resolved by the
//! Windows loader before `main()` runs, so without Npcap installed the whole
//! binary refuses to start: `remgr --version` exits with 0xC0000135
//! (STATUS_DLL_NOT_FOUND) and the relay manager is unusable even with the EasyTier
//! node switched off, which is the only part that needs a packet driver at all.
//!
//! Delay-loading makes those two imports lazy: the process starts, every module
//! that does not touch the TUN path works normally, and only a call that actually
//! goes through pnet would try to load them. That call happens while starting the
//! EasyTier *node*, which is guarded separately (`modules::easytier` checks that
//! the driver it needs is loadable before it starts the node) so the failure is a
//! clear message rather than a missing-DLL abort.
//!
//! `delayimp` is MSVC's delay-load helper. Both DLL names are declared with
//! `#[link]` inside the dependency, so the linker is the only place this can be
//! arranged.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    for dll in ["Packet.dll", "wpcap.dll"] {
        println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
    }
    println!("cargo:rustc-link-lib=delayimp");
}
