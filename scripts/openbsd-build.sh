#!/bin/ksh
# Build ReMgr on OpenBSD — records the exact environment the binary needs.
#
#   pkg_add rust llvm19 protobuf
#
# Verified combination (OpenBSD 7.9/amd64, single vcpu VPS):
#   rust / cargo 1.94.1   (packages, not rustup)
#   llvm-19.1.7p14        -> /usr/local/llvm19/lib/libclang.so
#   protobuf-6.34.1       -> /usr/local/bin/protoc
#
# Every variable below is load-bearing; none is a leftover:
#   LIBCLANG_PATH=/usr/local/llvm19/lib
#       kcp-sys (pulled in by the vendored easytier tree) runs bindgen through
#       libclang. Without this it looks in the default compiler paths, finds no
#       libclang.so there, and the build script fails.
#   RUSTC_BOOTSTRAP=1
#       the vendored guarden crate uses the cfg_select! macro, which rustc 1.94
#       rejects on the stable channel. Nothing in ReMgr's own sources needs it —
#       remove it only together with the vendored patch.
#   --ignore-rust-version
#       vendored guarden advertises rust-version = 1.95 in its Cargo.toml while
#       the code builds fine on 1.94; this is exactly what the flag is for.
#   --locked
#       Cargo.lock is committed, so the build is reproducible from the repo and
#       fails loudly if the manifest and lockfile have drifted. Drop it only
#       when deliberately updating dependencies.
#   ulimit -n 1024
#       linking under thin LTO wants more file descriptors than a default build
#       shell has. This is a COMPILE-time limit and has nothing to do with the
#       runtime one: the service itself runs under the `daemon` login class
#       (openfiles-cur=128) unless scripts/login.conf.d/remgr is installed. Do
#       not "fix" production fd pressure by copying this line into rc.d — see
#       scripts/login.conf.d/remgr for why that cannot work.
#   CARGO_BUILD_JOBS=2 / CARGO_INCREMENTAL=0
#       one vcpu; more jobs only thrash, incremental artifacts are dead weight.
#   CARGO_NET_GIT_FETCH_WITH_CLI=true
#       the easytier patches are git dependencies and libgit2 needs more
#       descriptors than the limit above allows.
set -e
cd "$(dirname "$0")/.."
for t in cargo protoc; do
	command -v $t >/dev/null || { echo "missing $t: pkg_add rust llvm19 protobuf" >&2; exit 1; }
done
[ -f /usr/local/llvm19/lib/libclang.so ] ||
	echo "warning: /usr/local/llvm19/lib/libclang.so missing (pkg_add llvm19) — bindgen will fail" >&2
ulimit -n 1024
export RUSTC_BOOTSTRAP=1
export LIBCLANG_PATH=/usr/local/llvm19/lib
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
cargo build --release --locked --ignore-rust-version -p remgr
echo "=== build ok: target/release/remgr ==="
