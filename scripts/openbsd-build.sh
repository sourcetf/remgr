#!/bin/ksh
# Build ReMgr on OpenBSD.
# Requires: pkg_add rust llvm19 protobuf (protobuf-codegen is pure, but kcp-sys
# needs bindgen -> libclang from llvm19).
set -e
cd /root/ReMgr
ulimit -n 1024
export RUSTC_BOOTSTRAP=1                 # guarden patch uses cfg_select (rustc < 1.95)
export LIBCLANG_PATH=/usr/local/llvm19/lib
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_BUILD_JOBS=2                # single vcpu VPS
# vendored guarden carries rust-version=1.95 metadata; the code builds fine
export CARGO_INCREMENTAL=0
cargo build --release --ignore-rust-version -p remgr
echo "=== build ok: target/release/remgr ==="
