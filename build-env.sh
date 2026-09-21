#!/bin/ksh
cd /root/ReMgr
ulimit -n 1024
export RUSTC_BOOTSTRAP=1
export LIBCLANG_PATH=/usr/local/llvm19/lib
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_BUILD_JOBS=2
exec env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo build --release --ignore-rust-version -p remgr
