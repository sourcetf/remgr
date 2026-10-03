#!/bin/ksh
# Build ReMgr on OpenBSD — records the exact environment the binary needs.
#
#   pkg_add rust-1.94.1 llvm-19.1.7p14 protobuf-6.34.1 git-2.53.0
#
# Exact versions on purpose. `pkg_add` resolves a *stem*, and an ambiguous stem is
# an error when there is no tty to prompt on (as in CI): there is no `llvm19`
# package — the stem is `llvm`, whose branches are 19/20/21 — and a bare `rust`
# also matches rust-analyzer, rust-bootstrap and rust-clippy. `git` is not part of
# OpenBSD's base system, and cargo needs it for the vendored EasyTier patches,
# which are git dependencies.
#
# Verified combination (OpenBSD 7.9/amd64):
#   rust / cargo 1.94.1   (packages, not rustup)
#   llvm-19.1.7p14        -> provides libclang.so, located below rather than assumed
#   protobuf-6.34.1       -> /usr/local/bin/protoc
#   git-2.53.0
#
# Every variable below is load-bearing; none is a leftover:
#   LIBCLANG_PATH
#       kcp-sys (pulled in by the vendored easytier tree) runs bindgen through
#       libclang. Without it bindgen looks in the default compiler paths, finds no
#       libclang.so there, and the build fails. The directory is derived from the
#       installed package (see below), and an LIBCLANG_PATH from the environment is
#       honoured, so a caller that already knows can say so.
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
#       Overridable from the environment so the CI VM (two vcpus) can ask for
#       more without editing this file.
#   CARGO_NET_GIT_FETCH_WITH_CLI=true
#       the easytier patches are git dependencies and libgit2 needs more
#       descriptors than the limit above allows.
set -e
cd "$(dirname "$0")/.."
for t in cargo protoc git; do
	command -v $t >/dev/null ||
		{ echo "missing $t: pkg_add rust-1.94.1 llvm-19.1.7p14 protobuf-6.34.1 git-2.53.0" >&2; exit 1; }
done

# Where is libclang? Do not guess. A wrong LIBCLANG_PATH is not noticed until
# bindgen runs, ~20 minutes into the build, and both the directory and the file name
# are easy to get wrong: the OpenBSD package installs
# `/usr/local/llvm19/lib/libclang.so.0.0` — no unversioned `libclang.so` — while
# bindgen accepts `libclang.so` or `libclang.so.*`. So look for the file (by
# pattern), not for a specific name.
if [ -z "${LIBCLANG_PATH:-}" ]; then
	clang=$(find /usr/local -maxdepth 4 -name 'libclang.so*' -type f 2>/dev/null | head -1) || true
	if [ -z "$clang" ]; then
		clang=$(pkg_info -L 'llvm-*' 2>/dev/null | grep -E '/libclang\.so' | head -1) || true
	fi
	[ -n "$clang" ] && LIBCLANG_PATH=$(dirname "$clang")
fi
if [ -n "${LIBCLANG_PATH:-}" ] && ls "$LIBCLANG_PATH"/libclang.so* >/dev/null 2>&1; then
	echo "libclang: $LIBCLANG_PATH/$(ls "$LIBCLANG_PATH" | grep '^libclang\.so' | head -1)"
else
	echo "warning: libclang not found (pkg_add llvm-19.1.7p14) — bindgen will fail" >&2
fi

ulimit -n 1024
export RUSTC_BOOTSTRAP=1
export LIBCLANG_PATH
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_INCREMENTAL=0
cargo build --release --locked --ignore-rust-version -p remgr
echo "=== build ok: target/release/remgr ==="
