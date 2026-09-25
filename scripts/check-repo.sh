#!/bin/sh
# Repository hygiene gate: nothing that must never be committed, and the property
# that lets CI build the frp crate on a Linux runner.
#
#   sh scripts/check-repo.sh
#
# Run from anywhere; it finds the repo root itself. Non-zero exit means the tree
# should not be shipped.
set -u
fail=0
bad() { printf 'FAIL  %s\n' "$*"; fail=$((fail + 1)); }
ok() { printf 'ok    %s\n' "$*"; }

root=$(git rev-parse --show-toplevel 2>/dev/null) || { bad "not a git work tree"; exit 1; }
cd "$root" || exit 1

# third_party/ is vendored upstream code (its own build config, its own dist
# assets) — not ours to police.
ours=$(git ls-files | grep -v '^third_party/' | grep -v '^docs/')

# ---------------------------------------------------------------- no credentials
# The live config carries the password hash, the frps token and the network
# secret; keys and bootstrap passwords live next to it. A deploy artefact must
# never carry any of them.
hits=$(printf '%s\n' "$ours" | grep -Ei '(^|/)(config\.toml|initial_password|.*_dashboard_password|id_ed25519.*)$|\.(pem|key|p12|jks)$|\.log$' || true)
if [ -n "$hits" ]; then
    bad "credential-like file(s) tracked:"
    printf '        %s\n' $hits
else
    ok "no config/key/log/password files tracked"
fi

# ---------------------------------------------------------------- no build output
hits=$(printf '%s\n' "$ours" | grep -E '^target/|/target/' || true)
if [ -n "$hits" ]; then
    bad "build output tracked (should be gitignored): $(printf '%s ' $hits)"
else
    ok "no build output tracked"
fi

# ---------------------------------------------------------------- size
big=$(git ls-files -z | xargs -0 du -k 2>/dev/null | awk '$1 > 5120 {print $1 " KiB  " $2}')
if [ -n "$big" ]; then
    bad "tracked file(s) larger than 5 MiB:"
    printf '        %s\n' "$big"
else
    ok "no tracked file over 5 MiB"
fi

# ---------------------------------------------------------------- frp crate portability
# CI builds `remgr-frps` on a Linux runner and runs its tests. That only works
# while the crate stays OS-independent; adding an OpenBSD-only dependency or a
# `cfg(target_os = "openbsd")` here would make CI unable to verify the protocol
# implementation at all. The service crate (`remgr`) is sandbox-and-platform
# specific and is deliberately not covered by that job.
osdep=$(grep -rnE 'target_os = "openbsd"|libc::|pledge\(|unveil\(' remgr-frps/src remgr-frps/examples 2>/dev/null || true)
if [ -n "$osdep" ]; then
    bad "remgr-frps must stay portable (it carries the frp protocol + its tests):"
    printf '        %s\n' "$osdep"
else
    ok "remgr-frps has no platform-specific code"
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
    printf 'repo hygiene: %d problem(s)\n' "$fail"
    exit 1
fi
printf 'repo hygiene: all good\n'