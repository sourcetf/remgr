#!/bin/ksh
# Reclaim build artifacts on a box where the root filesystem is the binding
# constraint (this one has been at 95-102% for weeks).
#
#   ksh scripts/reclaim-build-artifacts.sh
#
# Cargo keeps every superseded copy of a compiled crate in target/release/deps:
# after a few rebuilds the same crate appears several times with different hashes,
# and only the newest one is ever linked. Removing the older copies is safe (cargo
# rebuilds anything it actually needs) and reclaimed 721 MiB on this box, twice.
# The `target/release/build` and registry *cache* directories are deliberately left
# alone: the first holds build-script output that is expensive to reproduce, the
# second is a re-downloadable cache but deleting it makes the next build need the
# network.
# Deliberately no `set -u`: the body expands an array that is empty whenever a
# crate has only one copy, and OpenBSD's ksh reports that as "parameter not set"
# (the original on the box, written before this was moved into the repo, had no
# such guard either — this is a bug fix, not a style choice).
root="${1:-/root/ReMgr}"
cd "$root/target/release/deps" 2>/dev/null || { echo "no $root/target/release/deps"; exit 1; }
before=$(df -k / | awk 'NR==2{print $4}')
freed=0
n=0
for base in $(ls -1 *.rlib 2>/dev/null | sed -E 's/-[0-9a-f]{16}\.rlib$//' | sort -u); do
    set -A victims -- $(ls -1t ${base}-*.rlib 2>/dev/null | tail -n +2)
    for f in "${victims[@]}"; do
        sz=$(stat -f %z "$f" 2>/dev/null || echo 0)
        rm -f "$f" && { freed=$((freed + sz)); n=$((n + 1)); }
    done
done
echo "removed $n superseded artefact(s), $((freed / 1048576)) MiB"
after=$(df -k / | awk 'NR==2{print $4}')
echo "free on /: $((before / 1024)) MiB -> $((after / 1024)) MiB"
