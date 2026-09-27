#!/bin/ksh
# Attach the OpenBSD binary to the release CI just published.
#
# GitHub has no OpenBSD runner, so the *sanctioned* platform's binary cannot come
# from CI. It is built here, on a real OpenBSD machine, with
# scripts/openbsd-build.sh — the same binary scripts/preflight.sh then checks —
# and this script uploads it to the release CI created for this commit, then
# rewrites the checksum file so it covers all three platforms at once.
#
#     # a token with contents:write on the repository
#     GH_TOKEN=... ksh scripts/publish-openbsd-release.sh [tag] [binary]
#
# Defaults: tag `latest` (the rolling master release), binary target/release/remgr.
# Releases cut from a `v*` tag use that tag instead:
#
#     GH_TOKEN=... ksh scripts/publish-openbsd-release.sh v0.1.0
set -eu
tag="${1:-latest}"
bin="${2:-target/release/remgr}"
asset="remgr-openbsd-amd64"
repo="${REPO:-sourcetf/remgr}"
api="https://api.github.com/repos/$repo"
up="https://uploads.github.com/repos/$repo"

[ -n "${GH_TOKEN:-}" ] || { print -u2 "GH_TOKEN is not set (needs contents:write)"; exit 1; }
[ -f "$bin" ] || { print -u2 "no binary at $bin — build it with scripts/openbsd-build.sh"; exit 1; }

auth="Authorization: Bearer $GH_TOKEN"
work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT

# The release JSON is regular enough to read with awk: split on commas, and inside
# the assets array every entry lists "id" before "name".
asset_id() { # asset_id <json> <name>
	printf '%s' "$1" | tr ',' '\n' | awk -v want="$2" '
		/"assets"/          { in_assets = 1 }
		in_assets && /"id":/ { id = $0; gsub(/[^0-9]/, "", id) }
		in_assets && index($0, "\"name\": \"" want "\"") { print id; exit }'
}

rel=$(curl -sS --max-time 60 -H "$auth" "$api/releases/tags/$tag") || exit 1
rel_id=$(printf '%s' "$rel" | tr ',' '\n' | awk '/"id":/ { gsub(/[^0-9]/, ""); print; exit }')
[ -n "$rel_id" ] || { print -u2 "no release tagged $tag (has CI finished publishing one?)"; exit 1; }
print "release $tag: id $rel_id"

# Refuse to attach a binary from a different commit than the release describes: a
# checksum that verifies a mismatched pair is worse than no asset at all.
head_sha=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
case "$rel" in
*"$head_sha"*) print "commit $head_sha is the one the release names" ;;
*) print -u2 "WARNING: HEAD is $head_sha and the release does not mention it — attach only if that is intended" ;;
esac

sha=$(sha256 -q "$bin")
print "asset $asset: $(( $(stat -f %z "$bin") / 1048576 )) MiB, sha256 $sha"

# 1) the binary (a previous publish's copy is replaced)
curl -sS --max-time 600 -X POST -H "$auth" -H "Content-Type: application/octet-stream" \
	--data-binary "@$bin" "$up/releases/$rel_id/assets?name=$asset" > "$work/up1.json" || exit 1
grep -q '"state": *"uploaded"' "$work/up1.json" ||
	{ print -u2 "upload failed: $(cat "$work/up1.json")"; exit 1; }
print "uploaded $asset"

# 2) SHA256SUMS, so one file covers all three platforms
sums="$work/SHA256SUMS"
: > "$sums"
if url=$(printf '%s' "$rel" | tr ',' '\n' | grep -A3 'SHA256SUMS' | grep -o 'https://[^"]*' | head -1); then
	curl -sSL --max-time 120 -o "$sums" "$url" 2>/dev/null || : > "$sums"
fi
grep -v "[[:space:]]$asset\$" "$sums" > "$sums.keep" 2>/dev/null || : > "$sums.keep"
printf '%s  %s\n' "$sha" "$asset" >> "$sums.keep"
sort -k2 "$sums.keep" > "$sums"
print "checksums:"
cat "$sums"

if old=$(asset_id "$rel" SHA256SUMS) && [ -n "$old" ]; then
	curl -sS --max-time 60 -X DELETE -H "$auth" "$api/releases/assets/$old" >/dev/null || true
fi
curl -sS --max-time 120 -X POST -H "$auth" -H "Content-Type: text/plain" \
	--data-binary "@$sums" "$up/releases/$rel_id/assets?name=SHA256SUMS" > "$work/up2.json" || exit 1
grep -q '"state": *"uploaded"' "$work/up2.json" ||
	{ print -u2 "checksum upload failed: $(cat "$work/up2.json")"; exit 1; }
print "updated SHA256SUMS"

print ""
print "https://github.com/$repo/releases/tag/$tag"
