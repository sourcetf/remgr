#!/bin/sh
# Static checks for the ReMgr web console (single-file SPA, one inline script).
#
#   sh scripts/check-console.sh remgr/src/console/assets/index.html [remgr/src/console/mod.rs]
#
# The console is the operator's only interface, and it has broken in ways that no
# API test can see: a syntax error in the inline script left every handler
# undefined (the page still *looked* fine because the login overlay is static
# markup), and widgets silently degraded to text inputs so every save was
# rejected. These checks catch that class of bug without a browser.
#
# Exit status is non-zero if any check fails, so it can gate CI.
set -u

html="${1:-remgr/src/console/assets/index.html}"
router="${2:-remgr/src/console/mod.rs}"
fail=0
note() { printf '%s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=$((fail + 1)); }
ok() { printf 'ok    %s\n' "$*"; }

[ -f "$html" ] || { bad "no such file: $html"; exit 1; }

_tmpbase=$(mktemp) || exit 1
tmp="${_tmpbase}.js"      # node --check infers the language from the file name
mv "$_tmpbase" "$tmp"
trap 'rm -f "$tmp"' EXIT INT TERM

# ---------------------------------------------------------------- inline script
count=$(grep -c '<script>' "$html")
if [ "$count" != "1" ]; then
    bad "expected exactly one inline <script>, found $count"
else
    awk '/<script>/{inb=1; next} /<\/script>/{inb=0} inb' "$html" > "$tmp"
    lines=$(wc -l < "$tmp" | tr -d ' ')
    if [ "$lines" -lt 100 ]; then
        bad "inline script looks truncated ($lines lines)"
    else
        ok "inline script extracted ($lines lines)"
    fi

    # A syntax error is the failure this check exists for. `node --check` parses
    # in script mode; Node is present on GitHub runners and on this project's
    # OpenBSD hosts, so the step is skipped with a warning when it is missing
    # rather than silently passing.
    if command -v node > /dev/null 2>&1; then
        if node --check "$tmp" 2> "$tmp.err"; then
            ok "inline script parses (node --check)"
        else
            bad "inline script does NOT parse:"
            sed -n '1,12p' "$tmp.err"
        fi
        rm -f "$tmp.err"
    else
        note "warn  node not found — skipping the syntax check (install node to enable)"
    fi
fi

# ---------------------------------------------------------------- handlers
# Every function referenced from an inline on* attribute must be defined, or the
# button does nothing (this is exactly what a syntax error used to look like).
defs=$(mktemp)
trap 'rm -f "$tmp" "$defs"' EXIT INT TERM
{
    grep -oE 'function[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*' "$html" | awk '{print $2}'
    grep -oE '(const|let|var)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=[[:space:]]*(async[[:space:]]*)?(function[[:space:]]*\(|\()' "$html" |
        sed -E 's/^[[:space:]]*(const|let|var)[[:space:]]+//; s/[[:space:]]*=.*$//'
    grep -oE '(const|let|var)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=[[:space:]]*(async[[:space:]]*)?[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=>' "$html" |
        sed -E 's/^[[:space:]]*(const|let|var)[[:space:]]+//; s/[[:space:]]*=.*$//'
} | sort -u > "$defs"

used=$(grep -oE 'on(click|change|input|submit|keydown|keyup)="[^"]*"' "$html" |
    grep -oE '[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*\(' |
    sed 's/[[:space:]]*($//' | sort -u)

missing=""
for h in $used; do
    # DOM methods and keywords that legitimately appear inside an attribute
    case "$h" in
        if|for|while|return|typeof|Number|String|Array|Object|JSON|parseInt|parseFloat) continue ;;
        confirm|prompt|alert|select|focus|blur|submit|reload|preventDefault) continue ;;
        el|val|esc) continue ;;
    esac
    grep -qx "$h" "$defs" || missing="$missing $h"
done
if [ -n "$missing" ]; then
    bad "handler(s) referenced from HTML but never defined:$missing"
else
    ok "every handler used by an inline attribute is defined ($(echo "$used" | wc -w | tr -d ' ') checked)"
fi

# ---------------------------------------------------------------- widgets
# SCHEMAS declares kinds as ['checkbox'] / ['number'] / ['textarea']; a kind with
# no branch in the renderer falls through to a text input, which then sends
# strings where serde wants bools/numbers and every save fails.
wdef=$(grep -oE "\['(checkbox|number|textarea|hidden)'\]" "$html" | tr -d "[]'" | sort -u)
wuse=$(grep -oE "widget==='[a-z_]+'" "$html" | grep -oE "'[a-z_]+'" | tr -d "'" | sort -u)
wmissing=""
for w in $wdef; do
    [ "$w" = text ] && continue          # the fallback branch renders it
    echo "$wuse" | grep -qx "$w" || wmissing="$wmissing $w"
done
if [ -n "$wmissing" ]; then
    bad "widget kind(s) declared but not rendered:$wmissing"
else
    ok "every declared widget kind has a renderer (text falls through): $(echo $wdef | tr '\n' ' ')"
fi

# ---------------------------------------------------------------- cert services
# genCert/uploadCert take a service name that the server maps onto a config
# field; an unmapped name silently does nothing.
cs=$(grep -oE "(genCert|uploadCert)\('[a-z_]+'\)" "$html" | grep -oE "'[a-z_]+'" | tr -d "'" | sort -u)
csbad=""
for c in $cs; do
    case "$c" in turn|frps|console) ;; *) csbad="$csbad $c" ;; esac
done
if [ -n "$csbad" ]; then
    bad "certificate buttons target unmapped service(s):$csbad"
else
    ok "certificate buttons target mapped services: $(echo $cs | tr '\n' ' ')"
fi

# ---------------------------------------------------------------- API surface
# Every /api/... the SPA calls must exist in the axum router. Only the first two
# path segments are compared (the SPA builds paths by concatenation), which is
# enough to catch a renamed or removed endpoint.
if [ -f "$router" ]; then
    # Compare only the first two path segments on both sides (the SPA builds paths
    # by concatenation, and a route may carry :params), which is enough to catch a
    # renamed or removed endpoint.
    api_used=$(grep -oE "/api/[a-z_]+(/[a-z_]+)?" "$html" | awk -F/ '{print "/" $2 "/" $3}' | sort -u)
    api_route=$(grep -oE '\.route\("/api/[^"]*"' "$router" | sed 's/^\.route("//; s/"$//' |
        awk -F/ '{print "/" $2 "/" $3}' | sort -u)
    apibad=""
    for p in $api_used; do
        echo "$api_route" | grep -qx "$p" || apibad="$apibad $p"
    done
    if [ -n "$apibad" ]; then
        bad "SPA calls endpoint(s) the router does not define:$apibad"
    else
        ok "every SPA endpoint exists in the router ($(echo "$api_used" | wc -w | tr -d ' ') checked)"
    fi
else
    note "warn  router source not found ($router) — skipping the endpoint cross-check"
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
    printf 'console checks: %d failure(s)\n' "$fail"
    exit 1
fi
printf 'console checks: all good\n'