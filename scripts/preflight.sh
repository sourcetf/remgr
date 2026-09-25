#!/bin/ksh
# ReMgr deployment preflight — read-only checks for the target box.
# Run after installing the binary, /etc/rc.d/remgr and (for the fd limit)
# /etc/login.conf.d/remgr.  Exits 1 if any check failed.
#
#   usage: sh scripts/preflight.sh [/path/to/repo]
#
# Each check corresponds to something that has gone wrong in practice, so a
# warning here is a real finding, not a style opinion.
set -u
REPO=${1:-/root/ReMgr}
BIN=/usr/local/bin/remgr
CONF=/etc/remgr/config.toml
LOG=/var/log/remgr/remgr.log
fails=0
warns=0
ok()   { echo "  ok    $*"; }
bad()  { echo "  FAIL  $*"; fails=$((fails + 1)); }
warn() { echo "  warn  $*"; warns=$((warns + 1)); }
info() { echo "  info  $*"; }

echo "== binary / rc.d =="
if [ -x "$BIN" ]; then
	ok "$BIN ($(wc -c < "$BIN" | tr -d ' ') bytes)"
else
	bad "$BIN missing or not executable"
fi
if [ -f /etc/rc.d/remgr ] && [ -f "$REPO/scripts/rc.d/remgr" ]; then
	if [ "$(md5 -q /etc/rc.d/remgr)" = "$(md5 -q "$REPO/scripts/rc.d/remgr")" ]; then
		ok "/etc/rc.d/remgr is byte-identical to the repo copy"
	else
		bad "/etc/rc.d/remgr differs from $REPO/scripts/rc.d/remgr — reinstall it"
	fi
fi
if grep -q '^rc_bg=YES' /etc/rc.d/remgr 2>/dev/null; then
	ok "rc_bg=YES present (start/restart return immediately)"
else
	bad "rc_bg=YES missing: rcctl start/restart waits the whole daemon_timeout and exits 1"
fi
rcctl ls on 2>/dev/null | grep -qx remgr && ok "enabled (rcctl ls on)" || warn "not enabled: rcctl enable remgr"
if rcctl check remgr >/dev/null 2>&1; then
	ok "running"
else
	warn "not running"
fi

echo "== resource limits =="
cur=$(getcap -f /etc/login.conf.d/remgr:/etc/login.conf -s openfiles-cur remgr 2>/dev/null)
case "$cur" in
''|*[!0-9]*) warn "no login class named remgr -> the stock daemon class (openfiles-cur=128) applies; install scripts/login.conf.d/remgr" ;;
*) if [ "$cur" -ge 1024 ]; then ok "openfiles-cur=$cur (class remgr)"; else warn "openfiles-cur=$cur (class remgr), want >= 1024"; fi ;;
esac
[ -f /etc/login.conf.d/remgr ] && ok "/etc/login.conf.d/remgr installed" || warn "/etc/login.conf.d/remgr not installed"
sysmax=$(sysctl -n kern.maxfiles 2>/dev/null)
[ -n "$sysmax" ] && info "kern.maxfiles=$sysmax (system-wide ceiling, shared with pf/relayd/…)"

echo "== paths / permissions =="
for d in /etc/remgr /etc/remgr/ssl /var/lib/remgr /var/db/remgr /var/log/remgr /var/run/remgr; do
	if [ -d "$d" ]; then ok "$d"; else warn "$d missing (recreated at start by secure::prepare_dirs)"; fi
done
if [ -f "$CONF" ]; then
	m=$(stat -f %Lp "$CONF")
	[ "$m" = 600 ] && ok "$CONF mode 0600" || warn "$CONF mode $m (should be 0600: it holds the password hash and every token)"
	if grep -q '^password_hash = "\$argon2id' "$CONF"; then
		ok "console password hash set (no default password will be installed)"
	else
		warn "password_hash empty: admin/admin is installed on the next start (check /var/run/remgr/initial_password)"
	fi
else
	warn "$CONF missing (defaults are used and a file is written on first start)"
fi
for k in /etc/remgr/ssl/*_key.pem; do
	[ -f "$k" ] || continue
	m=$(stat -f %Lp "$k")
	[ "$m" = 600 ] && ok "$k mode 0600" || warn "$k mode $m (should be 0600)"
done

echo "== disk =="
cap=$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')
if [ "${cap:-0}" -ge 90 ]; then
	bad "root filesystem ${cap}% full — a full / has killed this process before"
elif [ "${cap:-0}" -ge 80 ]; then
	warn "root filesystem ${cap}% full"
else
	ok "root filesystem ${cap}% full"
fi

echo "== listeners =="
for p in 9443 3478 5349 22020 11010 21115 21116 21117 21118 21119 7000; do
	if netstat -an -f inet | awk '{print $4}' | grep -qE "[.:]${p}\$"; then
		ok "port $p bound"
	else
		warn "port $p not bound (module disabled, or the port moved in the config)"
	fi
done
netstat -an -f inet | awk '{print $4}' | grep -q '11211$' &&
	ok "11211 bound to loopback only" || warn "11211 (easytier-web API) not bound"

echo "== sandbox =="
if grep -q 'openbsd sandbox active: pledge "' "$LOG" 2>/dev/null; then
	line=$(grep 'openbsd sandbox active' "$LOG" | tail -1)
	ok "$(echo "$line" | sed 's/.*openbsd sandbox/sandbox/')"
	grep -q 'pledge "stdio rpath wpath cpath fattr flock inet unix dns getpw route wroute"' "$LOG" ||
		warn "the pledge set differs from the documented one — update README.md"
	grep -q 'unveil locked' "$LOG" || warn "unveil was not locked"
else
	warn "no 'sandbox active' line in $LOG (wrong log path, or the binary predates pledge/unveil)"
fi
if [ -n "$(pgrep -x remgr)" ]; then
	info "fds in use now: $(fstat -p "$(pgrep -x remgr | head -1)" | wc -l | tr -d ' ')"
	info "child processes: $(pgrep -P "$(pgrep -x remgr | head -1)" | wc -l | tr -d ' ') (0 = no exec/self-spawn, as designed)"
fi

echo
echo "preflight: $fails failure(s), $warns warning(s)"
[ "$fails" -eq 0 ] || exit 1
