#!/bin/ksh
# /etc/remgr/remgr-watchdog.sh — bring remgr back if it is gone.
#
# Optional. Nothing in OpenBSD's rc.subr supervises a foreground daemon, so a
# service that dies stays dead until someone notices: on 2026-09-26 remgr took an
# external SIGTERM at 03:08 (a clean shutdown — the log shows the modules stopping
# one by one), and stayed down for about forty minutes until a human restarted it.
# That is the gap this fills.
#
# It is deliberately NOT installed by default: a watchdog and an operator who
# stopped the service for maintenance fight each other. Enable it only if you want
# the service to be un-stoppable without also disabling this script.
#
# Install (checks every two minutes, logs to syslog via logger):
#     install -m 555 scripts/remgr-watchdog.sh /etc/remgr/remgr-watchdog.sh
#     crontab -l > /tmp/ct 2>/dev/null; \
#       echo '*/2 * * * * /etc/remgr/remgr-watchdog.sh' >> /tmp/ct; crontab /tmp/ct
#
# Disable: remove that line from root's crontab (`crontab -e`).
#
# Deliberate behaviours:
#   * `rcctl check` returns 0 only while the daemon is actually running, and it
#     looks at the pid file rc.subr wrote, so a zombie or a wrong-process pid
#     cannot fool it.
#   * the restart goes through `rcctl -f start`, so login.conf limits, the
#     working directory and the rc.d flags are applied exactly as at boot — a
#     restart from here is indistinguishable from a reboot's.
#   * `rcctl start` on a service that is already up is a no-op, so a race between
#     the watchdog and a real start cannot produce two instances (rc.subr holds
#     the pid file and rc_check gates on it).
#   * if remgr is configured off (`rcctl ls off`), the watchdog does nothing: an
#     operator who disabled the service at boot meant it.
set -u

rcctl="/usr/sbin/rcctl"
logger="/usr/bin/logger"
name="remgr"
tag="remgr-watchdog"

# Not enabled for boot → not our business.
if ! "$rcctl" ls on 2>/dev/null | grep -qx "$name"; then
    exit 0
fi

if "$rcctl" check "$name" > /dev/null 2>&1; then
    exit 0
fi

"$logger" -t "$tag" -p daemon.warning "$name is not running — starting it"
out=$("$rcctl" -f start "$name" 2>&1)
rc=$?
sleep 5
if "$rcctl" check "$name" > /dev/null 2>&1; then
    "$logger" -t "$tag" -p daemon.info "$name recovered (rcctl rc=$rc)"
    exit 0
fi

# Still down: say so once, loudly, with what rcctl reported. Repeated failures are
# what a human has to look at — a restart loop cannot fix a port conflict or a
# full disk, and restarting faster only buries the reason in the log.
"$logger" -t "$tag" -p daemon.err "$name did NOT come back (rcctl rc=$rc): $out"
"$logger" -t "$tag" -p daemon.err "check: $rcctl check $name; tail -50 /var/log/remgr/remgr.log"
exit 1