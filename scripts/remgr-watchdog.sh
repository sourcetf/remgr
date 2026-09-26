#!/bin/ksh
# /etc/remgr/remgr-watchdog.sh — bring remgr back if it is gone.
#
# Optional. Nothing in OpenBSD's rc.subr supervises a foreground daemon, so a
# service that dies stays dead until someone notices: on 2026-09-26 remgr took an
# external SIGTERM three times (the shutdown itself was clean, and remgr's own
# signal handler records the sending pid), and each time it stayed down until a
# human restarted it — one of those gaps was 4.5 hours. That is the gap this
# fills.
#
# It is deliberately NOT installed by default: a watchdog and an operator who
# stopped the service for maintenance fight each other. Enable it only if you want
# the service to be un-stoppable without also disabling this script.
#
# Install (checks every two minutes, logs to syslog and to the file below):
#     install -m 555 scripts/remgr-watchdog.sh /etc/remgr/remgr-watchdog.sh
#     crontab -l > /tmp/ct 2>/dev/null; \
#       echo '*/2 * * * * /etc/remgr/remgr-watchdog.sh' >> /tmp/ct; crontab /tmp/ct
#
# Disable: remove that line from root's crontab (`crontab -e`).
#
# Where the history is: /var/log/remgr/watchdog.log (append-only, root-only), one
# line per action, next to remgr's own log. syslog alone is awkward to read back
# per service, and this file is what answers "how often does it restart, and when
# did it start going wrong?".
#
# Deliberate behaviours:
#   * `rcctl check` returns 0 only while the daemon is actually running — it
#     matches the daemon's command line, so a stale pid cannot fool it.
#   * the restart goes through `rcctl -f start`, so login.conf limits, the
#     working directory and the rc.d flags are applied exactly as at boot — a
#     restart from here is indistinguishable from a reboot's.
#   * `rcctl start` on a service that is already up is a no-op (7.9's rc.subr
#     runs rc_check first and exits 0 without touching the running daemon, even
#     with -f), so neither a race between the watchdog and a real start nor this
#     script itself can kill a healthy instance.
#   * if remgr is configured off (`rcctl ls off`), the watchdog does nothing: an
#     operator who disabled the service at boot meant it.
#   * it also bounds /var/account/acct (16 MiB), because remgr reads that file's
#     tail when it is signalled and OpenBSD's daily(8) never truncates it.
#   * when it finds the service down, it copies the last signal/accounting lines of
#     remgr's log into its own: nothing is logged while the service is down, so
#     those lines *are* the shutdown, and they name what killed it.
#   * it raises one box-level alarm: under 256 MiB free on / — the condition that
#     has killed processes here before, and that also makes the kernel stop writing
#     accounting records. That alarm fires even when the service is disabled at
#     boot, because a full filesystem is not the service's private problem.
set -u
umask 077

rcctl="/usr/sbin/rcctl"
logger="/usr/bin/logger"
name="remgr"
tag="remgr-watchdog"
logfile="/var/log/remgr/watchdog.log"
# a missing directory must not break the restart itself
[ -d /var/log/remgr ] || logfile=/dev/null

log() {
    msg="$1"
    prio="${2:-info}"
    "$logger" -t "$tag" -p "daemon.$prio" "$msg"
    printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$msg" >> "$logfile" 2>/dev/null || true
}

# Loudly if the filesystem the service writes to is nearly full. This box has been
# killed by a full root filesystem before, and a full one also makes the kernel
# stop writing accounting records (so the forensics go stale silently) — the one
# condition worth waking an operator up for, and cheap to check here.
DISK_WARN_MIB=256
avail_kib=$(df -k / | awk 'NR==2{print $4}')
case "$avail_kib" in
''|*[!0-9]*) : ;;
*)
    if [ "$avail_kib" -lt $((DISK_WARN_MIB * 1024)) ]; then
        log "only $((avail_kib / 1024)) MiB free on / — the kernel kills processes and stops writing accounting records when it fills" err
    fi
    ;;
esac

# Bound the kernel's accounting file.
#
# remgr reads that file's tail when a termination signal arrives (it is how the
# commands before a signal get recorded — see the README), but OpenBSD's daily(8)
# only *copies* it (`cp -f /var/account/acct /var/account/acct.0`) and never
# truncates the live file: it grows without bound and every daily run freezes its
# current size into another generation. On a box at 96% that is a disk-filling
# hazard, so it is capped here — accton(8) off, rotate the way daily expects,
# start again.
ACCT=/var/account/acct
ACCT_MAX=16777216
accton=/usr/sbin/accton

if [ -f "$ACCT" ]; then
    size=$(stat -f %z "$ACCT" 2>/dev/null || echo 0)
    case "$size" in ''|*[!0-9]*) size=0 ;; esac
    if [ "$size" -gt "$ACCT_MAX" ]; then
        "$accton" 2>/dev/null || true                  # accounting off
        mv -f "$ACCT" "${ACCT}.0" 2>/dev/null || true  # the generation daily(8) shifts
        : > "$ACCT" 2>/dev/null || true
        "$accton" "$ACCT" 2>/dev/null || true          # and on again
        log "accounting file was $((size / 1048576)) MiB — rotated (cap $((ACCT_MAX / 1048576)) MiB)" warning
    fi
fi

# Not enabled for boot → not our business.
if ! "$rcctl" ls on 2>/dev/null | grep -qx "$name"; then
    exit 0
fi

if "$rcctl" check "$name" > /dev/null 2>&1; then
    exit 0
fi

log "$name is not running — starting it" warning
# Why it stopped, in this file, before anything else is written to remgr's log:
# nothing is logged while the service is down, so the last lines of its log *are*
# the shutdown. When it was killed by a signal they name the signal, and (through
# the kernel's accounting tail) the commands that ran around it — the two things an
# operator has to see without going hunting. Two separate reads on purpose: the
# accounting block is long enough to push the signal line out of a single tail.
REMLOG=/var/log/remgr/remgr.log
if [ -f "$REMLOG" ]; then
    tail -120 "$REMLOG" 2>/dev/null | grep -aE "received with no sender|received from pid" | tail -2 |
        while IFS= read -r line; do log "  how it ended: $line" warning; done
    # dedupe: the daemon reads the accounting file twice on purpose (the sender's
    # own record is only written when it exits), so a record can appear in both
    tail -120 "$REMLOG" 2>/dev/null | grep -a "accounting: " | awk -F"accounting: " 'NF>1 && !seen[$2]++' |
        tail -6 | while IFS= read -r line; do
            log "  ran before it: ${line##*accounting: }" warning
        done
fi
out=$("$rcctl" -f start "$name" 2>&1)
rc=$?
sleep 5
if "$rcctl" check "$name" > /dev/null 2>&1; then
    log "$name recovered (rcctl rc=$rc)"
    exit 0
fi

# Still down: say so once, loudly, with what rcctl reported. Repeated failures are
# what a human has to look at — a restart loop cannot fix a port conflict or a
# full disk, and restarting faster only buries the reason in the log.
log "$name did NOT come back (rcctl rc=$rc): $out" err
log "check: $rcctl check $name; tail -50 /var/log/remgr/remgr.log" err
exit 1
