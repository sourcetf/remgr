#!/bin/ksh
# End-to-end check of the signal-provenance work, on the live service.
#
# The load-bearing trick: the lethal signal is sent by /bin/kill, a short-lived
# external command. The kernel's accounting file only gets a process's record
# when that process exits, so the daemon's second read of the tail — 1.2s into
# the shutdown — is exactly what has to catch it. If "kill" shows up in the log,
# the mechanism works; if only the shell around it shows up, it does not.
set -u
L=/var/log/remgr/remgr.log

show_since() {
	sed -n "$1,\$p" "$L" | cut -c1-170
}

echo "== 0. baseline =="
rcctl check remgr || { echo "service not running to begin with"; exit 1; }
prod_pid() {
	# the production instance only: scratch instances of the same binary run from
	# /tmp with their own --config, and signalling "the" pid would hit both
	pgrep -f "/etc/remgr/config.toml"
}
n=$(prod_pid | wc -l | tr -d ' ')
[ "$n" -eq 1 ] || { echo "expected exactly one production instance, found $n: $(prod_pid | tr '
' ' ')"; exit 1; }
echo "running, pid=$(prod_pid)"

echo "== 1. install the new binary (rename: install(1)/cp(1) cannot overwrite a running one) =="
cp /usr/local/bin/remgr /usr/local/bin/remgr.prev 2>/dev/null || true
install -m 755 /root/ReMgr/target/release/remgr /usr/local/bin/remgr.new
mv -f /usr/local/bin/remgr.new /usr/local/bin/remgr
ls -l /usr/local/bin/remgr
rcctl restart remgr
echo "restart rc=$?"
sleep 8
rcctl check remgr && echo "  up again: OK" || { echo "  FAILED to come up"; exit 1; }

echo
echo "== 2. SIGHUP must be recorded and ignored =="
pid=$(prod_pid)
from=$(wc -l < "$L")
/bin/kill -HUP "$pid"
sleep 3
show_since $((from + 1))
if rcctl check remgr >/dev/null 2>&1; then
	echo "  still running after SIGHUP: OK"
else
	echo "  FAIL: SIGHUP killed the service"
	exit 1
fi

echo
echo "== 3. SIGTERM must be recorded, and the accounting tail must name the sender =="
from=$(wc -l < "$L")
/bin/kill -TERM "$pid"
sleep 9
show_since $((from + 1))
if prod_pid >/dev/null 2>&1 && [ -n "$(prod_pid)" ]; then
	echo "  FAIL: still running after SIGTERM"
	exit 1
fi
echo "  exited on SIGTERM: OK"
sed -n "$((from + 1)),\$p" "$L" > /tmp/vs.tail
case "$(cat /tmp/vs.tail)" in
*"signal 15 from pid="*) echo "  raw record written by the handler: OK" ;;
*) echo "  FAIL: no raw record from the handler" ;;
esac
case "$(cat /tmp/vs.tail)" in
*"stopped; exiting"*) echo "  the shutdown runs to its final line: OK" ;;
*) echo "  FAIL: the shutdown did not reach its final line" ;;
esac
if grep -q "accounting: .*kill uid=" /tmp/vs.tail; then
	echo "  accounting names the command that sent it (/bin/kill): OK"
else
	echo "  NOTE: /bin/kill is not in the accounting tail:"
	grep "^accounting:" /tmp/vs.tail | head -8
fi

echo
echo "== 4. bring it back (the watchdog would do this too) =="
rcctl start remgr
sleep 8
rcctl check remgr && echo "  running: OK" || { echo "  FAILED to restart"; exit 1; }

echo
echo "== 5. the console still serves, and logs =="
curl -ks -o /dev/null -w "  GET /       -> %{http_code}\n" --max-time 10 https://127.0.0.1:9443/
curl -ks -o /dev/null -w "  POST login  -> %{http_code}\n" --max-time 10 \
	-X POST https://127.0.0.1:9443/api/login \
	-H 'content-type: application/json' -d '{"username":"admin","password":"admin"}'
echo "  listeners:"
netstat -na -f inet 2>/dev/null | grep -E 'LISTEN' | grep -E '3478|5349|9443|7000|11010|21115|21116|21117' | awk '{print "   ", $4}' | sort -u

echo
echo "== 6. modules after the round trip (needs a session: /api/status is not public) =="
J=/tmp/vs.cookies
rm -f "$J"
curl -ks --max-time 10 -c "$J" -o /dev/null 	-X POST https://127.0.0.1:9443/api/login 	-H 'content-type: application/json' -d '{"username":"admin","password":"admin"}'
curl -ks --max-time 10 -b "$J" https://127.0.0.1:9443/api/status | cut -c1-800
rm -f "$J"
echo
echo "== done =="
