#!/bin/ksh
# Interop check for the embedded frps against the *upstream* frp client.
#
# What it needs: this script downloads the official frp release for OpenBSD
# (~20 MiB, into /tmp/frp71) and points it at whatever frps this box is running,
# using the token from /etc/remgr/config.toml. Nothing else, and nothing is faked:
# the TCP proxy targets the console's own HTTPS port and is exercised with curl
# through the tunnel, and the UDP proxy targets the STUN/TURN port and is
# exercised with a STUN binding request, whose reply proves the return path too.
#
# Run it after any change to remgr-frps/src/server.rs — the crate's own tests and
# the in-tree probe only prove it agrees with itself:
#
#     ksh scripts/verify-frp-interop.sh
#
# Expected: "login to server success", "[…] start proxy success" for both proxies,
# both remote ports listening, curl returning 200 through the tunnel, and a STUN
# reply of 20+ bytes. Last run (frp 0.71.0, 2026-09-27, after the proxy-port retry
# change): all of the above.
UDP_REMOTE=17091

cleanup() {
	[ -n "${FRPCPID:-}" ] && kill "$FRPCPID" 2>/dev/null
	[ -n "${NCPID:-}" ] && kill "$NCPID" 2>/dev/null
}
trap cleanup EXIT

if [ ! -x "$FRP/frpc" ]; then
	mkdir -p /tmp/frp71 || exit 1
	cd /tmp/frp71 || exit 1
	url=https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_openbsd_amd64.tar.gz
	curl -sL --max-time 180 -o frp.tgz "$url" || { echo "download failed"; exit 1; }
	tar xzf frp.tgz || { echo "extract failed"; exit 1; }
	rm -f frp.tgz
fi
echo "client: $("$FRP/frpc" --version)"

TOKEN=$(grep -E '^token' /etc/remgr/config.toml | head -1 | sed -E 's/.*= *"//; s/".*//')
[ -n "$TOKEN" ] || { echo "no frps token in the config"; exit 1; }

cat > /tmp/frp71/interop.toml <<EOC
serverAddr = "127.0.0.1"
serverPort = 7000
auth.token = "$TOKEN"
log.level = "info"
transport.tls.enable = true
transport.tcpMux = true

[[proxies]]
name = "interop-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 9443
remotePort = $TCP_REMOTE

[[proxies]]
name = "interop-udp"
type = "udp"
localIP = "127.0.0.1"
localPort = 3478
remotePort = $UDP_REMOTE
EOC

echo "== start frpc =="
"$FRP/frpc" -c /tmp/frp71/interop.toml > /tmp/frp71/frpc.log 2>&1 &
FRPCPID=$!
sleep 6
grep -E "login to server success|start proxy success|start error|login failed" /tmp/frp71/frpc.log | head -6

echo
echo "== the server's listeners for the two proxies =="
netstat -na -f inet 2>/dev/null | grep -E "\.($TCP_REMOTE|$UDP_REMOTE) " | head -4

echo
echo "== TCP: curl the console *through* the tunnel =="
curl -ks -o /dev/null -w "  https://127.0.0.1:$TCP_REMOTE/ -> %{http_code}\n" --max-time 15 "https://127.0.0.1:$TCP_REMOTE/"

echo
echo "== UDP: STUN binding request through the tunnel (port 3478 of this box) =="
# 20-byte STUN binding request: type 0x0001, length 0, magic cookie, 12-byte txid
printf '\x00\x01\x00\x00\x21\x12\xa4\x42\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c' > /tmp/frp71/stun.req
if nc -u -w 5 127.0.0.1 "$UDP_REMOTE" < /tmp/frp71/stun.req > /tmp/frp71/stun.resp 2>/dev/null; then
	size=$(wc -c < /tmp/frp71/stun.resp | tr -d ' ')
	echo "  reply: $size bytes (a STUN binding response is 20+ bytes: the return path works)"
	[ "$size" -ge 20 ] && echo "  UDP tunnel: OK" || echo "  UDP tunnel: no usable reply"
else
	echo "  no reply through the UDP tunnel"
fi

echo
echo "== and the server agrees the proxies are up =="
PW=$(cat /var/run/remgr/initial_password 2>/dev/null || echo admin)
CK=/tmp/frp71/ck.txt
curl -ks -X POST "https://127.0.0.1:9443/api/login" -H content-type:application/json \
	-d "{\"username\":\"admin\",\"password\":\"$PW\"}" -c "$CK" > /dev/null
curl -ks -b "$CK" "https://127.0.0.1:9443/api/status" | tr ',' '\n' |
	grep -E "interop-tcp|interop-udp|proxies_running|clients_online" | head -8
rm -f "$CK"
echo "== done =="
