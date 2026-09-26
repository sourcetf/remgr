#!/bin/ksh
# Run scripts/probes/turn-allocation.c against this deployment, using the TURN
# credentials from /etc/remgr/config.toml.
#
#   ksh scripts/probes/run-turn-probe.sh [host] [port]
#
# The point of doing it this way: the credentials stay out of the command line, the
# shell history and every log — and out of this repository, which is public.
set -u
cfg=/etc/remgr/config.toml
# the whole section: users is the eleventh key in it, so a fixed -A window missed it
line=$(sed -n '/^\[stun_turn\]/,/^\[/p' "$cfg" | grep -m1 '^users' || true)
entry=$(printf '%s\n' "$line" | cut -d'"' -f2)
user=${entry%%:*}
pass=${entry#*:}
if [ -z "$user" ] || [ -z "$pass" ] || [ "$user" = "$entry" ]; then
	echo "no usable [stun_turn] credential in $cfg (found: '$line')"
	exit 1
fi
echo "using a ${#user}-char user and a ${#pass}-char password from the config"
if [ ! -x /tmp/p-turn ]; then
	cc -O1 -o /tmp/p-turn /root/ReMgr/scripts/probes/turn-allocation.c -lcrypto || exit 1
fi
TURN_USER="$user" TURN_PASS="$pass" /tmp/p-turn 127.0.0.1 3478
