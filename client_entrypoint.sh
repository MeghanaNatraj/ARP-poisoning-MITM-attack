#!/usr/bin/env sh
set -eu

CAPDIR="/captures"
TS="$(date +%s)"
PCAP="${CAPDIR}/client-${TS}.pcap"
# Network interface to capture on; default to eth0
IFACE="${IFACE:-eth0}"

mkdir -p "$CAPDIR" || true
chmod 0777 "$CAPDIR" || true

echo "[client] tcpdump: iface=$IFACE -> $PCAP"
# start tcpdump in the background
tcpdump -i "$IFACE" -nn -s 0 -w "$PCAP" -U &
TCPDUMP_PID=$!

# stop tcpdump when container stops
cleanup() {
  echo "[client] stopping tcpdump pid=$TCPDUMP_PID"
  kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# hand off to the container's main command (your script.sh)
exec "$@"
