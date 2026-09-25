#!/usr/bin/env bash
# End-to-end test of the ID/password flow with no GPU, no Apollo and no
# Moonlight: rendezvous + fake Apollo + host agent + native client pairing.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p ra-rendezvous -p ra-host -p ra-client -p ra-fakehost -p ra-desk
BIN=target/debug
TMP=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT
export RA_HOME="$TMP/client" RA_HOST_CONFIG="$TMP/host.toml" RUST_LOG=${RUST_LOG:-info}
RV_PORT=${RV_PORT:-21999}
GS_PORT=${GS_PORT:-47989}

wait_for() { # url
  for _ in $(seq 1 120); do curl -fs "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done
  echo "timeout waiting for $1"; return 1
}

"$BIN/ra-rendezvous" --listen "127.0.0.1:$RV_PORT" > "$TMP/rv.log" 2>&1 &
"$BIN/ra-fakehost" --port "$GS_PORT" --username admin --password admin > "$TMP/fake.log" 2>&1 &
wait_for "http://127.0.0.1:$RV_PORT/v1/health"
wait_for "http://127.0.0.1:$GS_PORT/serverinfo"

"$BIN/ra-host" init --rendezvous "http://127.0.0.1:$RV_PORT" \
  --apollo-url "http://127.0.0.1:$((GS_PORT+1))" --apollo-username admin --apollo-password admin \
  --name "E2E Host" --password "correct horse" > "$TMP/init.log"
ID=$("$BIN/ra-host" id | tr -d ' ')
echo "host id: $ID"
"$BIN/ra-host" run > "$TMP/host.log" 2>&1 &
for _ in $(seq 1 60); do /usr/bin/grep -q "host online" "$TMP/host.log" && break; sleep 0.5; done

"$BIN/ra" config --rendezvous "http://127.0.0.1:$RV_PORT" > /dev/null
"$BIN/ra" info "$ID" | tee "$TMP/info.log"
/usr/bin/grep -q "reachable    127.0.0.1:$GS_PORT" "$TMP/info.log"

echo "--- wrong password must be rejected"
if "$BIN/ra" pair "$ID" --native --password "nope" 2>&1 | tee "$TMP/wrong.log"; then
  echo "FAIL: wrong password accepted"; exit 1
fi
/usr/bin/grep -q "wrong password" "$TMP/wrong.log"

echo "--- correct password pairs natively and lists apps"
"$BIN/ra" pair "$ID" --native --password "correct horse" 2>&1 | tee "$TMP/pair.log"
/usr/bin/grep -q "Desktop" "$TMP/pair.log"
/usr/bin/grep -q "paired natively" "$TMP/pair.log"

echo "--- host applied permissions"
/usr/bin/grep -q "permissions applied" "$TMP/host.log"
"$BIN/ra-host" clients | tee "$TMP/clients.log"
/usr/bin/grep -q "perm=0x07031f00" "$TMP/clients.log"

echo "--- cached password: apps without re-pairing"
"$BIN/ra" apps "$ID" | tee "$TMP/apps.log"
/usr/bin/grep -q "Steam Big Picture" "$TMP/apps.log"

echo "--- headless desktop app takes over the host agent"
kill %3 2>/dev/null || true   # ra-host run
sleep 1
"$BIN/ra-desk" --headless > "$TMP/desk.log" 2>&1 &
for _ in $(seq 1 60); do /usr/bin/grep -q "host online" "$TMP/desk.log" && break; sleep 0.5; done
/usr/bin/grep -q "headless host agent starting" "$TMP/desk.log"
if "$BIN/ra-desk" --headless > "$TMP/desk2.log" 2>&1; then echo "FAIL: second headless instance should refuse"; exit 1; fi
/usr/bin/grep -q "already running" "$TMP/desk2.log"
RA_HOME="$TMP/client2" "$BIN/ra" config --rendezvous "http://127.0.0.1:$RV_PORT" > /dev/null
RA_HOME="$TMP/client2" "$BIN/ra" pair "$ID" --native --password "correct horse" 2>&1 | tee "$TMP/pair2.log"
/usr/bin/grep -q "paired natively" "$TMP/pair2.log"
/usr/bin/grep -q "permissions applied" "$TMP/desk.log"

echo "E2E OK"
