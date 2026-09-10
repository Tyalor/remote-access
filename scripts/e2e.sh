#!/usr/bin/env bash
# End-to-end test of the ID/password flow with no GPU, no Apollo and no
# Moonlight: rendezvous + fake Apollo + host agent + native client pairing.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p ra-rendezvous -p ra-host -p ra-client -p ra-fakehost
BIN=target/debug
TMP=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT
export RA_HOME="$TMP/client" RA_HOST_CONFIG="$TMP/host.toml" RUST_LOG=${RUST_LOG:-info}
RV_PORT=${RV_PORT:-21999}
GS_PORT=${GS_PORT:-47989}

"$BIN/ra-rendezvous" --listen "127.0.0.1:$RV_PORT" > "$TMP/rv.log" 2>&1 &
"$BIN/ra-fakehost" --port "$GS_PORT" --username admin --password admin > "$TMP/fake.log" 2>&1 &
sleep 1

"$BIN/ra-host" init --rendezvous "http://127.0.0.1:$RV_PORT" \
  --apollo-url "http://127.0.0.1:$((GS_PORT+1))" --apollo-username admin --apollo-password admin \
  --name "E2E Host" --password "correct horse" > "$TMP/init.log"
ID=$("$BIN/ra-host" id | tr -d ' ')
echo "host id: $ID"
"$BIN/ra-host" run > "$TMP/host.log" 2>&1 &
sleep 1

"$BIN/ra" config --rendezvous "http://127.0.0.1:$RV_PORT" > /dev/null
"$BIN/ra" info "$ID" | tee "$TMP/info.log"
grep -q "reachable    127.0.0.1:$GS_PORT" "$TMP/info.log"

echo "--- wrong password must be rejected"
if "$BIN/ra" pair "$ID" --native --password "nope" 2>&1 | tee "$TMP/wrong.log"; then
  echo "FAIL: wrong password accepted"; exit 1
fi
grep -q "wrong password" "$TMP/wrong.log"

echo "--- correct password pairs natively and lists apps"
"$BIN/ra" pair "$ID" --native --password "correct horse" 2>&1 | tee "$TMP/pair.log"
grep -q "Desktop" "$TMP/pair.log"
grep -q "paired natively" "$TMP/pair.log"

echo "--- host applied permissions"
grep -q "permissions applied" "$TMP/host.log"
"$BIN/ra-host" clients | tee "$TMP/clients.log"
grep -q "perm=0x07031f00" "$TMP/clients.log"

echo "--- cached password: apps without re-pairing"
"$BIN/ra" apps "$ID" | tee "$TMP/apps.log"
grep -q "Steam Big Picture" "$TMP/apps.log"

echo "E2E OK"
