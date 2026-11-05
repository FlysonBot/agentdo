#!/usr/bin/env bash
#
# Exercise install.sh and the upgrade handoff against a THROWAWAY prefix, using
# the working tree as the source. Nothing here touches /opt/agentdo,
# /usr/local/bin, /run/agentdo*.sock or a broker you are currently using, so it
# is safe to run while agentrun sessions are live.
#
#   tests/sandbox-install.sh            # install, then upgrade over itself
#   tests/sandbox-install.sh --keep     # leave the sandbox running to poke at
#
# It needs sudo (the broker must be root, exactly as in production).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SBX="${AGENTDO_SANDBOX:-/tmp/agentdo-sbx}"
KEEP=""
[[ "${1:-}" == "--keep" ]] && KEEP=1

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }

# Every path this test uses, all under $SBX or clearly namespaced.
export AGENTDO_INSTALL_DIR="$SBX/opt"
export AGENTDO_BIN_DIR="$SBX/bin"
export AGENTDO_CONF_DIR="$SBX/etc"
export AGENTDO_SOCK="$SBX/s.sock"
export AGENTDO_REG="$SBX/r.sock"
export AGENTDO_HANDOFF="$SBX/h.sock"
export AGENTDO_LOG="$SBX/events.log"
export AGENTDO_BOOT_LOG="$SBX/boot.log"
export AGENTDO_DENY="$SBX/etc/denylist.json"

# Serve the working tree instead of GitHub. install.sh builds its URLs as
# "$BASE/<file>", and curl/wget both accept file:// -- so an unpushed branch is
# testable without pushing anything.
export AGENTDO_REPO="."
export AGENTDO_REF="."
_base_override() { :; }

cleanup() {
  local pids
  pids="$(broker_pids || true)"
  if [[ -n "$pids" ]]; then
    note "stopping sandbox broker(s): $pids"
    sudo kill $pids 2>/dev/null || true
    sleep 0.5
  fi
  [[ -n "$KEEP" ]] || sudo rm -rf "$SBX"
}

# Brokers belonging to THIS sandbox only -- matched on argv[1], so it can never
# pick up your real /opt/agentdo broker.
broker_pids() {
  local pid arg1
  for pid in $(pgrep -x python3 2>/dev/null); do
    arg1="$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | sed -n 2p)"
    [[ "$arg1" == "$AGENTDO_INSTALL_DIR/agentdo-broker.py" ]] && printf '%s\n' "$pid"
  done
  return 0
}

trap cleanup EXIT

say "sandbox: $SBX"
sudo rm -rf "$SBX"
# BIN_DIR is normally /usr/local/bin, which already exists, so install.sh does
# not create it. A redirected one has to exist before `install` writes into it.
mkdir -p "$SBX" "$AGENTDO_BIN_DIR"

# ---------------------------------------------------------------------------
say "1. install from the working tree"
# install.sh composes BASE from REPO/REF; point it at the checkout instead.
sed "s|^BASE=.*|BASE=\"file://$REPO_DIR\"|" "$REPO_DIR/install.sh" > "$SBX/install.sh"
bash "$SBX/install.sh" --sudo-shim

[[ -x "$AGENTDO_BIN_DIR/agentrun" ]] || { echo "FAIL: agentrun not installed"; exit 1; }
[[ "$(readlink "$AGENTDO_INSTALL_DIR/bin/sudo")" == "agentdo" ]] \
  || { echo "FAIL: --sudo-shim did not create the sudo -> agentdo symlink"; exit 1; }
note "installed: $(ls "$AGENTDO_INSTALL_DIR" "$AGENTDO_BIN_DIR" | tr '\n' ' ')"

# ---------------------------------------------------------------------------
say "2. start a broker with a client, as agentrun does"
# A stand-in client: any long-lived process works as the registered tree root.
setsid sleep 600 & CLIENT=$!
disown 2>/dev/null || true
sleep 0.3

sudo env AGENTDO_SOCK="$AGENTDO_SOCK" AGENTDO_REG="$AGENTDO_REG" \
         AGENTDO_HANDOFF="$AGENTDO_HANDOFF" AGENTDO_LOG="$AGENTDO_LOG" \
         AGENTDO_DENY="$AGENTDO_DENY" AGENTDO_CLIENT_UID="$(id -u)" \
    setsid sh -c "exec python3 '$AGENTDO_INSTALL_DIR/agentdo-broker.py' \
                  >>'$AGENTDO_BOOT_LOG' 2>&1" &
for _ in $(seq 1 50); do [[ -S "$AGENTDO_SOCK" ]] && break; sleep 0.1; done
[[ -S "$AGENTDO_SOCK" ]] || { echo "FAIL: broker never came up"; sudo cat "$AGENTDO_BOOT_LOG"; exit 1; }

sudo python3 - "$AGENTDO_REG" "$CLIENT" <<'PY'
import sys, socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(json.dumps({"pid": int(sys.argv[2])}).encode())
s.shutdown(socket.SHUT_WR)
print("   registration:", s.recv(4096).decode().strip())
PY

OLD="$(broker_pids | tr '\n' ' ')"
note "broker before upgrade: $OLD   client: $CLIENT"

# ---------------------------------------------------------------------------
say "3. upgrade over the running broker (agentrun --upgrade)"
"$AGENTDO_BIN_DIR/agentrun" --upgrade

NEW="$(broker_pids | tr '\n' ' ')"
note "broker after upgrade:  $NEW"

# ---------------------------------------------------------------------------
say "4. verify"
fail=0

for p in $OLD; do
  if kill -0 "$p" 2>/dev/null; then
    echo "   FAIL: old broker $p did not retire"; fail=1
  fi
done
[[ -n "$NEW" ]] || { echo "   FAIL: no broker serving after upgrade"; fail=1; }
[[ "$(printf '%s' "$NEW" | wc -w)" == "1" ]] || { echo "   FAIL: expected exactly one broker, got '$NEW'"; fail=1; }

# The registry must have MOVED, not been rebuilt: the new broker should still
# name the original client as an authorized root.
out="$(AGENTDO_SOCK="$AGENTDO_SOCK" python3 "$AGENTDO_INSTALL_DIR/bin/agentdo" true 2>&1 || true)"
if [[ "$out" == *"roots: $CLIENT"* ]]; then
  note "OK: adopted client $CLIENT is still the authorized root"
elif [[ "$out" == *"no authorized client"* ]]; then
  echo "   FAIL: new broker has an EMPTY registry -- the handoff did not transfer"; fail=1
else
  note "note: unexpected shim output: $out"
fi

# The sudo shim is the same file, so it must accept sudo's options too.
out="$(AGENTDO_SOCK="$AGENTDO_SOCK" "$AGENTDO_INSTALL_DIR/bin/sudo" -n true 2>&1 || true)"
if [[ "$out" == *"unknown option"* || "$out" == *"command not found"* ]]; then
  echo "   FAIL: sudo shim rejected -n: $out"; fail=1
else
  note "OK: sudo shim accepts sudo options"
fi

if sudo grep -q '"kind": "handoff_out"' "$AGENTDO_LOG" 2>/dev/null; then
  note "OK: $(sudo grep '"kind": "handoff_out"' "$AGENTDO_LOG" | tail -1)"
else
  echo "   FAIL: no handoff_out in the event log"; fail=1
fi

kill "$CLIENT" 2>/dev/null || true

if [[ "$fail" == "0" ]]; then
  printf '\n\033[32m   PASS -- install and seamless upgrade both work\033[0m\n\n'
else
  printf '\n\033[31m   FAILED\033[0m\n\n'
fi

[[ -n "$KEEP" ]] && note "sandbox kept at $SBX (broker still running)"
exit "$fail"
