#!/usr/bin/env bash
#
# agentdo installer.
#
#   curl -fsSL https://raw.githubusercontent.com/FlysonBot/agentdo/main/install.sh | bash
#
# Or, preferably, read it first:
#
#   curl -fsSLO https://raw.githubusercontent.com/FlysonBot/agentdo/main/install.sh
#   less install.sh && bash install.sh
#
# Downloads the four files agentdo needs into place. Uses sudo for the install
# steps only; everything else runs as you. Set AGENTDO_REF to install from a
# branch, tag, or commit other than main.

set -euo pipefail

REPO="${AGENTDO_REPO:-FlysonBot/agentdo}"
REF="${AGENTDO_REF:-main}"
BASE="https://raw.githubusercontent.com/${REPO}/${REF}"

INSTALL_DIR="${AGENTDO_INSTALL_DIR:-/opt/agentdo}"
BIN_DIR="${AGENTDO_BIN_DIR:-/usr/local/bin}"
CONF_DIR="${AGENTDO_CONF_DIR:-/etc/agentdo}"

say()  { printf '[agentdo] %s\n' "$*" >&2; }
die()  { printf '[agentdo] error: %s\n' "$*" >&2; exit 1; }

# ------------------------------- preflight --------------------------------- #

[[ "$(uname -s)" == "Linux" ]] || die "agentdo is Linux-only (needs pidfd and SO_PEERCRED)."

[[ $EUID -ne 0 ]] || die "run this as your normal user, not root -- it calls sudo itself."

command -v python3 >/dev/null || die "python3 not found."
python3 - <<'PY' || die "python3 3.9+ required (needs socket.send_fds)."
import sys
sys.exit(0 if sys.version_info >= (3, 9) else 1)
PY

command -v sudo >/dev/null || die "sudo not found; agentdo needs it to start the broker."

# pidfd_open landed in 5.3. Compare only major.minor, and don't hard-fail on an
# unparseable version -- a wrong guess here should not block an install.
KREL="$(uname -r)"
if [[ "$KREL" =~ ^([0-9]+)\.([0-9]+) ]]; then
  if (( BASH_REMATCH[1] < 5 || (BASH_REMATCH[1] == 5 && BASH_REMATCH[2] < 3) )); then
    die "kernel $KREL is too old; agentdo needs 5.3+ for pidfd_open."
  fi
fi

if command -v curl >/dev/null; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null; then
  fetch() { wget -qO "$2" "$1"; }
else
  die "neither curl nor wget found."
fi

# --------------------------------- fetch ----------------------------------- #

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "downloading from ${REPO}@${REF}..."
for f in agentdo-broker.py bin/agentdo agentrun denylist.example.json; do
  mkdir -p "$TMP/$(dirname "$f")"
  fetch "$BASE/$f" "$TMP/$f" || die "failed to download $f"
  [[ -s "$TMP/$f" ]] || die "$f downloaded empty"
done

# A truncated or HTML-error download would install a broken broker, so check
# that what arrived is actually the code before putting it anywhere privileged.
python3 -m py_compile "$TMP/agentdo-broker.py" "$TMP/bin/agentdo" \
  || die "downloaded Python files failed to compile; refusing to install."
bash -n "$TMP/agentrun" || die "downloaded agentrun is not valid bash; refusing to install."

# -------------------------------- install ---------------------------------- #

say "installing (needs sudo)..."
sudo mkdir -p "$INSTALL_DIR/bin" "$CONF_DIR"
sudo install -m 0750 "$TMP/agentdo-broker.py" "$INSTALL_DIR/agentdo-broker.py"
sudo install -m 0755 "$TMP/bin/agentdo"       "$INSTALL_DIR/bin/agentdo"
sudo install -m 0755 "$TMP/agentrun"          "$BIN_DIR/agentrun"

# Never clobber a denylist the user has customised.
if [[ -e "$CONF_DIR/denylist.json" ]]; then
  say "keeping existing $CONF_DIR/denylist.json"
else
  sudo install -m 0644 "$TMP/denylist.example.json" "$CONF_DIR/denylist.json"
fi

# An upgrade over a running broker would leave the old code serving requests.
if pgrep -f "$INSTALL_DIR/agentdo-broker.py" >/dev/null 2>&1; then
  say "stopping the running broker so the new version is picked up..."
  sudo pkill -f "$INSTALL_DIR/agentdo-broker.py" || true
fi

say "installed:"
say "  $INSTALL_DIR/agentdo-broker.py"
say "  $INSTALL_DIR/bin/agentdo"
say "  $BIN_DIR/agentrun"
say ""
say "start an agent with:  agentrun claude"

if ! command -v agentrun >/dev/null 2>&1; then
  say ""
  say "note: $BIN_DIR is not on your PATH; add it or call $BIN_DIR/agentrun directly."
fi
