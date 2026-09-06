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
#
# Killing it is NOT how to replace it: a client is registered only at launch, so
# every running agentrun would keep running while permanently losing privilege,
# with no way back short of restarting the agent. Instead start the new broker
# and let it ADOPT the old one's clients over the handoff socket; the old one
# retires once the transfer is confirmed, and agents mid-task never notice.
# Broker PIDs, excluding this script and its own children. A bare
# `pgrep -f "<pattern>"` also matches any process whose ARGUMENTS contain the
# pattern -- including the pgrep in a command substitution here -- which
# inflates the count and can make a completed handoff look like two brokers.
# Matching /proc/<pid>/exe's argv[1] avoids the whole class of self-matching.
broker_pids() {
  local pid comm
  for pid in $(pgrep -x python3 2>/dev/null); do
    [[ "$pid" == "$$" ]] && continue
    comm="$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | sed -n 2p)"
    [[ "$comm" == "$INSTALL_DIR/agentdo-broker.py" ]] && printf '%s\n' "$pid"
  done
  # Explicit success: the loop's last `[[ ]] && printf` would otherwise be the
  # function's exit status, and finding no broker is a normal outcome.
  return 0
}

if [[ -n "$(broker_pids)" ]]; then
  SOCK="${AGENTDO_SOCK:-/run/agentdo.sock}"
  REG="${AGENTDO_REG:-/run/agentdo-reg.sock}"
  HANDOFF="${AGENTDO_HANDOFF:-/run/agentdo-handoff.sock}"
  BOOT_LOG="${AGENTDO_BOOT_LOG:-/var/log/agentdo.boot.log}"

  if [[ -S "$HANDOFF" ]]; then
    say "a broker is running; handing its clients to the new version..."
    OLD_PIDS="$(broker_pids | sort -n | tr '\n' ' ')"

    # The successor must serve the same user, so take the client UID from the
    # broker it is replacing rather than assuming it is whoever runs this.
    #
    # `sudo cat`, not `sudo tr < file`: with a redirect, OUR shell opens the
    # file before sudo ever runs, and an unprivileged shell cannot read root's
    # /proc/<pid>/environ. The read itself has to happen as root. (agentrun
    # documents the same trap for its log redirect.)
    OLD_UID=""
    for p in $OLD_PIDS; do
      OLD_UID="$(sudo cat "/proc/$p/environ" 2>/dev/null | tr '\0' '\n' \
                 | sed -n 's/^AGENTDO_CLIENT_UID=//p' | head -1)"
      [[ -n "$OLD_UID" ]] && break
    done

    if [[ -n "$OLD_UID" ]]; then
      # Pass the socket paths through explicitly. `sudo env FOO=bar` forwards
      # ONLY what is listed, so a successor started without these would fall
      # back to the built-in defaults and bind paths the predecessor is not
      # using -- serving an empty registry on the default socket while the real
      # broker keeps its clients on the configured one.
      sudo env AGENTDO_CLIENT_UID="$OLD_UID" \
               AGENTDO_SOCK="$SOCK" AGENTDO_REG="$REG" \
               AGENTDO_HANDOFF="$HANDOFF" \
        setsid sh -c "exec python3 '$INSTALL_DIR/agentdo-broker.py' \
                      >>'$BOOT_LOG' 2>&1" &

      # The predecessor exits only after the successor confirms the transfer,
      # so "every original PID is gone" is the signal that the handoff really
      # completed rather than merely started.
      for _ in $(seq 1 50); do
        sleep 0.1
        STILL_OLD=""
        for p in $OLD_PIDS; do
          kill -0 "$p" 2>/dev/null && STILL_OLD="yes"
        done
        [[ -z "$STILL_OLD" && -S "$SOCK" ]] && break
      done

      if [[ -z "$STILL_OLD" && -S "$SOCK" && -n "$(broker_pids)" ]]; then
        say "upgrade complete; running agents kept their authorization."
      elif [[ -n "$STILL_OLD" ]]; then
        say "the old broker did not retire; it is still serving its clients."
        say "they are unaffected -- it will exit when its last client does,"
        say "and the next 'agentrun' starts the new version."
      else
        say "the new broker did not come up; see $BOOT_LOG."
        say "no broker is serving now -- run 'agentrun' to start the new one."
      fi
    else
      say "could not read the running broker's client UID; leaving it alone."
      say "running agents keep working on the OLD code until they exit."
    fi
  else
    # A broker installed before the handoff existed cannot transfer its
    # clients. Killing it would silently strip privilege from whatever is
    # running right now, so leave it: it exits once its last client does.
    say "the running broker predates seamless upgrades and cannot hand over."
    say "leaving it running: it will exit when its last client does, and the"
    say "next 'agentrun' starts the new version. Running agents are unaffected."
  fi
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
