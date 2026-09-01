#!/usr/bin/env bash
#
# agentdo uninstaller.
#
#   curl -fsSL https://raw.githubusercontent.com/FlysonBot/agentdo/main/uninstall.sh | bash
#
# Removes the broker, the shim and the launcher. Leaves your logs and your
# denylist alone by default, since those are records and configuration rather
# than program files:
#
#   --purge   also remove /etc/agentdo and /var/log/agentdo*.log

set -euo pipefail

INSTALL_DIR="${AGENTDO_INSTALL_DIR:-/opt/agentdo}"
BIN_DIR="${AGENTDO_BIN_DIR:-/usr/local/bin}"
CONF_DIR="${AGENTDO_CONF_DIR:-/etc/agentdo}"
LOG="${AGENTDO_LOG:-/var/log/agentdo.log}"
BOOT_LOG="${AGENTDO_BOOT_LOG:-/var/log/agentdo.boot.log}"
SOCK="${AGENTDO_SOCK:-/run/agentdo.sock}"
REG="${AGENTDO_REG:-/run/agentdo-reg.sock}"

PURGE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) printf '[agentdo] unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

say() { printf '[agentdo] %s\n' "$*" >&2; }

[[ $EUID -ne 0 ]] || { say "run this as your normal user, not root -- it calls sudo itself."; exit 1; }

# Stop the broker first: it holds root and owns the sockets, and it exits on its
# own when its client exits, so a stale one may or may not still be around.
if pgrep -f "$INSTALL_DIR/agentdo-broker.py" >/dev/null 2>&1; then
  say "stopping the broker..."
  sudo pkill -f "$INSTALL_DIR/agentdo-broker.py" || true
  sleep 0.5
fi

say "removing files (needs sudo)..."
sudo rm -rf "$INSTALL_DIR"
sudo rm -f  "$BIN_DIR/agentrun"
sudo rm -f  "$SOCK" "$REG"

if (( PURGE )); then
  say "purging configuration and logs..."
  sudo rm -rf "$CONF_DIR"
  sudo rm -f  "$LOG" "$BOOT_LOG"
else
  [[ -e "$CONF_DIR" ]] && say "kept $CONF_DIR (use --purge to remove)"
  [[ -e "$LOG"      ]] && say "kept $LOG (use --purge to remove)"
fi

say "done."

# The client's PATH entry only exists inside a session agentrun started, so
# there is nothing to unset in your shell config -- unlike an askpass setup,
# agentdo never edits it.
