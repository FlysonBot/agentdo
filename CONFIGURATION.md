# Configuration

Everything is an environment variable:

| Variable | Default | Meaning |
| --- | --- | --- |
| `AGENTDO_SOCK` | `/run/agentdo.sock` | Command socket |
| `AGENTDO_REG` | `/run/agentdo-reg.sock` | Registration socket (root-only) |
| `AGENTDO_LOG` | `/var/log/agentdo.log` | Append-only event log |
| `AGENTDO_DENY` | `/etc/agentdo/denylist.json` | Denylist file (optional) |
| `AGENTDO_CLIENT_UID` | `$SUDO_UID` | UID the broker serves |
| `AGENTDO_INSTALL_DIR` | `/opt/agentdo` | Where the files live |
| `AGENTDO_SHIM_DIR` | `$INSTALL_DIR/bin` | Directory added to client `PATH` |

### Denylist

Python regexes matched against the space-joined argv, hot-reloaded on change:

```json
{
  "patterns":       ["...regexes that BLOCK the command..."],
  "alert_patterns": ["...regexes that LOG but still ALLOW..."]
}
```

Built-in blocks: recursive root deletion, `mkfs`, `dd` onto a block device, user
creation/deletion, password changes, `visudo`, rewriting `sudoers`, planting
`authorized_keys`, disabling the firewall or SELinux, flushing iptables, and
`curl|sh` / `wget|sh`. Alerts on `chown`, world-writable `chmod`, `systemctl
start/enable`, `crontab`, `at`, `nc`, `chattr`, `mount`.

Keep your block list short and high-confidence. A false positive is a wall your
agent hits mid-task. See `denylist.example.json`.

### Logs

One JSON object per line, fsync'd, append-only:

```bash
sudo tail -f /var/log/agentdo.log \
  | python3 -c 'import sys,json; [print(json.loads(l)) for l in sys.stdin]'
```

Events: `start`, `register`, `exec`, `done`, `deny`, `alert`, `reject`,
`version_mismatch`, `revoke`, `shutdown`.
