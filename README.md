# agentdo

**Lifecycle-scoped privilege for a single process.**

`agentdo` lets one unprivileged process — typically an autonomous agent or a
long-running application — run privileged commands, **without** running that
process as root and **without** a blanket `NOPASSWD: ALL` sudoers entry. The
grant is bound to one specific process instance and disappears the moment it
exits.

It exists for a specific situation: you have a process that legitimately needs
to run many privileged commands, but you don't want to (a) run the whole process
as root — which leaves root-owned files scattered through its config/working
directories and breaks on the next launch — or (b) hand its user account
permanent unrestricted sudo.

## How it works

Three pieces:

- **`agentdo-broker.py`** — a daemon that runs as root. It authorizes exactly
  one client process (captured as a `pidfd` at registration), executes commands
  on its behalf, applies a denylist, and logs everything. When the client exits,
  the broker revokes and shuts down.
- **`agentdo`** (the shim) — a small client the process calls instead of `sudo`.
  It forwards the command to the broker over a Unix socket.
- **`agentdo-launch.sh`** — starts the broker if needed, launches your client as
  your normal user with your environment, and registers it with the broker.

The client runs as **your** user, so everything it writes is owned by you.
Privileged commands are executed by the **root** broker on request. The two
concerns are cleanly separated: the process that makes a mess is never root, and
the thing that is root never wanders off writing files.

### Authorization model

The broker authorizes a caller by:

1. `SO_PEERCRED` on the Unix socket — the kernel stamps the connecting
   process's real PID/UID, which the client cannot spoof.
2. Matching that PID against the registered `pidfd` — a stable handle on one
   process instance, so a **reused PID** after the client dies cannot inherit
   the grant.
3. A `/proc/<pid>/stat` start-time cross-check as a belt-and-suspenders guard
   against PID reuse.
4. A liveness check on the pidfd.

When the authorized process exits, the broker revokes immediately (it is woken
by the pidfd, not a polling loop) and shuts itself down. **Privilege cannot
outlive the process.**

### Denylist, not allowlist

Workloads that need broad privilege (system auditing, troubleshooting,
provisioning) routinely run general-purpose interpreters — `find -exec`,
`bash -c`, `awk`, `python -c`. Any allowlist permissive enough to let such work
proceed necessarily contains commands that are each an arbitrary-command escape
hatch, so an allowlist gives you maintenance burden without a real boundary.

`agentdo` instead:

- **blocks** a short, editable list of catastrophic-and-rarely-needed operations
  (see below),
- **logs** every command to an append-only file the client's UID can't rewrite,
- **alerts** (logs, does not block) on a configurable set of sensitive verbs.

## Threat model — read before relying on this

`agentdo` raises the bar for some attackers and is transparent to others. Be
honest with yourself about which you face.

- **Wandering foothold** (attacker enters via some *other* service, then hunts
  for a way to escalate): the non-obvious shim + pidfd gate is a genuine
  obstacle. They can't easily pose as the authorized client.
- **Client compromise** (a malicious input to the agent, a poisoned dependency):
  the hostile code runs **as the authorized client**, so the pidfd gate cannot
  distinguish it from legitimate use. Here the **denylist and logs** are the only
  in-band controls — and a string denylist can be evaded by anyone able to shape
  arbitrary argv (`bash -c '<obfuscated>'`). The denylist targets realistic,
  low-sophistication misuse ("add an SSH key", "create a user", "curl x | sh"),
  not a determined human.
- **Not a substitute for isolation.** For a host you can't afford to lose, run
  the whole setup inside a VM or a snapshottable environment and point the
  workload at that.

In short: `agentdo` is a pragmatic middle point between "process runs as root"
and "unrestricted passwordless sudo." It is not a security boundary against a
motivated attacker who already controls the client.

## Requirements

- Linux with `pidfd_open` (kernel 5.3+; `os.pidfd_open` needs Python 3.9+, with a
  raw-syscall fallback for older Python).
- Python 3 (standard library only).
- `sudo` available to start the broker and register the client once at launch.

## Install

```bash
sudo mkdir -p /opt/agentdo/bin /etc/agentdo
sudo cp agentdo-broker.py /opt/agentdo/
sudo cp bin/agentdo       /opt/agentdo/bin/
sudo chmod 0755 /opt/agentdo/bin/agentdo
sudo chmod 0750 /opt/agentdo/agentdo-broker.py
# Optional: install a custom denylist (built-in defaults apply otherwise)
# sudo cp denylist.example.json /etc/agentdo/denylist.json
```

## Use

```bash
./agentdo-launch.sh <your-client-command> [args...]
```

The client comes up as your user with `/opt/agentdo/bin` early on its `PATH`, so
it can call `agentdo <cmd>` wherever it would have called `sudo <cmd>`. When the
client exits, the broker revokes and stops automatically.

### Wiring the client to use `agentdo`

Two options:

1. **Explicit (recommended):** configure or instruct your client to run
   privileged commands as `agentdo <cmd>` rather than `sudo <cmd>`. This keeps
   the privilege path explicit and leaves the system `sudo` untouched.
2. **Transparent:** place a wrapper named `sudo` in the shim directory that
   forwards to `agentdo`. Existing `sudo ...` calls then route to the broker for
   the client's `PATH` only; the system `/usr/bin/sudo` is unmodified. This is
   not shipped by default because a file named `sudo` on the client's `PATH`
   advertises the privilege path — but it's trivial to add if you want zero
   changes to how the client phrases commands.

## Configuration

All via environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `AGENTDO_SOCK` | `/run/agentdo.sock` | Command socket path |
| `AGENTDO_REG` | `/run/agentdo-reg.sock` | Registration socket (root-only) |
| `AGENTDO_LOG` | `/var/log/agentdo.log` | Append-only event log |
| `AGENTDO_DENY` | `/etc/agentdo/denylist.json` | Denylist file (optional) |
| `AGENTDO_CLIENT_UID` | `$SUDO_UID` | UID the broker will serve |
| `AGENTDO_INSTALL_DIR` | `/opt/agentdo` | Where the files live |
| `AGENTDO_SHIM_DIR` | `$INSTALL_DIR/bin` | Dir put early on client PATH |

## Denylist

Defaults are compiled into the broker and can be fully overridden by a JSON file
at `AGENTDO_DENY`. Patterns are Python regexes matched against the space-joined
argv; the file is hot-reloaded when it changes.

```json
{
  "patterns": ["...regexes that BLOCK the command..."],
  "alert_patterns": ["...regexes that LOG-AND-ALERT but still allow..."]
}
```

The built-in block list covers operations that are both dangerous and rarely
legitimate for a read/inspect workload: recursive root deletion, filesystem
formatting, `dd` onto a block device, user creation/deletion, password changes,
`visudo`, rewriting `sudoers`, planting `authorized_keys`, disabling the
firewall or SELinux, flushing iptables, and `curl|sh` / `wget|sh`. It alerts on
`chown`, world-writable `chmod`, `systemctl start/enable`, `crontab`, `at`,
`nc`, `chattr`, `mount`.

Keep the block list short and high-confidence: a false positive is a wall your
client hits mid-task. See `denylist.example.json`.

## Logs

One JSON object per line, fsync'd, append-only:

```bash
sudo tail -f /var/log/agentdo.log \
  | python3 -c 'import sys,json; [print(json.loads(l)) for l in sys.stdin]'
```

Event kinds: `start`, `register`, `exec`, `done`, `deny`, `alert`, `reject`,
`revoke`, `shutdown`.

## Verifying

1. `agentdo cat /etc/shadow` from the client → returns content.
2. `agentdo useradd -m test` → returns a denylist error, exits 126, logs `deny`.
3. Kill the client → broker exits and the socket disappears.
4. From another shell as the same user (different PID) → connection rejected.

## License

MIT — see `LICENSE`.

## Status

Early / experimental. Review the code before running it as root on anything you
care about, and treat the threat-model section above as load-bearing, not
boilerplate.
