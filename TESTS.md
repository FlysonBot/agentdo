# Tests

```bash
python3 tests/run.py                    # all 73
python3 tests/run.py gate               # gate | protocol | signals | launcher | handoff
```

No dependencies, no `sudo`, no password prompt. Each test starts its own broker
on a private socket under `/tmp` and runs commands as you; the launcher tests
substitute a fake `sudo` on `PATH`. Nothing touches `/run`, `/var/log`, or an
installed copy, so the suite is safe to run while `agentdo` is live.

## What each module covers

- **`test_gate.py`** — who may run commands: the ancestry walk (self, child,
  grandchild, PID 1, a recycled PID, a process that escaped the tree) and the
  same decisions end to end through the real socket.
- **`test_protocol.py`** — stdio passing, exit-code conventions, the version
  handshake, malformed requests, the denylist.
- **`test_signals.py`** — signal relay and resource hygiene.
- **`test_launcher.py`** — `agentrun`: sudo prompts, startup timing, arguments.
- **`test_handoff.py`** — upgrading without severing running clients: a
  successor adopts its predecessor's registry as live pidfds, the predecessor
  retires, and the gate is no wider afterwards. Also the failure branches,
  driven by a peer that misbehaves on purpose: a non-root requester, a version
  mismatch, and the three ways a handoff can be abandoned (the successor drops
  the connection, stays silent until the timeout, or refuses outright). All
  must leave the predecessor serving — a failed handoff must never leave
  clients with no broker at all.

Most cases are regressions for bugs that reached a user, and each says in its
docstring which failure it defends against.

**Not covered:** the root-only paths (log writes, socket ownership), which need
a privileged install to exercise.

## Installing and upgrading

`install.sh` and `agentrun --upgrade` cannot be reached by the suite above:
both need real root and a real process boundary, and the in-process harness
stubs the exit paths a genuine handoff depends on.

```bash
tests/sandbox-install.sh          # add --keep to leave it running
```

It installs from the working tree — not GitHub, so an unpushed branch is
testable — into a throwaway prefix under `/tmp`, starts a broker with a
registered client, upgrades over it, and checks that the registry *moved*
rather than being rebuilt: the new broker must still name the original client
as an authorized root. Every path is redirected and broker discovery matches on
`/proc/<pid>/cmdline`, so it cannot see or disturb an installed broker you are
using. It does need `sudo`, since the broker must be root.

## How the suite runs unprivileged

The broker refuses to start as a non-root process, but that check lives in
`main()`. The tests import the module and drive `registration_server` and
`command_server` directly, so the real gate, protocol, and denylist code runs
while commands execute with your own privileges rather than root's.

Two constraints shape the harness:

- **Socket paths stay short.** `AF_UNIX` caps a path near 108 bytes, and
  exceeding it fails with a confusing error from `connect()`, so each test gets
  a short `/tmp` directory rather than one under the repo.
- **Commands run inside the registered tree.** Authorization covers a process
  tree, so a client spawned from the test process itself is correctly refused.
  The harness sends commands to a registered helper shell and reads results
  back, which is the only way to exercise the allowed path.

## Manual smoke test

Some things need a real terminal and a privileged install. After installing,
launch a client and check:

1. `agentdo cat /etc/shadow` → returns content
2. `agentdo useradd -m test` → denylist error, exit 126, logs `deny`
3. `echo hi | agentdo cat` → prints `hi`
4. `agentdo top` → runs interactively; `Ctrl-C` and resizing work
5. Exit the client → broker stops, socket disappears (only once its *last*
   client is gone: with a second `agentrun` running, the first exiting must
   leave that one working)
6. `agentdo echo x` from an unrelated shell → refused
