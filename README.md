# agentdo

**Scoped, revocable root for Claude Code — one command at a time, gone the
moment it exits.**

Imagine this:

You're debugging a service with Claude Code. It asks for `sudo journalctl -u nginx`.
You run it. You paste the output back. It asks for `sudo systemctl status nginx`.
You run it. You paste the output back. There's always one more command to run.

You do this back and forth for an hour, when the agent could of done all
of these for you in under 5 minutes.

The obvious fix is to let it run those commands itself. But an agent has no
interactive terminal, so `sudo` cannot ask it for a password. That leaves
three real options, and none are good:

- **Run the whole agent as root.** Every file it creates is now owned by root —
  its config, its caches, the files in your project. You now need to fix permissions.
  Claude may failed to launch next time due to permission issues. And there's
  always one more file that slip through.
- **Add `NOPASSWD:ALL` to sudoers.** Now *anything* running as your user have root,
  not just the agent. A malware on your machine now have root for free.
- **Setup an Askpass Program.** If you ever try to do this, you know how tedious
  it is to get it to work, and you cannot bypass the issue that you now have
  to store your sudo password somewhere on your disk since the program has to
  enter them on your behave, which is terrible for security.

Now, introducing `agentdo`!

`agentdo` give you the fourth option, and it's a good one! With `agentdo`, a broker
process run as root and execute commands on your AI agent's behaves. You launch your
agent with `agentrun claude` (replace `claude` with your agent), and your agent now
run `agentdo` instead of `sudo` whenever it need escalated permission. Your agent
never run as root itself, so no file permission problem to fix. The broker is only
thing that run as root, so nothing else need to be root, meaning no `NOPASSWD:ALL`
needed. The broken request ask you to authenticate for `sudo` once at the beginning
and keep running as root, so an askpass program is not needed either.

All the problem is solved! No password prompts. No root-owned files.
No askpass program. And most importantly, it is secure!

---

## How it works

Three pieces:

| | |
| --- | --- |
| **`agentrun`** | Starts the broker, launches your agent as *you*, and registers it. |
| **`agentdo-broker.py`** | Runs as root. Checks every request, executes what it approves, logs everything. |
| **`bin/agentdo`** | The shim your agent calls instead of `sudo`. |

Four things keep this narrower than a sudoers entry:

**Privilege is bound to one process, by the kernel.** At launch, the broker
captures a `pidfd` for your agent — a kernel handle to that exact process, not a
PID number that could later be reused by something else. Every request is
checked against it, and the kernel reports who is calling via `SO_PEERCRED`, so
the caller cannot lie about its identity. Requests from anywhere else on the
machine are refused, even from your own user account, and even if they bypass
the shim and speak the broker directly.

**Privilege dies with the process.** The broker watches that `pidfd`. When your
agent exits — cleanly, killed, or crashed — the broker revokes authorization and
shuts itself down. There is no window afterward, and nothing to remember to undo.
Close the terminal and the privilege is gone.

**Catastrophic commands are blocked outright.** A deny list refuses things a
agent should never legitimately needs: reformatting a disk, creating
users, rewriting `sudoers`, planting SSH keys, disabling the firewall,
`curl | sh`. These are refused before the command runs, and the refusal is
logged.

**Everything is on the record.** Every command, every denial, every rejected
caller is appended to a root-owned log the agent's own UID cannot rewrite. When
you want to know what happened, there's an answer.

Commands run with your real terminal attached, so interactive tools work
normally — `agentdo top` draws and responds to `Ctrl-C`, pipes and binary output
behave, and there's no output size limit.

---

## Requirements

- Linux, kernel 5.3+ (for `pidfd_open`)
- Python 3.9+ (standard library only — no dependencies)
- `sudo`, used at launch to start the broker and register the agent

## Install

First, clone this repo somewhere and `cd` into it:

```bash
git clone https://github.com/FlysonBot/agentdo.git
cd agentdo
```

Then, install the broker and shim:

```bash
sudo mkdir -p /opt/agentdo/bin /etc/agentdo
sudo install -m 0750 agentdo-broker.py /opt/agentdo/agentdo-broker.py
sudo install -m 0755 bin/agentdo       /opt/agentdo/bin/agentdo
sudo install -m 0755 agentrun          /usr/local/bin/agentrun

# Optional — built-in defaults apply if you skip this:
sudo install -m 0644 denylist.example.json /etc/agentdo/denylist.json
```

`bin/` holds a single file on purpose: that directory is placed on the client's
`PATH`, so anything in it becomes callable by name. Keeping the broker out of it
is deliberate — don't flatten it.

## Use

```bash
agentrun claude          # or other agents and commands you want to grant this to
```

The client starts as you, with `/opt/agentdo/bin` **prepended** to its `PATH`.
Anywhere it would have run `sudo <cmd>`, it runs `agentdo <cmd>` instead.

Claude Code won't know to do that on its own — tell it, in `CLAUDE.md`:

```markdown
For commands needing root, use `agentdo <cmd>` instead of `sudo <cmd>`.
```

If you'd rather not change how a client phrases commands, drop a wrapper named
`sudo` into the shim directory that forwards to `agentdo`. This will shadow the
system `sudo` for the agent's `PATH` only, leaving `/usr/bin/sudo` untouched.
This isn't done by default as a file named `sudo` on the `PATH` advertises
the privilege path to anything looking around.

Upgrading? **Restart the broker by running the following** —
the running one keeps its old code in memory:

```bash
sudo pkill -f 'agentdo-broker[.]py'
```

If you forget, `agentdo` tells you: requests carry a protocol version, and a
mismatch is refused with a message saying to restart.

---

## Read this before you rely on it

**What it protects against.** Unrelated processes cannot use the broker, even
running as your user, even speaking the socket protocol directly. Privilege
cannot outlive the client you launched. And every command is on the record in a
log the client's own UID cannot rewrite.

**What it does not.** Authorization answers *who is asking*, not *what they're
asking for or why they're asking*. If your agent starts doing things you don't
want it to do, or starts running malicious code, the broker cannot tell or
stop it. There is a deny list feature, but it only blocks against a fixed
list of dangerous patterns and is reactive, not proactive. If you noticed
your agent is doing something you don't want it to do, you should interrupt
it immediately before things get worse.

**Prompt injection is the realistic threat.** An LLM agent takes instructions
from whatever it reads: a web page, a repo, a log file, an error message. Text
in any of those can tell it to run a command, and your agent might mistaken
those as your instructions and run them. Treat every input your agent touches
as capable of issuing commands with this privilege.

**The denylist is a guardrail, not a wall.** It blocks realistic accidents and
unsophisticated misuse. It cannot stop someone who can shape arbitrary argv:
`bash -c '<obfuscated>'` defeats string matching, by construction.

---

## Configuration

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

---

## Tests

50 tests, no dependencies and no `sudo` required:

```bash
python3 tests/run.py
```

See [TESTS.md](TESTS.md) for what they cover and a manual smoke-test checklist.

## Status

Early and experimental. Read the code before running it as root on anything you
care about.

## License

MIT — see `LICENSE`.
