<p align="center">
<img src="https://raw.githubusercontent.com/FlysonBot/agentdo/main/logo.svg" width="260" title="agentdo Logo" alt="agentdo Logo">
</p>

<h3 align="center">Scoped, revocable root for Claude Code —<br>
one command at a time, gone the moment it exits.</h3>

<p align="center">
<a href="#install"><img src="https://img.shields.io/badge/install-2%20minutes-d45840?style=flat-square" alt="Install in 2 minutes"></a>
<img src="https://img.shields.io/badge/dependencies-none-d45840?style=flat-square" alt="No dependencies">
<img src="https://img.shields.io/badge/python-3.9%2B-d45840?style=flat-square" alt="Python 3.9+">
<img src="https://img.shields.io/badge/license-MIT-d45840?style=flat-square" alt="MIT License">
</p>

---

## The problem

You're debugging a service with Claude Code. It asks for `sudo journalctl -u nginx`.

You run it. You paste the output back. It asks for `sudo systemctl status nginx`.

You run it. You paste the output back. There's always one more command to run.

**You spend an hour relaying commands the agent could have run itself in five minutes.**

The obvious fix is to let it run those commands directly. But an agent has no
interactive terminal, so `sudo` can never ask it for a password. That leaves
three options, and none of them are good:

| Option | What it costs you |
| --- | --- |
| **Run the agent as root** | Every file it creates is root-owned — its config, its caches, your project files. You'll be fixing permissions for days, and there's always one more that slipped through. |
| **Add `NOPASSWD:ALL` to sudoers** | *Anything* running as your user now has root. Not just the agent. Malware on your machine gets root for free. |
| **Set up an askpass program** | Tedious to wire up, and it only works if your sudo password sits somewhere a program can read it. Terrible trade. |

## The fix

`agentdo` is the fourth option.

A broker process holds root and runs commands on your agent's behalf. You
launch your agent with `agentrun claude`, and it calls `agentdo` instead of
`sudo` whenever it needs privilege.

```console
$ agentrun claude                       # authenticate once, up front

# ...inside the session, Claude runs privileged commands itself:
$ dmesg | head -1
dmesg: read kernel buffer failed: Operation not permitted
$ agentdo dmesg | head -1
[    0.000000] Linux version ...
```

No root-owned files, no `NOPASSWD:ALL`, no password on disk. When the agent
exits, the privilege is gone.

---

## How it works

Three pieces:

| Piece | What it does |
| --- | --- |
| **`agentrun`** | Starts the broker, launches your agent as *you*, and registers it. |
| **`agentdo-broker.py`** | Runs as root. Checks every request, executes what it approves, logs everything. |
| **`bin/agentdo`** | The shim your agent calls instead of `sudo`. |

Four things keep this narrower than a sudoers entry.

### 🔒 Bound to one process, by the kernel

The broker captures a `pidfd` for your agent — a kernel handle to that exact
process, not a PID number something else could reuse. The kernel itself reports
who is calling, so a caller cannot lie about its identity. Requests from
anywhere else are refused, even from your own user account.

### ⏱️ Dies with the process

When your agent exits — cleanly, killed, or crashed — the broker revokes
authorization and shuts down. No window afterward, nothing to remember to undo.

### 🛑 Catastrophic commands blocked

A deny list refuses what an agent should never need: reformatting a disk,
creating users, rewriting `sudoers`, planting SSH keys, disabling the firewall,
`curl | sh`. Rejected before the command runs.

### 🔍 Everything on the record

Every command, denial, and rejected caller is appended to a root-owned log the
agent's own UID cannot rewrite.

> [!NOTE]
> Interactive commands work normally — `agentdo top` draws and responds to
> `Ctrl-C`, pipes and binary output behave, and there's no output size limit.

---

## Install

Requires Linux (kernel 5.3+), Python 3.9+, and `sudo`. No dependencies.

```bash
git clone https://github.com/FlysonBot/agentdo.git && cd agentdo

sudo mkdir -p /opt/agentdo/bin /etc/agentdo
sudo install -m 0750 agentdo-broker.py /opt/agentdo/agentdo-broker.py
sudo install -m 0755 bin/agentdo       /opt/agentdo/bin/agentdo
sudo install -m 0755 agentrun          /usr/local/bin/agentrun

# Optional — built-in defaults apply if you skip this:
sudo install -m 0644 denylist.example.json /etc/agentdo/denylist.json
```

Prefer a one-liner? Run this instead:
```bash
curl -fsSL https://raw.githubusercontent.com/FlysonBot/agentdo/main/install.sh | bash
```

Either way, re-running it on a newer version is also how you upgrade — see
[Upgrading](#upgrading).

To uninstall, remove what that put in place:

```bash
sudo pkill -f 'agentdo-broker[.]py'
sudo rm -rf /opt/agentdo /etc/agentdo
sudo rm -f  /usr/local/bin/agentrun /var/log/agentdo*.log /run/agentdo*.sock
```

One-liner to uninstall (pass --purge if you want deny list and logs removed as well):
```bash
curl -fsSL https://raw.githubusercontent.com/FlysonBot/agentdo/main/uninstall.sh | bash
```

## Use

```bash
agentrun claude          # or any agent or command you want to grant this to
```

Claude Code won't know to use the shim on its own — tell it, in `CLAUDE.md`:

```markdown
For commands needing root, use `agentdo <cmd>` instead of `sudo <cmd>`.
```

> [!TIP]
> Prefer not to change how your agent phrases commands? Drop a wrapper named
> `sudo` into `/opt/agentdo/bin`. It shadows the system `sudo` for that agent
> only. Not the default, since a file named `sudo` on the `PATH` advertises the
> privilege path.

## Upgrading

Run the install command again — the same one you used to install:

```bash
curl -fsSL https://raw.githubusercontent.com/FlysonBot/agentdo/main/install.sh | bash
```

If a broker is still running, it hands its clients over to the new version and
retires — agents mid-task keep working and never notice.

To do so after manual upgrading (meaning you didn't run the one-liner above), run:

```bash
sudo env AGENTDO_CLIENT_UID="$(id -u)" \
  setsid sh -c 'exec python3 /opt/agentdo/agentdo-broker.py \
                >>/var/log/agentdo.boot.log 2>&1' &
```

---

## ⚠️ Read this before you rely on it

### ✅ What it protects against

Unrelated processes cannot use the broker — not even running as your user, not
even speaking the socket protocol directly. Privilege cannot outlive the client
you launched. And every command is on the record in a log the client's own UID
cannot rewrite.

### ❌ What it does not

Authorization answers *who is asking*, not *what they're asking for or why*. If
your agent starts doing things you don't want, or starts running malicious code,
the broker cannot tell and will not stop it. The deny list blocks a fixed set of
dangerous patterns — it is reactive, not proactive. **If you notice your agent
doing something you don't want, interrupt it immediately.**

> [!WARNING]
> **Prompt injection is the realistic threat.** An LLM agent takes instructions
> from whatever it reads — a web page, a repo, a log file, an error message.
> Text in any of those can tell it to run a command, and your agent may mistake
> that for your instruction. Treat every input your agent touches as capable of
> issuing commands with this privilege.

**The deny list is a guardrail, not a wall.** It blocks realistic accidents and
unsophisticated misuse. It cannot stop anyone who can shape arbitrary argv:
`bash -c '<obfuscated>'` defeats string matching, by construction.

---

## Docs

- [CONFIGURATION.md](CONFIGURATION.md) — environment variables, deny list, logs
- [TESTS.md](TESTS.md) — running the suite, what it covers

## Status

Early and experimental. Read the code before running it as root on anything you
care about.

## License

MIT — see `LICENSE`.
