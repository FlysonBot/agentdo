#!/usr/bin/env python3
"""
agentdo-broker.py  --  a lifecycle-scoped privileged command broker.

agentdo lets a single unprivileged process (typically an autonomous agent or a
long-running application) execute privileged commands, without running that
process as root and without a blanket NOPASSWD:ALL sudoers entry. Privileges are
bound to one process instance and vanish the moment it exits.

DESIGN (do not "simplify" these away):
  * The broker runs as root (it must, to execute privileged commands).
  * It authorizes ONE PROCESS TREE: the registered client, identified by a
    pidfd captured at registration, plus that process's descendants. Not a bare
    PID number -- a pidfd, so a recycled PID cannot impersonate the client
    after it exits.
    The unit is the tree, not a single PID, because the `agentdo` shim runs as
    a CHILD of the registered client (you type `agentdo ...` at a registered
    shell). A single-PID gate would reject every real caller: the registered
    process is the one that never makes requests.
  * Per-request it re-validates the caller via SO_PEERCRED, confirms the
    registered root is still alive (pidfd), and walks the caller's parent chain
    up to that root, re-checking the root's /proc start-time so a recycled PID
    cannot inherit authorization. If the client has exited, the broker refuses
    and shuts down -- privilege dies with the process, by construction.
  * A descendant that deliberately orphans itself (double-fork) reparents to
    init or a subreaper such as `systemd --user`, leaving the tree, and then
    fails the ancestry check. Escaping the tree LOSES privilege: the gate fails
    closed.
  * An upgrade HANDS OVER rather than restarting cold: a successor broker
    adopts the running one's registry by receiving each live pidfd over
    SCM_RIGHTS, and the predecessor retires once the transfer is confirmed.
    Clients are registered only at launch, so killing a broker would strip
    privilege from every running agent with no way back. Authorizations move as
    descriptors and never as PID numbers -- re-deriving a pidfd from a
    serialized PID would reopen the recycled-PID hole the pidfd design closes.
  * It does NOT allowlist commands. Many real workloads (e.g. system auditing,
    troubleshooting) legitimately run general-purpose interpreters
    (find/awk/bash -c/python -c), so an allowlist permissive enough to be
    useful is no real bar. Instead:
       - a short DENYLIST of catastrophic-and-rarely-needed operations,
       - append-only logging of every command (client UID cannot rewrite it),
       - anomaly alerting on a configurable set of sensitive verbs.

THREAT-MODEL HONESTY (keep this in mind before relying on it):
  * The pidfd + ancestry gate resists a "wandering foothold": an attacker who
    lands on the host via some other path and goes looking for a way to
    escalate cannot trivially talk to the broker, because an unrelated process
    is not in the authorized tree. This is the property the gate is FOR.
  * Correspondingly, anything the registered client spawns IS authorized, for
    as long as it stays in the tree. The gate answers "who is asking", never
    "what are they asking for".
  * It does NOT, by itself, resist CLIENT COMPROMISE: if the authorized process
    is subverted (a malicious input, a poisoned dependency), the malicious code
    runs AS the authorized client, and the pidfd gate cannot tell the
    difference. There, the denylist and the logs are the controls that bite.
  * A string denylist can be defeated by an attacker who can shape arbitrary
    argv (e.g. `bash -c '<obfuscated>'`). The denylist targets realistic,
    unsophisticated misuse ("add an SSH key", "create a user", "curl x | sh"),
    not a determined human. Logging is what makes the rest reviewable.
  * This is NOT a substitute for isolation. For high-value hosts, run the whole
    setup inside a VM or a snapshottable environment.
"""

import os
import sys
import socket
import struct
import json
import signal
import subprocess
import threading
import time
import re
import ctypes
import ctypes.util

# ----------------------------- configuration ------------------------------- #

SOCK_PATH   = os.environ.get("AGENTDO_SOCK",  "/run/agentdo.sock")
REG_PATH    = os.environ.get("AGENTDO_REG",   "/run/agentdo-reg.sock")
LOG_PATH    = os.environ.get("AGENTDO_LOG",   "/var/log/agentdo.log")
DENY_PATH   = os.environ.get("AGENTDO_DENY",  "/etc/agentdo/denylist.json")

# The UID the client runs as. The broker only accepts a registration and
# commands from THIS uid. Set via env at launch; defaults to SUDO_UID if the
# broker was started through sudo.
CLIENT_UID  = int(os.environ.get("AGENTDO_CLIENT_UID",
                                 os.environ.get("SUDO_UID", "-1")))

MAX_MSG     = 4 * 1024 * 1024  # 4 MiB cap on a single request payload

# Wire-protocol version. Bump this whenever the request/reply shape changes.
# The client sends the version it speaks; a mismatch is refused with a clear
# message instead of silently misbehaving. A stale broker left running after an
# upgrade previously swallowed all command output and exited 0 -- the worst
# possible failure mode, and exactly what this check exists to prevent.
PROTOCOL_VERSION = 2

# ------------------------- pidfd / syscall plumbing ------------------------ #

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def pidfd_open(pid: int) -> int:
    # glibc exposes pidfd_open since 2.36; fall back to raw syscall otherwise.
    if hasattr(os, "pidfd_open"):
        return os.pidfd_open(pid)
    NR = 434  # __NR_pidfd_open on x86_64/arm64
    fd = _libc.syscall(NR, pid)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "pidfd_open failed")
    return fd

def pidfd_alive(pidfd: int) -> bool:
    """True iff the process referred to by pidfd is still alive.

    A pidfd becomes readable exactly when its process dies. If it's readable,
    the process is gone (or a zombie past exit)."""
    import select
    r, _, _ = select.select([pidfd], [], [], 0)
    return not r  # readable => exited => not alive

# ------------------------------ shared state ------------------------------- #

class Client:
    """One registered client: the root of an authorized process tree."""

    __slots__ = ("pid", "pidfd", "start")

    def __init__(self, pid, pidfd, start):
        self.pid = pid
        self.pidfd = pidfd
        self.start = start      # /proc/<pid>/stat field 22, anti-recycle backup


class State:
    """Every currently-authorized client, keyed by PID.

    MULTIPLE clients are authorized at once, deliberately. You may `agentrun`
    as many processes as you like -- several agents, several terminals -- and
    each gets its own independently-scoped authorization. An earlier version
    kept a single slot here, so launching a second client silently revoked the
    first one mid-task; see _watch_exit for the other half of that bug.

    Keying by PID is safe because a live registration pins its PID: the kernel
    cannot recycle a number while its process is alive, and a dead client is
    reaped from the registry (dropping its key) before that number is free to
    reuse. `start` is still checked per request as defence in depth.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.clients = {}        # pid -> Client

    def add(self, client):
        """Register a client, replacing any stale entry under the same PID."""
        with self.lock:
            old = self.clients.get(client.pid)
            self.clients[client.pid] = client
        # Close the superseded pidfd outside the lock; it refers to a process
        # that already exited (see the keying note above), so its watcher is
        # already on its way out.
        if old is not None and old.pidfd != client.pidfd:
            try:
                os.close(old.pidfd)
            except OSError:
                pass

    def remove(self, pid, pidfd):
        """Drop a client. Returns the number of clients still registered.

        The pidfd is matched as well as the PID so a watcher for a superseded
        registration cannot evict the live one that replaced it.
        """
        with self.lock:
            cur = self.clients.get(pid)
            if cur is not None and cur.pidfd == pidfd:
                del self.clients[pid]
            return len(self.clients)

    def snapshot(self):
        with self.lock:
            return list(self.clients.values())

    def adopt(self, client):
        """Take on a client inherited from a predecessor broker.

        Unlike add(), this never displaces a live entry: a client registered
        directly with THIS broker is more current than anything the outgoing
        one knew about, so the incoming copy is dropped instead. Returns True
        if adopted, False if a live entry already covered that PID.
        """
        with self.lock:
            if client.pid in self.clients:
                return False
            self.clients[client.pid] = client
            return True


state = State()

# -------------------------------- logging ---------------------------------- #

def _open_append_only(path):
    """Open the log append-only so history cannot be silently truncated by the
    client's own UID."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)

_log_fd = None
_log_lock = threading.Lock()

def log_event(kind, **fields):
    global _log_fd
    rec = {"ts": time.time(), "kind": kind, **fields}
    line = (json.dumps(rec, ensure_ascii=False) + "\n").encode()
    with _log_lock:
        if _log_fd is None:
            _log_fd = _open_append_only(LOG_PATH)
        os.write(_log_fd, line)
        os.fsync(_log_fd)

# ------------------------------- denylist ---------------------------------- #

DEFAULT_DENY = {
    # Each rule matches against the fully-joined argv string, case-sensitive.
    # These are operations that are both dangerous and rarely legitimately
    # needed by a read/inspect-oriented workload. Tune to taste.
    "patterns": [
        r"\brm\b.*\s-[a-z]*r[a-z]*f\b.*\s/(?:\s|$)",  # rm -rf / (root)
        r"\bmkfs\b",                                   # formatting a filesystem
        r"\bdd\b.*\bof=/dev/(?:sd|nvme|vd|xvd)",       # dd onto a block device
        r">\s*/etc/sudoers",                           # rewriting sudoers
        r"\btee\b.*/etc/sudoers",
        r"\buseradd\b|\badduser\b",                    # creating accounts
        r"\buserdel\b|\bdeluser\b",
        r"\bpasswd\b\s+\w",                            # setting a user's password
        r"\bchpasswd\b",
        r"\bvisudo\b",
        r">\s*/root/\.ssh/authorized_keys",            # planting an SSH key
        r"\btee\b.*/\.ssh/authorized_keys",
        r"\bufw\b\s+disable|\bsystemctl\b\s+(?:stop|disable)\s+(?:ufw|firewalld|nftables|iptables)",
        r"\bsetenforce\b\s+0",                         # disabling SELinux
        r"\biptables\b\s+-F\b",                        # flushing firewall rules
        r"\bcurl\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",  # curl | sh
        r"\bwget\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",  # wget | sh
    ],
    # Verbs that are allowed but ALERTED on -- not blocking, just tripwires.
    "alert_patterns": [
        r"\bchown\b", r"\bchmod\b\s+[0-7]*7[0-7]{2}",
        r"\bsystemctl\b\s+(?:start|enable)\b",
        r"\bcrontab\b", r"\bat\b\s", r"\bnc\b\s|\bncat\b\s",
        r"\bchattr\b", r"\bmount\b", r"\bumount\b",
    ],
}

_deny_cache = {"mtime": None, "compiled": None, "alert": None}

def load_denylist():
    """Load and compile the denylist, reloading if the file changed on disk.
    Falls back to DEFAULT_DENY if the file is absent or malformed."""
    data = DEFAULT_DENY
    try:
        st = os.stat(DENY_PATH)
        if _deny_cache["mtime"] == st.st_mtime and _deny_cache["compiled"]:
            return _deny_cache["compiled"], _deny_cache["alert"]
        with open(DENY_PATH) as f:
            loaded = json.load(f)
        data = {
            "patterns": loaded.get("patterns", DEFAULT_DENY["patterns"]),
            "alert_patterns": loaded.get("alert_patterns", DEFAULT_DENY["alert_patterns"]),
        }
        mtime = st.st_mtime
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        mtime = None

    compiled = [re.compile(p) for p in data["patterns"]]
    alert    = [re.compile(p) for p in data["alert_patterns"]]
    _deny_cache.update(mtime=mtime, compiled=compiled, alert=alert)
    return compiled, alert

def evaluate(argv):
    """Return (decision, matched_pattern, alert_hits).
    decision in {'allow','deny'}."""
    joined = " ".join(argv)
    deny, alert = load_denylist()
    for rx in deny:
        if rx.search(joined):
            return "deny", rx.pattern, []
    hits = [rx.pattern for rx in alert if rx.search(joined)]
    return "allow", None, hits

# ------------------------------- handoff ----------------------------------- #
#
# Upgrading used to sever privilege for every running client: the installer
# killed the broker, and a client can only be registered at launch (agentrun
# registers it in the exec handoff), so an already-running agent could never
# get authorization back. It kept running, but every agentdo call failed.
#
# A successor broker therefore ADOPTS the registry from its predecessor. The
# only sound way to move an authorization is to pass the live pidfd itself over
# SCM_RIGHTS: a pidfd is a kernel handle to one exact process instance, and it
# survives the transfer intact (the receiving broker can waitid on it and see
# liveness, even after the sender closes its copy).
#
# What must NEVER happen here is re-deriving a pidfd from a serialized PID
# number. That reintroduces exactly the recycled-PID attack the pidfd design
# exists to prevent: between the old broker recording the number and the new
# one re-opening it, the process can exit and an attacker can occupy the PID.
# The start-time check narrows that window but does not close it, because the
# attacker chooses when to fork. So PIDs on this wire are metadata only -- they
# are cross-checked against the fd, never used to obtain authorization.
#
# The socket is root-only (0600 + peer-cred check), like the registration
# socket: anything that can talk to it receives live authorizations.

HANDOFF_PATH = os.environ.get("AGENTDO_HANDOFF", "/run/agentdo-handoff.sock")

# The predecessor stops serving once it has handed over. Set when a successor
# has taken the registry, so the outgoing broker fails closed rather than
# racing its replacement.
_handed_over = threading.Event()

# Set while a handoff is in flight: from the moment the registry is snapshotted
# for transfer until the handoff either completes or is abandoned.
#
# A client registering inside that window would be stranded: the successor was
# told about the clients in the snapshot and no others, so a late arrival stays
# only in the outgoing broker's registry and vanishes when it retires. The
# window is short (a few tens of milliseconds), and the client would fail
# closed rather than gain anything -- but it would fail *silently*, mid-launch.
# Refusing to register during the window instead makes agentrun abort with a
# clear message before it execs the client, which is recoverable: you just run
# it again a moment later.
_handoff_in_flight = threading.Event()

# Listening sockets, so a broker can be stopped without exiting the process.
# Production never needs this (a retiring broker calls os._exit), but the test
# suite runs successive brokers in ONE process and must be able to stop the
# accept loops of one it has retired.
_listeners = []

# The peer UID permitted to request a handoff. Root, always, in production: a
# handoff hands out live authorizations. The test suite runs unprivileged and
# relaxes this to its own UID, the same concession the registration socket
# already makes (see tests/harness.py).
HANDOFF_PEER_UID = 0

# The peer UID permitted to register a client. Root, always, in production:
# registration grants an authorization. Same test-suite concession as
# HANDOFF_PEER_UID -- relaxed only by tests/harness.py, never in production.
REG_PEER_UID = 0

# How long each side waits on the other during a handoff. Generous: a transfer
# is a handful of small messages, so reaching this means the peer is wedged or
# gone, and the safe response is to abandon the handoff rather than wait.
HANDOFF_TIMEOUT = 30.0

def handoff_server():
    """Serve the registry to a successor broker, then retire.

    One shot: after a successful transfer this broker stops accepting commands
    and exits. Two brokers must never serve the same socket concurrently --
    they would have overlapping registries and racing _watch_exit threads.
    """
    _unlink_quiet(HANDOFF_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(HANDOFF_PATH)
    _listeners.append(srv)
    os.chmod(HANDOFF_PATH, 0o600)  # only root may ask for the registry
    try:
        srv.listen(2)
    except OSError:
        return  # stopped before we finished setting up
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return  # socket closed by stop_listening(); this broker is done
        try:
            _pid, uid, _gid = peer_creds(conn)
            if uid != HANDOFF_PEER_UID:
                _send(conn, {"ok": False, "err": "handoff requires root"})
                continue
            _serve_handoff(conn)
        except Exception as e:
            try: _send(conn, {"ok": False, "err": str(e)})
            except OSError: pass
        finally:
            _close_gracefully(conn)

def _serve_handoff(conn):
    """Send every live client's pidfd to the successor, then retire.

    Registration is blocked for the duration: a client that registered after
    the snapshot below would not be in the transfer, and would be lost when
    this broker retires. See _handoff_in_flight.
    """
    _handoff_in_flight.set()
    try:
        _do_handoff(conn)
    finally:
        # Cleared on every path, including an abandoned handoff: if we did not
        # retire, we are still serving and must accept registrations again.
        _handoff_in_flight.clear()

def _do_handoff(conn):
    clients = [c for c in state.snapshot()
               if c.pidfd is not None and pidfd_alive(c.pidfd)]

    # Sent as one message per client so each pidfd rides with the metadata
    # describing it: a batched transfer would leave the receiver matching fds
    # to records positionally, with no way to detect a mismatch.
    _send(conn, {"ok": True, "count": len(clients),
                 "version": PROTOCOL_VERSION})
    for c in clients:
        socket.send_fds(
            conn, [(json.dumps({"pid": c.pid, "start": c.start}) + "\n").encode()],
            [c.pidfd])

    # Only retire once the successor confirms it has them all. If confirmation
    # never arrives, this broker keeps serving -- a failed handoff must leave
    # the clients with a working broker, not with neither.
    conn.settimeout(HANDOFF_TIMEOUT)
    try:
        reply = json.loads(_read_line_unbuffered(conn) or b"{}")
    except (OSError, socket.timeout, json.JSONDecodeError):
        log_event("handoff_failed", reason="no confirmation from successor")
        return
    finally:
        conn.settimeout(None)

    if not reply.get("ok"):
        log_event("handoff_failed", reason=reply.get("err", "successor refused"))
        return

    adopted = reply.get("adopted")
    log_event("handoff_out", clients=len(clients), adopted=adopted)
    _handed_over.set()
    # The successor owns the sockets now; drop ours without unlinking the
    # paths it has already bound, then exit. Routed through _retire so the
    # tests, which run both brokers in one process, can stop at the state
    # change instead of taking the whole test runner down with os._exit.
    _retire()

def _retire():
    """Exit a broker that has handed its registry to a successor."""
    os._exit(0)

def stop_listening():
    """Close this broker's listening sockets, ending its accept loops.

    Not used in production, where a broker stops by exiting the process. The
    test suite runs successive brokers in one process and needs a retired one
    to actually stop accepting, rather than lingering and competing with its
    successor for connections.
    """
    for srv in _listeners:
        # shutdown() before close(): a thread already blocked inside accept()
        # is not woken by closing the descriptor alone on Linux, so it would
        # sit there forever holding the port. shutdown() forces accept() to
        # return and the loop to see the error and exit.
        try:
            srv.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            srv.close()
        except OSError:
            pass
    _listeners.clear()

def adopt_from_predecessor(path=None):
    """Take the registry from a running broker, if there is one.

    Returns the number of clients adopted. Absent or unresponsive predecessor
    is not an error: the successor simply starts empty, which is the old
    behaviour.

    `path` names the predecessor's handoff socket, defaulting to our own --
    correct in production, where the predecessor exits and frees the path
    before we bind it. The tests run both brokers in one process and pass the
    predecessor's own path explicitly.
    """
    path = path or HANDOFF_PATH
    if not os.path.exists(path):
        return 0
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(HANDOFF_TIMEOUT)
    try:
        s.connect(path)
    except (FileNotFoundError, ConnectionRefusedError, PermissionError, OSError):
        return 0  # stale socket from a dead broker, or none listening
    try:
        return _receive_handoff(s)
    except (OSError, socket.timeout, json.JSONDecodeError, ValueError) as e:
        log_event("handoff_in_failed", err=str(e))
        return 0
    finally:
        s.close()

def _read_line_unbuffered(s):
    """Read one newline-terminated message a byte at a time.

    Deliberately not makefile().readline(): a buffered reader reads AHEAD, and
    on a socket carrying SCM_RIGHTS that swallows the next message's bytes into
    the buffer while its descriptors are dropped on the floor. Ancillary data
    can only be collected by the recvmsg that reads its own payload, so every
    read on this socket must consume exactly its own message and no more.
    """
    buf = bytearray()
    while not buf.endswith(b"\n"):
        b = s.recv(1)
        if not b:
            break
        buf += b
    return bytes(buf)

def _receive_handoff(s):
    header = json.loads(_read_line_unbuffered(s) or b"{}")
    if not header.get("ok"):
        log_event("handoff_in_failed", err=header.get("err", "predecessor refused"))
        return 0
    if header.get("version") != PROTOCOL_VERSION:
        # Registry shape could differ across versions; refusing leaves the
        # predecessor serving rather than adopting something misunderstood.
        log_event("handoff_in_failed",
                  err=f"version {header.get('version')} != {PROTOCOL_VERSION}")
        return 0

    adopted = 0
    for _ in range(int(header.get("count", 0))):
        msg, fds, _flags, _addr = socket.recv_fds(s, 65536, 1)
        if not msg or not fds:
            _close_fds(fds)
            break
        fd = fds[0]
        try:
            rec = json.loads(msg)
            pid, start = int(rec["pid"]), rec["start"]
        except (json.JSONDecodeError, KeyError, ValueError):
            _close_fds([fd])
            continue

        # The fd is the authorization; the PID is only a label for it. Confirm
        # they still describe the same live process before trusting the pair,
        # so a mislabelled record cannot authorize the wrong tree.
        if not pidfd_alive(fd) or _read_starttime(pid) != start:
            log_event("handoff_dropped", client_pid=pid, reason="stale or mismatched")
            _close_fds([fd])
            continue

        if state.adopt(Client(pid, fd, start)):
            threading.Thread(target=_watch_exit, args=(fd, pid),
                             daemon=True).start()
            adopted += 1
        else:
            _close_fds([fd])

    _send(s, {"ok": True, "adopted": adopted})
    log_event("handoff_in", adopted=adopted)
    return adopted

# ---------------------------- registration --------------------------------- #

def peer_creds(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                            struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    return pid, uid, gid

def registration_server():
    """A separate socket, mode 0600 root-only, on which the launcher (running
    as root, briefly) registers the client's pid. We capture a pidfd for that
    pid immediately, so authorization is bound to that exact process instance
    for its whole life."""
    _unlink_quiet(REG_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(REG_PATH)
    _listeners.append(srv)
    os.chmod(REG_PATH, 0o600)  # only root may register
    try:
        srv.listen(4)
    except OSError:
        return  # stopped before we finished setting up
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return  # socket closed by stop_listening(); this broker is done
        try:
            pid, uid, gid = peer_creds(conn)
            if uid != REG_PEER_UID:
                conn.sendall(b'{"ok":false,"err":"registration requires root"}')
                conn.close()
                continue
            # Refuse rather than strand: a registration accepted while a
            # handoff is in flight would not reach the successor, and would
            # disappear when this broker retires. agentrun reports this and
            # exits without starting the client, so retrying works.
            if _handoff_in_flight.is_set() or _handed_over.is_set():
                log_event("register_refused", reason="handoff in progress")
                conn.sendall(b'{"ok":false,"err":"broker is handing over to a '
                             b'new version; retry in a moment"}')
                continue
            msg = json.loads(conn.recv(65536))
            client_pid = int(msg["pid"])
            fd = pidfd_open(client_pid)
            start = _read_starttime(client_pid)
            # ADDITIVE: registering a second client does not disturb the first.
            state.add(Client(client_pid, fd, start))
            log_event("register", client_pid=client_pid, client_uid=CLIENT_UID,
                      clients=len(state.snapshot()))
            threading.Thread(target=_watch_exit, args=(fd, client_pid),
                             daemon=True).start()
            conn.sendall(b'{"ok":true}')
        except Exception as e:
            try: conn.sendall(json.dumps({"ok": False, "err": str(e)}).encode())
            except OSError: pass
        finally:
            conn.close()

def _watch_exit(pidfd, pid):
    """Block until this authorized process exits, then revoke ITS authorization.

    Revocation is per-client: one client exiting must not disturb the others.
    An earlier version shut the whole broker down here, so the first `agentrun`
    to finish tore down privilege for every other one still working.

    The broker exits only when the LAST client is gone, which keeps the
    original guarantee -- privilege never outlives the processes it was granted
    to -- while allowing any number of them to coexist.
    """
    try:
        os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
    except (ChildProcessError, OSError):
        import select
        select.select([pidfd], [], [])
    remaining = state.remove(pid, pidfd)
    try:
        os.close(pidfd)
    except OSError:
        pass
    # A broker that handed its registry to a successor must stay silent here:
    # the clients it was watching now belong to the successor, which runs its
    # own watchers for them. Without this check the retired broker would log a
    # revocation it no longer owns and, on the last one, call _shutdown() --
    # tearing down a process whose sockets its successor has already taken.
    if _handed_over.is_set():
        return
    log_event("revoke", reason="client_exited", client_pid=pid,
              clients=remaining)
    if remaining == 0:
        _shutdown()

# ---------------------------- command serving ------------------------------ #

def command_server():
    _unlink_quiet(SOCK_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    _listeners.append(srv)
    # Only the client's uid (and root) can even open the socket. This is the
    # first gate; the peer-cred + pidfd checks below are the real ones.
    os.chmod(SOCK_PATH, 0o660)
    if CLIENT_UID >= 0:
        try:
            os.chown(SOCK_PATH, 0, CLIENT_UID)
        except OSError:
            pass
    try:
        srv.listen(16)
    except OSError:
        return  # stopped before we finished setting up
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return  # socket closed by stop_listening(); this broker is done
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

def _authorized_caller(conn):
    """The core gate. Returns (ok, pid, reason).

    A caller is authorized if it belongs to ANY registered client's tree. The
    trees are independent: each `agentrun` contributes one, and a caller needs
    to match exactly one of them. Being outside all of them is the only
    rejection -- there is no cap on how many may be registered at once.
    """
    pid, uid, gid = peer_creds(conn)
    # A broker that has handed its registry to a successor must not also serve
    # commands: the successor now owns these authorizations, and two brokers
    # acting on one registry would race each other.
    if _handed_over.is_set():
        return False, pid, "broker has retired; its successor now serves this socket"
    clients = state.snapshot()
    if not clients:
        return False, pid, "no authorized client registered"
    if uid != CLIENT_UID:
        return False, pid, f"uid {uid} != client uid {CLIENT_UID}"
    for c in clients:
        # Liveness of the registered root is checked BEFORE ancestry: if the
        # root is gone the tree is void, whatever /proc still shows mid-teardown.
        if c.pidfd is not None and not pidfd_alive(c.pidfd):
            continue
        # The caller is a registered process itself, or something below it in
        # the process tree. The tree -- not a single PID -- is the unit of
        # authorization, because the shim runs as a CHILD of the registered
        # client, never as the client's own PID. _is_descendant_of re-checks
        # the root's start-time, so a recycled PID cannot inherit authorization.
        if _is_descendant_of(pid, c.pid, c.start):
            return True, pid, None
    roots = ", ".join(str(c.pid) for c in clients)
    return False, pid, (f"pid {pid} is not within any authorized client tree "
                        f"(roots: {roots})")

def handle_client(conn):
    try:
        ok, pid, reason = _authorized_caller(conn)
        if not ok:
            log_event("reject", pid=pid, reason=reason)
            # Drain first: replying while the request still sits unread makes
            # close() send an RST, which discards this very message and leaves
            # the client with ECONNRESET instead of the reason.
            _drain(conn)
            _send(conn, {"ok": False, "err": f"not authorized: {reason}"})
            return

        raw, fds = _recv_request(conn)
        if raw is None:
            _drain(conn)
            _send(conn, {"ok": False, "err": "oversized or malformed request"})
            return
        req = json.loads(raw)

        client_ver = req.get("version")
        if client_ver != PROTOCOL_VERSION:
            log_event("version_mismatch", pid=pid, client=client_ver,
                      broker=PROTOCOL_VERSION)
            _close_fds(fds)
            _send(conn, {"ok": False, "err":
                         f"protocol mismatch: client speaks v{client_ver}, "
                         f"broker speaks v{PROTOCOL_VERSION}. "
                         f"Restart the broker so it picks up the installed version."})
            return

        argv = req.get("argv")
        if not isinstance(argv, list) or not argv or \
           not all(isinstance(a, str) for a in argv):
            _close_fds(fds)
            _send(conn, {"ok": False, "err": "argv must be a non-empty list of strings"})
            return

        # Evaluated BEFORE the descriptors are attached to anything: a denied
        # command must never get hold of the caller's stdin/stdout/stderr.
        decision, matched, alerts = evaluate(argv)
        if decision == "deny":
            log_event("deny", pid=pid, argv=argv, matched=matched)
            _close_fds(fds)
            _send(conn, {"ok": False, "denied": True,
                         "err": f"blocked by denylist rule: {matched}"})
            return

        if alerts:
            log_event("alert", pid=pid, argv=argv, alerts=alerts)

        if len(fds) != 3:
            _close_fds(fds)
            _send(conn, {"ok": False,
                         "err": f"expected 3 file descriptors, got {len(fds)}"})
            return

        log_event("exec", pid=pid, argv=argv)
        cwd = req.get("cwd") or None
        env = None
        if isinstance(req.get("env"), dict):
            env = {str(k): str(v) for k, v in req["env"].items()}

        # The command inherits the CALLER's own stdin/stdout/stderr, so its I/O
        # streams live to the caller's terminal or pipes and never passes
        # through this process. No capture, no decode, no size cap -- and stdin
        # works, which it cannot when output is buffered and returned as JSON.
        try:
            proc = _run_and_report_pid(conn, argv, fds, cwd, env)
            # subprocess reports a signal death as a NEGATIVE returncode
            # (-13 for SIGPIPE). Shells report 128+signal, and an exit status
            # is only 8 bits, so passing -13 through would surface as 243.
            # Normalise here, where the sign is still meaningful.
            code = (128 - proc.returncode) if proc.returncode < 0 else proc.returncode
        except FileNotFoundError:
            _send(conn, {"ok": False, "err": f"command not found: {argv[0]}"})
            return
        except Exception as e:
            _send(conn, {"ok": False, "err": f"exec failed: {e}"})
            return
        finally:
            # Always release our copies; the caller holds its own originals.
            _close_fds(fds)

        log_event("done", pid=pid, argv0=argv[0], code=code)
        _send(conn, {"ok": True, "code": code})
    except Exception as e:
        try: _send(conn, {"ok": False, "err": f"broker error: {e}"})
        except OSError: pass
    finally:
        _close_gracefully(conn)

# ------------------------------- helpers ----------------------------------- #

# The request is one datagram-shaped message carrying the JSON plus exactly
# three SCM_RIGHTS descriptors (stdin, stdout, stderr). It is small and fixed in
# shape, so it arrives in a single recv rather than being streamed to EOF: the
# ancillary data rides with the first message and cannot be reassembled across
# reads.
MAX_REQUEST = 1 << 20  # 1 MiB is far beyond any argv/env; refuse anything larger
EXPECTED_FDS = 3

def _recv_request(conn):
    """Return (payload_bytes, [fds]) or (None, []) if malformed/oversized.

    Any descriptors received alongside a payload we then reject are closed by
    the caller via _close_fds -- a leaked fd here would be a root-held handle on
    the caller's terminal.
    """
    try:
        msg, fds, _flags, _addr = socket.recv_fds(conn, MAX_REQUEST, EXPECTED_FDS)
    except OSError:
        return None, []
    if not msg or len(msg) >= MAX_REQUEST:
        _close_fds(fds)
        return None, []
    return msg, list(fds)

# Signals the client is permitted to forward to a running command. Restricted
# deliberately: the client may relay terminal-driven signals to the child it
# asked for, but this is not a general "signal any process as root" primitive.
FORWARDABLE_SIGNALS = {
    signal.SIGINT, signal.SIGTERM, signal.SIGQUIT,
    signal.SIGHUP, signal.SIGWINCH, signal.SIGTSTP, signal.SIGCONT,
}

def _run_and_report_pid(conn, argv, fds, cwd, env):
    """Start the command, tell the client its PID, then relay signals to it.

    The client sits between the terminal and the command, so terminal-generated
    signals (Ctrl-C, window resize) are delivered to the CLIENT, not to the
    command. Without relaying, Ctrl-C killed the shim and orphaned an
    interactive program holding the terminal, and SIGWINCH never reached it so
    resizes only took effect on the next redraw.

    The client learns the child's PID from the "started" line below and sends
    {"signal": N} lines while the command runs; each is forwarded to the child's
    process group.
    """
    proc = subprocess.Popen(argv, stdin=fds[0], stdout=fds[1], stderr=fds[2],
                            cwd=cwd, env=env, start_new_session=True)
    try:
        _send(conn, {"ok": True, "started": True, "pid": proc.pid})
    except OSError:
        proc.kill()
        raise

    stop = threading.Event()

    def relay():
        """Read {"signal": N} lines from the client until the command ends."""
        f = conn.makefile("rb")
        while not stop.is_set():
            line = f.readline()
            if not line:
                break
            try:
                sig = int(json.loads(line).get("signal", 0))
            except (ValueError, json.JSONDecodeError, AttributeError):
                continue
            if sig in (s.value for s in FORWARDABLE_SIGNALS):
                try:
                    # Signal the whole group: start_new_session put the command
                    # in its own, so this cannot reach anything else.
                    os.killpg(proc.pid, sig)
                except (ProcessLookupError, PermissionError):
                    break

    t = threading.Thread(target=relay, daemon=True)
    t.start()
    proc.wait()
    stop.set()
    return proc

def _close_fds(fds):
    """Close our copies of received descriptors. Safe to call more than once
    only if the list is cleared; callers pass each list exactly once."""
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass

def _send(conn, obj):
    """Send one newline-delimited JSON object.

    The reply stream may carry more than one message (a "started" line, then
    the final result), so each is newline-framed and the client reads by line.
    """
    conn.sendall((json.dumps(obj) + "\n").encode())

def _drain(conn, limit=MAX_MSG):
    """Consume any unread request bytes, discarding them.

    Closing a socket that still has unread data in its receive queue makes the
    kernel send an RST, which throws away anything already written back. Every
    early-return path must drain first or its error message never arrives.
    """
    conn.settimeout(2.0)
    total = 0
    try:
        while total < limit:
            b = conn.recv(65536)
            if not b:
                break
            total += len(b)
    except (OSError, socket.timeout):
        pass
    finally:
        conn.settimeout(None)

def _close_gracefully(conn):
    """Half-close, let the peer read the reply, then close.

    SHUT_WR sends EOF so the client's read loop ends on its own terms; the
    short drain that follows absorbs any late bytes so close() stays orderly.
    """
    try:
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    _drain(conn, limit=65536)
    try:
        conn.close()
    except OSError:
        pass

def _read_stat(pid):
    """Return (ppid, starttime) from /proc/<pid>/stat, or (None, None).

    Both come from a single read so they describe the same instant: reading
    them separately could straddle the target exiting and its PID being reused.
    Fields are taken after the last ')' because the comm field is parenthesized
    and may itself contain spaces or parens.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
        rparen = data.rfind(b")")
        fields = data[rparen + 2:].split()
        # After the split, index 0 is field 3 (state); so field N is index N-3.
        return int(fields[1]), int(fields[19])  # ppid (4), starttime (22)
    except (FileNotFoundError, IndexError, ValueError, OSError):
        return None, None

def _read_starttime(pid):
    """Field 22 of /proc/<pid>/stat: process start time in clock ticks.
    Unique-enough per process instance to defeat PID reuse."""
    return _read_stat(pid)[1]

# Hard ceiling on the ancestry walk. A real chain is a few dozen deep at most;
# this bounds the loop even if /proc were somehow inconsistent mid-walk.
MAX_ANCESTRY_DEPTH = 256

def _is_descendant_of(pid, ancestor_pid, ancestor_start):
    """True iff `pid` is `ancestor_pid` or lies below it in the process tree.

    Walks parent links upward. The walk terminates on:
      * reaching ancestor_pid  -> authorized, but only if its start-time still
        matches, so a recycled PID at the top cannot be inherited;
      * reaching PID 1 or 0    -> escaped the tree;
      * an unreadable PID      -> cannot attribute it, so refuse;
      * the depth ceiling      -> refuse.

    Note a process that deliberately orphans itself (double-fork) reparents to
    init or to a subreaper such as `systemd --user`, leaving this tree. It then
    fails this check -- privilege is lost on escape, which is the safe
    direction.
    """
    seen = set()
    cur = pid
    for _ in range(MAX_ANCESTRY_DEPTH):
        if cur == ancestor_pid:
            # Confirm the ancestor is still the same process instance, not a
            # different one that reused the number.
            return _read_starttime(cur) == ancestor_start
        if cur <= 1 or cur in seen:
            return False
        seen.add(cur)
        ppid, _ = _read_stat(cur)
        if ppid is None:
            return False  # vanished or unreadable -> fail closed
        cur = ppid
    return False

def _unlink_quiet(path):
    try: os.unlink(path)
    except FileNotFoundError: pass

def _shutdown(*_):
    log_event("shutdown")
    # A retired broker must not unlink the socket paths: its successor has
    # already bound them, and removing them would strand every client with a
    # missing socket. The successor owns those paths now.
    if not _handed_over.is_set():
        _unlink_quiet(SOCK_PATH)
        _unlink_quiet(REG_PATH)
        _unlink_quiet(HANDOFF_PATH)
    os._exit(0)

# --------------------------------- main ------------------------------------ #

def main():
    if os.geteuid() != 0:
        sys.exit("agentdo-broker must run as root (it executes privileged commands).")
    if CLIENT_UID < 0:
        sys.exit("Set AGENTDO_CLIENT_UID to the client's numeric UID (see README).")

    os.makedirs(os.path.dirname(DENY_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log_event("start", client_uid=CLIENT_UID, sock=SOCK_PATH)

    # Adopt any running predecessor's clients BEFORE binding our own sockets:
    # the outgoing broker only retires once the transfer is confirmed, so it
    # keeps serving until we are ready to take over. A failed or absent handoff
    # just leaves us empty, which is the pre-handoff behaviour.
    adopted = adopt_from_predecessor()
    if adopted:
        log_event("adopted_clients", clients=adopted)

    threading.Thread(target=handoff_server, daemon=True).start()
    threading.Thread(target=registration_server, daemon=True).start()
    command_server()

if __name__ == "__main__":
    main()
