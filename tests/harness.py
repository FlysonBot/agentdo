"""Shared test harness: an unprivileged broker plus an in-tree client runner.

The broker refuses to start as a non-root process, but that check lives in
main(); the servers themselves are importable and run fine as your own user, so
these tests exercise the real registration_server/command_server/handle_client
code rather than a reimplementation of it. Commands run as you, not as root,
which is exactly what makes the suite safe to run anywhere.

Two constraints shape everything here:

  * Socket paths must stay short. AF_UNIX caps a path at ~108 bytes and the
    failure is a confusing "path too long" from connect(), so the harness uses
    a short /tmp directory rather than the repo or a scratch tree.

  * Commands must run INSIDE the registered process tree. The gate authorizes a
    tree, so a client spawned from the test process itself is correctly refused.
    run_in_tree() sends shell commands to a registered helper shell and reads
    the results back, which is the only way to test the allowed path.
"""

import importlib.util
import itertools
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROKER_SRC = os.path.join(REPO, "agentdo-broker.py")
CLIENT = os.path.join(REPO, "bin", "agentdo")


_handoff_seq = itertools.count()


def load_broker(sock_dir, deny_path=None):
    """Import agentdo-broker.py as a module with test paths in the environment.

    The module reads its configuration at import time, so the environment must
    be set before the import, and each test gets its own freshly-imported copy
    to avoid sharing broker state between tests.

    Each instance gets its OWN handoff socket path. In production a successor
    reuses the path because the predecessor has exited and freed it, but these
    tests run both brokers in one process, where a retired broker's accept loop
    is still alive; sharing the path would make them contend for it. The
    successor is pointed at the predecessor's path explicitly instead.
    """
    os.environ.update(
        AGENTDO_SOCK=os.path.join(sock_dir, "s.sock"),
        AGENTDO_REG=os.path.join(sock_dir, "r.sock"),
        AGENTDO_LOG=os.path.join(sock_dir, "events.log"),
        AGENTDO_CLIENT_UID=str(os.getuid()),
        AGENTDO_DENY=deny_path or os.path.join(sock_dir, "no-such-denylist.json"),
        AGENTDO_HANDOFF=os.path.join(sock_dir, "h%d.sock" % next(_handoff_seq)),
    )
    name = "agentdo_broker_%s" % uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, BROKER_SRC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    # The handoff socket requires a root peer, like the registration socket.
    # These tests run as you, so accept this UID instead -- the same concession
    # register_pid makes by writing broker state directly. The gate itself is
    # unchanged; only who may ask for a handoff is relaxed, and only here.
    mod.HANDOFF_PEER_UID = os.getuid()
    mod.REG_PEER_UID = os.getuid()
    # The broker exits the process when its last client goes away -- correct
    # for a real daemon, fatal for a test runner that hosts many brokers and
    # kills their client shells in tearDown. Stop listening instead, which is
    # the observable part; tests that care about shutdown assert on state and
    # the event log rather than on the process dying.
    mod._shutdown = mod.stop_listening
    # Same for retirement after a handoff: a real broker exits the process,
    # which would take the test runner with it. Stopping its listeners is the
    # in-process equivalent, and _handed_over -- set before _retire is called
    # -- remains the flag tests assert on.
    mod._retire = mod.stop_listening
    return mod


class _Shell:
    """A helper shell that reads commands from a FIFO and echoes a sentinel.

    Used as the root of a registered process tree. The sentinel after each
    command is how run() knows where one command's output ends.
    """

    def __init__(self, dir_, sock, index):
        self.sock = sock
        fifo_in = os.path.join(dir_, "cmds%d" % index)
        fifo_out = os.path.join(dir_, "out%d" % index)
        os.mkfifo(fifo_in)
        os.mkfifo(fifo_out)
        self.proc = subprocess.Popen(
            ["bash", "-c",
             'while IFS= read -r line; do eval "$line"; echo "__DONE__$?"; done '
             '< %s > %s 2>&1' % (fifo_in, fifo_out)])
        self._w = open(fifo_in, "w")
        self._r = open(fifo_out, "r")

    @property
    def pid(self):
        return self.proc.pid

    def run(self, shell_cmd, timeout=30):
        """Run a shell snippet in this shell; return (output, exit_code)."""
        self._w.write("export AGENTDO_SOCK=%s; %s\n" % (self.sock, shell_cmd))
        self._w.flush()
        lines, deadline = [], time.time() + timeout
        while time.time() < deadline:
            line = self._r.readline()
            if not line:
                time.sleep(0.01)
                continue
            if line.startswith("__DONE__"):
                return "".join(lines).rstrip("\n"), int(line[8:].strip() or 0)
            lines.append(line)
        raise AssertionError("timed out running: %s" % shell_cmd)

    def close(self):
        for stream in (self._w, self._r):
            try:
                stream.close()
            except OSError:
                pass
        self.proc.kill()
        self.proc.wait(timeout=5)


class Broker:
    """A running broker plus a registered client shell to run commands in."""

    def __init__(self, deny_path=None):
        # Short path: AF_UNIX limit. mkdtemp under /tmp keeps it well under.
        self.dir = tempfile.mkdtemp(prefix="adt-", dir="/tmp")
        self.mod = load_broker(self.dir, deny_path)
        self.sock = os.path.join(self.dir, "s.sock")
        self._shell = None
        self._extra = []
        # Every broker module this instance has run, including retired
        # predecessors. close() must stop them ALL: self.mod moves on to the
        # successor after a handoff, and a predecessor left accepting would
        # still be serving during later tests in this same process.
        self._mods = [self.mod]

        for target in (self.mod.handoff_server, self.mod.registration_server,
                       self.mod.command_server):
            threading.Thread(target=target, daemon=True).start()
        self._await_socket()

    def start_successor(self):
        """Start a second broker in this directory, as an upgrade would.

        It adopts from this broker over the handoff socket, then binds the same
        socket paths -- the real upgrade sequence, minus the process boundary.
        Returns the successor's module; the predecessor is retired afterwards.
        """
        # load_broker already redirects _retire to stop_listening, so the
        # predecessor stops accepting instead of exiting this process.
        old = self.mod
        predecessor_handoff = old.HANDOFF_PATH
        mod = load_broker(self.dir)
        adopted = mod.adopt_from_predecessor(predecessor_handoff)
        old.stop_listening()    # in case the handoff bailed before retiring
        for target in (mod.handoff_server, mod.registration_server,
                       mod.command_server):
            threading.Thread(target=target, daemon=True).start()
        deadline = time.time() + 5.0
        while time.time() < deadline and not os.path.exists(self.sock):
            time.sleep(0.02)
        self.mod = mod          # later helpers should talk to the live broker
        self._mods.append(mod)
        return mod, adopted

    def _await_socket(self, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(self.sock):
                return
            time.sleep(0.02)
        raise RuntimeError("broker socket never appeared at %s" % self.sock)

    # -- registration ------------------------------------------------------ #

    def register_shell(self):
        """Start a helper shell and register it as the authorized client.

        Registration is done directly against broker state rather than through
        the registration socket, because that socket requires a root peer. The
        gate being tested reads this same state, so the tests still exercise
        the real authorization path.
        """
        self._shell = _Shell(self.dir, self.sock, 0)
        self.register_pid(self._shell.pid)
        return self._shell.pid

    def register_pid(self, pid):
        """Authorize `pid` (and its descendants) the way registration would.

        Additive, like the real registration socket: authorizing a second pid
        leaves the first one authorized.
        """
        fd = self.mod.pidfd_open(pid)
        self.mod.state.add(
            self.mod.Client(pid, fd, self.mod._read_starttime(pid)))

    def register_second_shell(self):
        """Start and register an ADDITIONAL client shell.

        Returns a Shell handle with its own run()/close(), so a test can drive
        two concurrently-registered clients and check they do not evict each
        other. The primary shell from register_shell() is unaffected.
        """
        shell = _Shell(self.dir, self.sock, len(self._extra) + 1)
        self._extra.append(shell)
        self.register_pid(shell.pid)
        return shell

    # -- running commands -------------------------------------------------- #

    def run_in_tree(self, shell_cmd, timeout=30):
        """Run a shell snippet inside the registered tree.

        Returns (output, exit_code) where exit_code is the snippet's status.
        AGENTDO_SOCK is exported so the client shim finds this test's broker.
        """
        if self._shell is None:
            raise RuntimeError("call register_shell() first")
        return self._shell.run(shell_cmd, timeout=timeout)

    def run_outside_tree(self, *argv, timeout=30):
        """Run the client from the TEST process, which is outside the tree."""
        env = dict(os.environ, AGENTDO_SOCK=self.sock)
        return subprocess.run([sys.executable, CLIENT, *argv], env=env,
                              capture_output=True, text=True, timeout=timeout)

    def agentdo(self, args):
        """Shell fragment invoking the client shim under test."""
        return "%s %s %s" % (sys.executable, CLIENT, args)

    # -- introspection ------------------------------------------------------ #

    def registered_pidfd(self, pid):
        """The pidfd the broker actually holds for `pid`.

        _watch_exit matches on the registered fd, not just the PID, so a test
        driving it must pass this rather than opening a fresh pidfd -- a new fd
        for the same process is a different fd and correctly will not match.
        """
        for c in self.mod.state.snapshot():
            if c.pid == pid:
                return c.pidfd
        raise RuntimeError("pid %d is not registered" % pid)

    def handoff_socket(self, timeout=5.0):
        """Connect to this broker's handoff socket as a raw client.

        Lets a test play the successor's side of the protocol by hand, which is
        the only way to reach the failure branches: a real successor always
        behaves correctly, so refusals and abandoned transfers need a peer that
        misbehaves on purpose.
        """
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(self.mod.HANDOFF_PATH)
        return s

    def events(self):
        """Parsed append-only log records the broker has written so far."""
        path = os.path.join(self.dir, "events.log")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def close(self):
        # Stop the accept loops first: these brokers share one process, so a
        # leaked listener would still be serving during later tests.
        for mod in self._mods:
            try:
                mod.stop_listening()
            except Exception:
                pass
        for shell in ([self._shell] if self._shell else []) + self._extra:
            try:
                shell.close()
            except OSError:
                pass
        shutil.rmtree(self.dir, ignore_errors=True)
