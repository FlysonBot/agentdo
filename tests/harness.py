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



def load_broker(sock_dir, deny_path=None):
    """Import agentdo-broker.py as a module with test paths in the environment.

    The module reads its configuration at import time, so the environment must
    be set before the import, and each test gets its own freshly-imported copy
    to avoid sharing broker state between tests.
    """
    os.environ.update(
        AGENTDO_SOCK=os.path.join(sock_dir, "s.sock"),
        AGENTDO_REG=os.path.join(sock_dir, "r.sock"),
        AGENTDO_LOG=os.path.join(sock_dir, "events.log"),
        AGENTDO_CLIENT_UID=str(os.getuid()),
        AGENTDO_DENY=deny_path or os.path.join(sock_dir, "no-such-denylist.json"),
    )
    name = "agentdo_broker_%s" % uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, BROKER_SRC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
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

        for target in (self.mod.registration_server, self.mod.command_server):
            threading.Thread(target=target, daemon=True).start()
        self._await_socket()

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

    def events(self):
        """Parsed append-only log records the broker has written so far."""
        path = os.path.join(self.dir, "events.log")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def close(self):
        for shell in ([self._shell] if self._shell else []) + self._extra:
            try:
                shell.close()
            except OSError:
                pass
        shutil.rmtree(self.dir, ignore_errors=True)
