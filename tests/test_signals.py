"""Signal relay and resource cleanup.

The client sits between the terminal and the command, so terminal-generated
signals arrive at the shim rather than at the program holding the terminal.
These tests pin down the relay that forwards them, and the fd hygiene that a
root process passing descriptors around has to get right.
"""

import os
import signal
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Broker


class SignalRelayTest(unittest.TestCase):
    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_sigint_terminates_the_command(self):
        """Ctrl-C used to kill the shim and leave the command running with the
        terminal, so an interactive program had to be quit by hand afterwards."""
        marker = "agentdo-test-sleep-%d" % os.getpid()
        out, _ = self.b.run_in_tree(
            "%s & CLIENT=$!; sleep 1.5; kill -INT $CLIENT; "
            "wait $CLIENT 2>/dev/null; echo rc=$?"
            % self.b.agentdo("bash -c 'exec -a %s sleep 60'" % marker))
        self.assertIn("rc=130", out, "SIGINT should surface as 128+2")

    def test_sigint_leaves_no_orphan(self):
        """The relayed signal must reach the command itself, not just the shim:
        a surviving process would hold the terminal after the client exits."""
        marker = "agentdo-orphan-probe-%d" % os.getpid()
        self.b.run_in_tree(
            "%s & CLIENT=$!; sleep 1.5; kill -INT $CLIENT; wait $CLIENT 2>/dev/null"
            % self.b.agentdo("bash -c 'exec -a %s sleep 60'" % marker))
        time.sleep(1.0)
        found = subprocess.run(["pgrep", "-f", marker],
                               capture_output=True, text=True).stdout.strip()
        if found:
            for pid in found.split():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
        self.assertEqual(found, "", "the command outlived the interrupted client")

    def test_signal_death_is_logged(self):
        self.b.run_in_tree(self.b.agentdo("bash -c 'kill -TERM $$'"))
        done = [e for e in self.b.events() if e["kind"] == "done"]
        self.assertTrue(done)
        self.assertEqual(done[-1]["code"], 143)

    def test_normal_commands_unaffected_by_relay(self):
        """Installing handlers must not disturb ordinary, uninterrupted runs."""
        out, code = self.b.run_in_tree(self.b.agentdo("echo undisturbed"))
        self.assertEqual(out, "undisturbed")
        self.assertEqual(code, 0)


class ResourceTest(unittest.TestCase):
    """The broker must not accumulate descriptors or threads."""

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def _open_fds(self):
        return len(os.listdir("/proc/self/fd"))

    def test_no_fd_leak_across_many_requests(self):
        """The broker holds root-owned copies of the caller's terminal; leaking
        them would accumulate open handles on user terminals."""
        for _ in range(3):                      # warm up
            self.b.run_in_tree(self.b.agentdo("true"))
        before = self._open_fds()
        for _ in range(25):
            self.b.run_in_tree(self.b.agentdo("true"))
        self.assertLessEqual(self._open_fds(), before + 2,
                             "descriptors accumulated across requests")

    def test_no_fd_leak_on_denied_requests(self):
        """A denied request still arrives carrying descriptors."""
        for _ in range(3):
            self.b.run_in_tree("%s 2>/dev/null" % self.b.agentdo("useradd bob"))
        before = self._open_fds()
        for _ in range(25):
            self.b.run_in_tree("%s 2>/dev/null" % self.b.agentdo("useradd bob"))
        self.assertLessEqual(self._open_fds(), before + 2,
                             "descriptors leaked on the denial path")

    def test_concurrent_commands_all_complete(self):
        out, _ = self.b.run_in_tree(
            "for i in 1 2 3 4 5; do %s & done; wait"
            % self.b.agentdo("bash -c 'sleep 0.2; echo done'"))
        self.assertEqual(out.count("done"), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
