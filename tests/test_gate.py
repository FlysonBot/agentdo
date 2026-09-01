"""The authorization gate: who may run privileged commands.

This is the security-critical half of the suite. The gate authorizes a process
TREE -- the registered client and its descendants -- because the `agentdo` shim
always runs as a child of the registered process, never as that process itself.
An earlier single-PID gate rejected every real caller, so the descendant cases
below are regression tests for a design error, not just for a bug.
"""

import os
import signal
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CLIENT, Broker


class AncestryWalkTest(unittest.TestCase):
    """Unit tests for _is_descendant_of, independent of any socket."""

    @classmethod
    def setUpClass(cls):
        cls.b = Broker()
        cls.mod = cls.b.mod

    @classmethod
    def tearDownClass(cls):
        cls.b.close()

    def setUp(self):
        self.me = os.getpid()
        self.start = self.mod._read_starttime(self.me)

    def test_process_is_its_own_ancestor(self):
        self.assertTrue(self.mod._is_descendant_of(self.me, self.me, self.start))

    def test_direct_child_is_descendant(self):
        child = subprocess.Popen(["sleep", "10"])
        try:
            self.assertTrue(
                self.mod._is_descendant_of(child.pid, self.me, self.start))
        finally:
            child.kill()
            child.wait()

    def test_grandchild_is_descendant(self):
        # bash spawns sleep, so the sleep is two levels below this process.
        proc = subprocess.Popen(["bash", "-c", "sleep 10 & echo $!; wait"],
                                stdout=subprocess.PIPE, text=True)
        try:
            grandchild = int(proc.stdout.readline().strip())
            self.assertTrue(
                self.mod._is_descendant_of(grandchild, self.me, self.start))
        finally:
            proc.kill()
            proc.wait()

    def test_init_is_not_descendant(self):
        self.assertFalse(self.mod._is_descendant_of(1, self.me, self.start))

    def test_parent_is_not_descendant(self):
        self.assertFalse(
            self.mod._is_descendant_of(os.getppid(), self.me, self.start))

    def test_recycled_pid_rejected_via_start_time(self):
        """A matching PID with a different start-time must not be authorized."""
        self.assertFalse(
            self.mod._is_descendant_of(self.me, self.me, self.start + 1))

    def test_nonexistent_pid_rejected(self):
        self.assertFalse(self.mod._is_descendant_of(999999, self.me, self.start))

    def test_orphan_escapes_the_tree(self):
        """A double-forked process reparents away and LOSES authorization.

        This is the deliberate edge of the model: escaping the tree fails
        closed. Recorded as a test so the behaviour is not "fixed" by accident.
        """
        marker = os.path.join(self.b.dir, "orphan.pid")
        subprocess.run([sys.executable, "-c", (
            "import os,sys,time\n"
            "if os.fork() > 0: sys.exit(0)\n"
            "os.setsid()\n"
            "open(%r,'w').write(str(os.getpid()))\n"
            "time.sleep(5)\n" % marker)], timeout=10)
        deadline = time.time() + 5
        while time.time() < deadline and not os.path.exists(marker):
            time.sleep(0.05)
        with open(marker) as f:
            orphan = int(f.read().strip())
        try:
            self.assertFalse(
                self.mod._is_descendant_of(orphan, self.me, self.start),
                "an orphaned process must not remain authorized")
        finally:
            try:
                os.kill(orphan, signal.SIGKILL)
            except ProcessLookupError:
                pass


class GateOverSocketTest(unittest.TestCase):
    """End-to-end authorization through the real client and broker."""

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_in_tree_command_is_allowed(self):
        out, code = self.b.run_in_tree(self.b.agentdo("echo allowed"))
        self.assertEqual(out, "allowed")
        self.assertEqual(code, 0)

    def test_grandchild_in_tree_is_allowed(self):
        out, code = self.b.run_in_tree(
            "bash -c '%s'" % self.b.agentdo("echo nested"))
        self.assertEqual(out, "nested")
        self.assertEqual(code, 0)

    def test_outsider_is_refused(self):
        r = self.b.run_outside_tree("echo", "malware")
        self.assertEqual(r.returncode, 127)
        self.assertIn("not authorized", r.stderr)
        self.assertEqual(r.stdout, "", "a refused command must produce no output")

    def test_detached_outsider_is_refused(self):
        env = dict(os.environ, AGENTDO_SOCK=self.b.sock)
        r = subprocess.run(["setsid", sys.executable, CLIENT, "echo", "malware"],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 127)
        self.assertIn("not authorized", r.stderr)

    def test_refusal_is_a_clean_message_not_a_traceback(self):
        """The original bug: the broker closed with the request unread, the
        kernel sent RST, and the reply was discarded -- the client raised
        ConnectionResetError instead of printing why it was refused."""
        r = self.b.run_outside_tree("echo", "malware")
        self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn("ConnectionResetError", r.stderr)

    def test_large_refused_request_still_gets_its_reason(self):
        """The original crash: the broker replied while the request was still
        unread, the kernel sent RST, and the reply was destroyed in flight. A
        small request fits the socket buffer and cannot reproduce it, so this
        uses a payload large enough to still be queued at reply time.

        Three layers now prevent it (per-path drain, the draining close, and
        the client's own reset handling); this pins the observable behaviour
        rather than any one of them.
        """
        args = ["echo"] + ["word%06d" % i for i in range(20000)]
        r = self.b.run_outside_tree(*args)
        self.assertEqual(r.returncode, 127)
        self.assertIn("not authorized", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_refusal_is_logged(self):
        self.b.run_outside_tree("echo", "malware")
        kinds = [e["kind"] for e in self.b.events()]
        self.assertIn("reject", kinds)


if __name__ == "__main__":
    unittest.main(verbosity=2)
