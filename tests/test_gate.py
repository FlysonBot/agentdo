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


class ConcurrentClientsTest(unittest.TestCase):
    """Several clients registered at once, each independently authorized.

    The reported bug: `agentrun claude` in one terminal, then `agentrun claude`
    in another, and the FIRST one lost agentdo mid-task. The broker kept a
    single authorization slot, so the second registration overwrote the first,
    and separately, the first client to exit shut the whole broker down. There
    is no limit on how many clients may be registered concurrently.
    """

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_second_registration_does_not_evict_the_first(self):
        """The core regression: registering client #2 must leave #1 working."""
        second = self.b.register_second_shell()
        out, code = self.b.run_in_tree(self.b.agentdo("echo first-still-works"))
        self.assertEqual(out, "first-still-works")
        self.assertEqual(code, 0)
        # And the newcomer works too -- this is not a first-wins swap.
        out2, code2 = second.run(self.b.agentdo("echo second-works"))
        self.assertEqual(out2, "second-works")
        self.assertEqual(code2, 0)

    def test_many_clients_are_authorized_at_once(self):
        """No cap: several concurrent clients all keep working."""
        shells = [self.b.register_second_shell() for _ in range(4)]
        out, code = self.b.run_in_tree(self.b.agentdo("echo original"))
        self.assertEqual((out, code), ("original", 0))
        for i, sh in enumerate(shells):
            out, code = sh.run(self.b.agentdo("echo client%d" % i))
            self.assertEqual((out, code), ("client%d" % i, 0))

    def test_one_client_exiting_leaves_the_others_authorized(self):
        """The second half of the bug: the first exit killed the broker.

        Privilege must die with the client it was granted to, and with no
        other.
        """
        second = self.b.register_second_shell()
        pidfd = self.b.registered_pidfd(second.pid)
        second.close()
        # Drive the real watcher path, which is what used to call _shutdown().
        self.b.mod._watch_exit(pidfd, second.pid)

        out, code = self.b.run_in_tree(self.b.agentdo("echo survivor"))
        self.assertEqual(out, "survivor")
        self.assertEqual(code, 0)

    def test_exited_client_tree_is_no_longer_authorized(self):
        """Revocation is still real: the exited client's tree loses access."""
        second = self.b.register_second_shell()
        pid, pidfd = second.pid, self.b.registered_pidfd(second.pid)
        second.close()
        self.b.mod._watch_exit(pidfd, pid)

        roots = [c.pid for c in self.b.mod.state.snapshot()]
        self.assertNotIn(pid, roots,
                         "an exited client must be removed from the registry")

    def test_outsider_still_refused_with_several_clients(self):
        """More registered trees must not weaken the gate."""
        self.b.register_second_shell()
        self.b.register_second_shell()
        r = self.b.run_outside_tree("echo", "malware")
        self.assertEqual(r.returncode, 127)
        self.assertIn("not authorized", r.stderr)
        self.assertEqual(r.stdout, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
