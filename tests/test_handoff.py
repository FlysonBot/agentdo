"""Broker-to-broker handoff: upgrading without severing running clients.

The bug this defends against: upgrading killed the broker, and a client can
only be registered at LAUNCH (agentrun registers it in the exec handoff), so an
already-running agent could never regain authorization. It kept running while
every agentdo call failed.

A successor therefore adopts its predecessor's registry by receiving the live
pidfds over SCM_RIGHTS. The security-critical property, pinned below, is that
authorization moves as a FILE DESCRIPTOR and never as a PID number: re-deriving
a pidfd from a serialized PID would reintroduce the recycled-PID attack the
pidfd design exists to prevent.
"""

import json
import os
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Broker, load_broker


class HandoffTest(unittest.TestCase):

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_client_keeps_working_across_an_upgrade(self):
        """The headline property: no interruption for a running client."""
        out, code = self.b.run_in_tree(self.b.agentdo("echo before"))
        self.assertEqual((out, code), ("before", 0))

        _mod, adopted = self.b.start_successor()
        self.assertEqual(adopted, 1, "the successor must adopt the client")

        out, code = self.b.run_in_tree(self.b.agentdo("echo after"))
        self.assertEqual((out, code), ("after", 0),
                         "the client must still be authorized after the upgrade")

    def test_all_clients_are_carried_over(self):
        """Every registered tree moves, not just the first."""
        shells = [self.b.register_second_shell() for _ in range(3)]
        _mod, adopted = self.b.start_successor()
        self.assertEqual(adopted, 4)

        out, code = self.b.run_in_tree(self.b.agentdo("echo original"))
        self.assertEqual((out, code), ("original", 0))
        for i, sh in enumerate(shells):
            out, code = sh.run(self.b.agentdo("echo c%d" % i))
            self.assertEqual((out, code), ("c%d" % i, 0))

    def test_adopted_client_is_a_live_pidfd_not_a_pid_number(self):
        """Authorization must arrive as a descriptor, not a re-opened PID.

        A re-derived pidfd would be a different kernel object; this checks the
        adopted registry holds a working handle to the SAME process instance,
        with the start-time that was transferred alongside it.
        """
        pid = self.b._shell.pid
        mod, _adopted = self.b.start_successor()
        clients = {c.pid: c for c in mod.state.snapshot()}
        self.assertIn(pid, clients)
        c = clients[pid]
        self.assertTrue(mod.pidfd_alive(c.pidfd),
                        "the adopted pidfd must refer to the live client")
        self.assertEqual(c.start, mod._read_starttime(pid),
                         "start-time must survive the transfer intact")

    def test_predecessor_stops_serving_after_handing_over(self):
        """Two brokers must never serve one registry concurrently."""
        old = self.b.mod
        self.b.start_successor()
        self.assertTrue(old._handed_over.is_set(),
                        "the retired broker must mark itself handed over")

    def test_outsider_still_refused_after_an_upgrade(self):
        """Adoption must not widen the gate."""
        self.b.start_successor()
        r = self.b.run_outside_tree("echo", "malware")
        self.assertEqual(r.returncode, 127)
        self.assertIn("not authorized", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_dead_client_is_not_carried_over(self):
        """A client that exited before the upgrade must not be adopted."""
        second = self.b.register_second_shell()
        pid = second.pid
        second.close()
        mod, adopted = self.b.start_successor()
        self.assertEqual(adopted, 1, "only the live client should transfer")
        self.assertNotIn(pid, [c.pid for c in mod.state.snapshot()])

    def test_no_predecessor_is_not_an_error(self):
        """A first install has nothing to adopt; that starts empty, not broken."""
        missing = os.path.join(self.b.dir, "no-such-handoff.sock")
        self.assertEqual(self.b.mod.adopt_from_predecessor(missing), 0)

    def test_handoff_is_logged_on_both_sides(self):
        self.b.start_successor()
        kinds = [e["kind"] for e in self.b.events()]
        self.assertIn("handoff_out", kinds)
        self.assertIn("handoff_in", kinds)


class HandoffRefusalTest(unittest.TestCase):
    """The failure branches: who may ask, and what happens when it goes wrong.

    A real successor always behaves, so these drive the handoff socket by hand.
    The guarantee being pinned throughout is that a handoff FAILS SAFE: if the
    transfer does not complete, the predecessor keeps serving, so clients are
    never left with no broker at all.
    """

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def _header(self, s):
        """Read the predecessor's opening line without buffering ahead."""
        return json.loads(self.b.mod._read_line_unbuffered(s) or b"{}")

    def test_non_root_peer_is_refused(self):
        """Only root may ask for the registry.

        The filesystem mode (0600) already stops a non-root process from
        connecting; this pins the peer-credential check behind it, so the
        socket is not relying on its permissions alone.
        """
        self.b.mod.HANDOFF_PEER_UID = 0 if os.getuid() != 0 else 12345
        s = self.b.handoff_socket()
        try:
            reply = self._header(s)
            self.assertFalse(reply.get("ok"))
            self.assertIn("root", reply.get("err", ""))
        finally:
            s.close()

    def test_refused_peer_gets_no_descriptors(self):
        """A refusal must not leak pidfds: the registry stays put."""
        self.b.mod.HANDOFF_PEER_UID = 0 if os.getuid() != 0 else 12345
        s = self.b.handoff_socket()
        try:
            self._header(s)
        finally:
            s.close()
        self.assertFalse(self.b.mod._handed_over.is_set())
        self.assertEqual(len(self.b.mod.state.snapshot()), 1,
                         "a refused handoff must leave the registry intact")

    def test_version_mismatch_is_refused_by_the_successor(self):
        """A successor must not adopt a registry shaped by another version.

        Registry contents could differ across versions, so adopting one it may
        misunderstand is worse than starting empty: refusing leaves the
        predecessor serving.
        """
        # The successor must be a SEPARATE module: bumping the version on the
        # predecessor's own module would change what it advertises too, so the
        # two would still agree and nothing would be tested.
        successor = load_broker(self.b.dir)
        successor.PROTOCOL_VERSION += 1
        # Short timeout: without the version check the successor goes on to
        # adopt and both sides wait on each other, so a missing check must
        # surface as a fast failure rather than a hung suite.
        successor.HANDOFF_TIMEOUT = 2.0
        self.b.mod.HANDOFF_TIMEOUT = 2.0
        try:
            adopted = successor.adopt_from_predecessor(self.b.mod.HANDOFF_PATH)
        finally:
            successor.stop_listening()

        self.assertEqual(adopted, 0, "a mismatched version must not be adopted")
        self.assertFalse(successor.state.snapshot(),
                         "a successor must adopt nothing from a version it "
                         "does not speak")
        self.assertIn("handoff_in_failed",
                      [e["kind"] for e in self.b.events()])
        # Fail safe: the predecessor keeps its clients rather than retiring
        # into a successor that could not understand them.
        self.assertFalse(self.b.mod._handed_over.is_set())
        out, code = self.b.run_in_tree(self.b.agentdo("echo still-serving"))
        self.assertEqual((out, code), ("still-serving", 0))

    def test_predecessor_keeps_serving_when_the_successor_vanishes(self):
        """The fail-safe guarantee, and the reason retirement is confirmed.

        A successor that collects the descriptors and then dies without
        confirming must NOT retire the predecessor -- that would leave running
        clients with no broker at all. The predecessor keeps its registry and
        goes on serving.
        """
        self._abandon_handoff(confirm=None)
        self._assert_still_serving()

    def test_predecessor_keeps_serving_when_the_successor_stays_silent(self):
        """The timeout branch specifically.

        Dropping the connection and hanging on to it while saying nothing are
        different code paths -- a closed socket reads as EOF, a held-open one
        has to time out. Both must leave the predecessor serving, so both are
        pinned; testing only the first left the timeout branch uncovered.
        """
        self._abandon_handoff(confirm="silence")
        self._assert_still_serving()

    def test_predecessor_keeps_serving_when_the_successor_refuses(self):
        """An explicit refusal must be honoured, not treated as success."""
        self._abandon_handoff(confirm={"ok": False, "err": "cannot adopt"})
        self._assert_still_serving()

    # -- helpers for the three abandonment shapes -------------------------- #

    def _abandon_handoff(self, confirm):
        """Play a successor that takes the descriptors but never completes.

        `confirm` is None to drop the connection, "silence" to hold it open
        saying nothing, or a dict to send as an explicit reply.
        """
        self.b.mod.HANDOFF_TIMEOUT = 1.0
        s = self.b.handoff_socket(timeout=10.0)
        try:
            header = self._header(s)
            self.assertTrue(header.get("ok"))
            self.assertEqual(header.get("count"), 1)
            # Collect the pidfd the predecessor sends, then fail to confirm.
            _msg, fds, _flags, _addr = socket.recv_fds(s, 65536, 1)
            for fd in fds:
                os.close(fd)
            if isinstance(confirm, dict):
                s.sendall((json.dumps(confirm) + "\n").encode())
            elif confirm == "silence":
                time.sleep(self.b.mod.HANDOFF_TIMEOUT + 1.0)
        finally:
            s.close()

        deadline = time.time() + 10
        while time.time() < deadline:
            if any(e["kind"] == "handoff_failed" for e in self.b.events()):
                return
            time.sleep(0.05)
        self.fail("the abandoned handoff was never recorded as failed")

    def _assert_still_serving(self):
        """The predecessor kept its clients and is still answering."""
        self.assertFalse(self.b.mod._handed_over.is_set(),
                         "an unconfirmed handoff must not retire the broker")
        self.assertEqual(len(self.b.mod.state.snapshot()), 1,
                         "the registry must survive a failed handoff")
        out, code = self.b.run_in_tree(self.b.agentdo("echo still-serving"))
        self.assertEqual((out, code), ("still-serving", 0))


class RegistrationDuringHandoffTest(unittest.TestCase):
    """A client must never be stranded by arriving mid-handoff.

    _serve_handoff snapshots the registry and then waits to be confirmed. A
    client registering in that window is not in the transfer, so it would live
    only in the outgoing broker's registry and vanish when it retired -- losing
    privilege silently, mid-launch, with nothing in any log to explain it.

    The broker refuses to register during the window instead. agentrun aborts
    before it execs the client, so the failure is visible and retrying works.
    """

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_registration_is_refused_while_a_handoff_is_in_flight(self):
        pred = self.b.mod
        pred.HANDOFF_TIMEOUT = 5.0

        # Start a handoff and stop after taking the header and descriptors,
        # leaving the predecessor waiting for confirmation.
        s = self.b.handoff_socket(timeout=10.0)
        try:
            header = json.loads(pred._read_line_unbuffered(s) or b"{}")
            self.assertTrue(header.get("ok"))
            fds = []
            for _ in range(header["count"]):
                _msg, got, _flags, _addr = socket.recv_fds(s, 65536, 1)
                fds += list(got)

            self.assertTrue(pred._handoff_in_flight.is_set(),
                            "the broker must know a handoff is in flight")
            reply = self._register(pred, os.getpid())
            self.assertFalse(reply.get("ok"),
                             "registering mid-handoff must be refused, not "
                             "silently accepted into a registry about to die")
            self.assertIn("handing over", reply.get("err", ""))

            for fd in fds:
                os.close(fd)
        finally:
            s.close()

    def test_registration_works_again_after_an_abandoned_handoff(self):
        """A failed handoff must not leave the broker permanently closed."""
        pred = self.b.mod
        pred.HANDOFF_TIMEOUT = 1.0
        s = self.b.handoff_socket(timeout=10.0)
        try:
            json.loads(pred._read_line_unbuffered(s) or b"{}")
        finally:
            s.close()

        deadline = time.time() + 10
        while time.time() < deadline and pred._handoff_in_flight.is_set():
            time.sleep(0.05)
        self.assertFalse(pred._handoff_in_flight.is_set(),
                         "the in-flight flag must clear when a handoff fails")

        shell = self.b.register_second_shell()
        out, code = shell.run(self.b.agentdo("echo registered-after-failure"))
        self.assertEqual((out, code), ("registered-after-failure", 0))

    def _register(self, mod, pid):
        """Register through the real socket, as agentrun's helper does."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect(mod.REG_PATH)
        try:
            s.sendall(json.dumps({"pid": pid}).encode())
            s.shutdown(socket.SHUT_WR)
            return json.loads(s.recv(65536) or b"{}")
        finally:
            s.close()


class UnbufferedReadTest(unittest.TestCase):
    """_read_line_unbuffered: why a buffered reader cannot be used here.

    Regression for a bug that cost real debugging time. makefile().readline()
    reads AHEAD, so on a socket carrying SCM_RIGHTS it pulls the next message's
    bytes into its buffer while the kernel drops that message's descriptors --
    the transfer then silently deadlocks, both sides waiting on the other.
    """

    def setUp(self):
        self.b = Broker()

    def tearDown(self):
        self.b.close()

    def test_reads_exactly_one_line_and_no_further(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            a.sendall(b'{"first":1}\n')
            a.sendall(b'{"second":2}\n')
            self.assertEqual(self.b.mod._read_line_unbuffered(b),
                             b'{"first":1}\n')
            # The second message must still be on the socket, unconsumed.
            self.assertEqual(self.b.mod._read_line_unbuffered(b),
                             b'{"second":2}\n')
        finally:
            a.close()
            b.close()

    def test_descriptors_survive_a_preceding_line_read(self):
        """The exact shape of the handoff: a line, then a message with an fd."""
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        proc = subprocess.Popen(["sleep", "30"])
        fd = self.b.mod.pidfd_open(proc.pid)
        try:
            a.sendall(b'{"ok":true,"count":1}\n')
            socket.send_fds(a, [b'{"pid":1}\n'], [fd])

            self.assertEqual(self.b.mod._read_line_unbuffered(b),
                             b'{"ok":true,"count":1}\n')
            _msg, fds, _flags, _addr = socket.recv_fds(b, 65536, 1)
            self.assertEqual(len(fds), 1,
                             "the descriptor must survive the preceding read")
            self.assertTrue(self.b.mod.pidfd_alive(fds[0]))
            for got in fds:
                os.close(got)
        finally:
            os.close(fd)
            proc.kill()
            proc.wait()
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
