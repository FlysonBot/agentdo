"""The request/reply path: stdio passing, exit codes, and the wire protocol.

Most cases here are regressions for bugs that reached a user. Where that is so,
the docstring says which failure the test pins down, because the value of the
test is knowing what it is defending against.
"""

import importlib.machinery
import importlib.util
import json
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Broker, CLIENT


class StdioTest(unittest.TestCase):
    """The command inherits the caller's real descriptors."""

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_stdout_reaches_the_caller(self):
        out, code = self.b.run_in_tree(self.b.agentdo("echo hello"))
        self.assertEqual(out, "hello")
        self.assertEqual(code, 0)

    def test_stdin_is_wired_up(self):
        """stdin was never implemented while output was captured and returned
        as JSON: the command was run with no stdin at all."""
        out, _ = self.b.run_in_tree("echo piped | %s" % self.b.agentdo("cat"))
        self.assertEqual(out, "piped")

    def test_stdin_from_a_heredoc(self):
        out, _ = self.b.run_in_tree(
            "%s <<< $'a\\nb\\nc'" % self.b.agentdo("wc -l"))
        self.assertEqual(out.strip(), "3")

    def test_stderr_is_separate_from_stdout(self):
        out, _ = self.b.run_in_tree(
            "%s 2>/dev/null" % self.b.agentdo("bash -c 'echo o; echo e >&2'"))
        self.assertEqual(out, "o", "stderr must not arrive on stdout")

    def test_large_output_is_not_truncated(self):
        """Output used to be buffered whole in the broker under a 4 MiB cap."""
        out, _ = self.b.run_in_tree(
            "%s | wc -l" % self.b.agentdo("seq 1 200000"))
        self.assertEqual(out.strip(), "200000")

    def test_binary_output_is_not_mangled(self):
        """Output was decoded as UTF-8 with errors replaced, corrupting bytes
        that are not valid UTF-8."""
        out, _ = self.b.run_in_tree(
            "%s | xxd -p" % self.b.agentdo(r"printf '\x00\xff\xfe'"))
        self.assertEqual(out.strip(), "00fffe")


class ExitCodeTest(unittest.TestCase):
    """Exit statuses follow shell conventions."""

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_plain_exit_code_passes_through(self):
        _, code = self.b.run_in_tree(self.b.agentdo("bash -c 'exit 42'"))
        self.assertEqual(code, 42)

    def test_success_is_zero(self):
        _, code = self.b.run_in_tree(self.b.agentdo("true"))
        self.assertEqual(code, 0)

    def test_sigpipe_reports_141(self):
        """subprocess reports a signal death as a NEGATIVE returncode (-13).
        Returned verbatim through an 8-bit exit status that surfaced as 243."""
        out, _ = self.b.run_in_tree(
            "%s 2>/dev/null | head -2 >/dev/null; echo ${PIPESTATUS[0]}"
            % self.b.agentdo("seq 1 100000"))
        self.assertEqual(out.strip(), "141")

    def test_sigterm_reports_143(self):
        _, code = self.b.run_in_tree(
            self.b.agentdo("bash -c 'kill -TERM $$'"))
        self.assertEqual(code, 143)

    def test_sigkill_reports_137(self):
        _, code = self.b.run_in_tree(
            self.b.agentdo("bash -c 'kill -KILL $$'"))
        self.assertEqual(code, 137)

    def test_command_not_found_reports_127(self):
        out, code = self.b.run_in_tree(
            "%s 2>&1" % self.b.agentdo("no-such-command-xyz"))
        self.assertEqual(code, 127)
        self.assertIn("command not found", out)

    def test_no_command_given_reports_2(self):
        out, code = self.b.run_in_tree("%s 2>&1" % self.b.agentdo(""))
        self.assertEqual(code, 2)
        self.assertIn("no command given", out)


class WireProtocolTest(unittest.TestCase):
    """Framing and versioning of the socket protocol."""

    def setUp(self):
        self.b = Broker()
        self.shell_pid = self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def _raw_request(self, payload_obj):
        """Send a hand-built request from inside the tree and read the reply.

        Runs via a helper script executed by the registered shell, so the
        connecting process is a descendant and passes the gate.
        """
        script = os.path.join(self.b.dir, "raw.py")
        with open(script, "w") as f:
            f.write(
                "import sys, os, socket, json\n"
                "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "s.connect(os.environ['AGENTDO_SOCK'])\n"
                "socket.send_fds(s, [json.dumps(%r).encode()],\n"
                "                [sys.stdin.fileno(), sys.stdout.fileno(),\n"
                "                 sys.stderr.fileno()])\n"
                "sys.stderr.write(s.recv(4096).decode())\n" % (payload_obj,))
        out, _ = self.b.run_in_tree("%s %s 2>&1" % (sys.executable, script))
        return out

    def test_version_mismatch_is_refused_clearly(self):
        """A broker left running across an upgrade accepted new-style requests,
        replied in the old shape, and the client silently discarded all output
        while exiting 0. The version check turns that into a message."""
        reply = self._raw_request({"argv": ["echo", "stale"], "cwd": "/", "env": {}})
        self.assertIn("protocol mismatch", reply)
        self.assertIn("Restart the broker", reply)

    def test_wrong_version_number_is_refused(self):
        reply = self._raw_request(
            {"version": 999, "argv": ["echo", "x"], "cwd": "/", "env": {}})
        self.assertIn("protocol mismatch", reply)

    def test_malformed_argv_is_refused(self):
        reply = self._raw_request({"version": 2, "argv": "not-a-list",
                                   "cwd": "/", "env": {}})
        self.assertIn("argv must be", reply)

    def test_empty_argv_is_refused(self):
        reply = self._raw_request({"version": 2, "argv": [], "cwd": "/", "env": {}})
        self.assertIn("argv must be", reply)


class DenylistTest(unittest.TestCase):
    """Denied commands are blocked before they can touch the caller's stdio."""

    def setUp(self):
        self.b = Broker()
        self.b.register_shell()

    def tearDown(self):
        self.b.close()

    def test_denied_command_exits_126(self):
        out, code = self.b.run_in_tree(
            "%s 2>&1" % self.b.agentdo("useradd bob"))
        self.assertEqual(code, 126)
        self.assertIn("blocked by denylist", out)

    def test_denied_command_produces_no_output(self):
        """A denied command must never run, so nothing may reach stdout."""
        out, _ = self.b.run_in_tree(
            "%s 2>/dev/null" % self.b.agentdo("useradd bob"))
        self.assertEqual(out, "")

    def test_denial_is_logged(self):
        self.b.run_in_tree("%s 2>&1" % self.b.agentdo("useradd bob"))
        kinds = [e["kind"] for e in self.b.events()]
        self.assertIn("deny", kinds)

    def test_allowed_command_is_logged_with_its_argv(self):
        self.b.run_in_tree(self.b.agentdo("echo logged"))
        execs = [e for e in self.b.events() if e["kind"] == "exec"]
        self.assertTrue(execs, "an executed command must be logged")
        self.assertEqual(execs[-1]["argv"], ["echo", "logged"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


def _load_shim():
    """The client shim is extensionless, so load it by path."""
    loader = importlib.machinery.SourceFileLoader("agentdo_shim", CLIENT)
    spec = importlib.util.spec_from_loader("agentdo_shim", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class SudoOptionsTest(unittest.TestCase):
    """`sudo -n cmd`, `sudo -u user cmd` and `sudo VAR=x cmd` must work.

    Agents reach for those spellings from habit, and the shim used to treat the
    first word as the command, so `sudo -n true` failed with "command not
    found: -n" -- indistinguishable, to the agent, from sudo being broken.
    Parsing is checked directly (the -u branch needs real root to execute);
    a few cases also run end to end through a broker.
    """

    @classmethod
    def setUpClass(cls):
        cls.shim = _load_shim()

    def parse(self, *args):
        return self.shim.parse_sudo_args(list(args))

    def test_plain_command_is_untouched(self):
        self.assertEqual(self.parse("ls", "-la"), ["ls", "-la"])

    def test_options_after_the_command_belong_to_the_command(self):
        self.assertEqual(self.parse("ls", "-n", "-u"), ["ls", "-n", "-u"])

    def test_noop_options_are_dropped(self):
        self.assertEqual(self.parse("-n", "-S", "-H", "-k", "true"), ["true"])

    def test_combined_short_options(self):
        self.assertEqual(self.parse("-nH", "true"), ["true"])
        self.assertEqual(self.parse("-nu", "bob", "id"),
                         ["runuser", "-u", "bob", "--", "id"])
        self.assertEqual(self.parse("-nubob", "id"),
                         ["runuser", "-u", "bob", "--", "id"])

    def test_user_option_forms(self):
        want = ["runuser", "-u", "bob", "--", "id"]
        for opts in (["-u", "bob"], ["-ubob"], ["--user", "bob"],
                     ["--user=bob"]):
            self.assertEqual(self.parse(*opts, "id"), want, opts)

    def test_root_user_needs_no_wrapper(self):
        self.assertEqual(self.parse("-u", "root", "id"), ["id"])

    def test_chdir(self):
        argv = self.parse("-D", "/etc", "pwd")
        self.assertEqual(argv[-2:], ["/etc", "pwd"])
        self.assertEqual(argv[:2], ["sh", "-c"])

    def test_variable_assignments_become_env(self):
        self.assertEqual(self.parse("FOO=bar", "cmd"),
                         ["env", "FOO=bar", "cmd"])

    def test_double_dash_ends_options_and_assignments(self):
        self.assertEqual(self.parse("--", "-n"), ["-n"])
        self.assertEqual(self.parse("--", "A=b"), ["A=b"])

    def test_validate_without_a_command_runs_nothing(self):
        self.assertIsNone(self.parse("-v"))
        self.assertIsNone(self.parse("-n", "-v"))

    def test_missing_command_is_an_error(self):
        with self.assertRaises(self.shim._UsageError):
            self.parse("-n")

    def test_unsupported_and_unknown_options_are_refused(self):
        for opt in ("-i", "-s", "-l", "-e", "-g", "--login", "-z", "--bogus"):
            with self.assertRaises(self.shim._UsageError, msg=opt):
                self.parse(opt, "id")

    def test_missing_option_argument_is_an_error(self):
        with self.assertRaises(self.shim._UsageError):
            self.parse("-u")

    def test_preserve_env_warns_but_still_runs(self):
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            argv = self.parse("-E", "id")
        self.assertEqual(argv, ["id"])
        self.assertIn("preserve-env is not supported", err.getvalue())

    def test_end_to_end_flags_and_assignments(self):
        b = Broker()
        b.register_shell()
        self.addCleanup(b.close)
        out, code = b.run_in_tree(b.agentdo("-n true"))
        self.assertEqual(code, 0, out)
        out, code = b.run_in_tree(b.agentdo("-nE FOO=bar sh -c 'echo $FOO' 2>/dev/null"))
        self.assertEqual((out.strip(), code), ("bar", 0))

    def test_end_to_end_refusal_exits_2_with_a_message(self):
        b = Broker()
        b.register_shell()
        self.addCleanup(b.close)
        out, code = b.run_in_tree("%s 2>&1" % b.agentdo("-i"))
        self.assertEqual(code, 2)
        self.assertIn("not supported", out)
