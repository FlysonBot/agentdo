"""The launcher: sudo handling, startup timing, and argument checking.

agentrun is the entry point for everything, and it is the one component the
rest of the suite cannot reach: it needs a real sudo and a real terminal. These
tests substitute a fake `sudo` early on PATH, which makes the interesting cases
-- a slow password, a wrong password, a broker that dies on launch -- scriptable
and fast, and keeps the suite unprivileged like the rest.

Every path the launcher touches is redirectable through the environment
(AGENTDO_INSTALL_DIR, AGENTDO_SOCK, AGENTDO_REG, AGENTDO_BOOT_LOG), so nothing
here goes near /run, /var/log, or an installed copy.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(REPO, "agentrun")


class LauncherTest(unittest.TestCase):
    def setUp(self):
        # Short path: the launcher builds AF_UNIX socket paths under it.
        self.dir = tempfile.mkdtemp(prefix="adl-", dir="/tmp")
        self.shim = os.path.join(self.dir, "shim")
        os.makedirs(os.path.join(self.dir, "bin"))
        os.makedirs(self.shim)

    def tearDown(self):
        # The broker stub is detached by setsid and outlives the launcher, so
        # removing the directory is not enough: reap it by the unique path it
        # was started from, or the suite leaves idle processes behind.
        subprocess.run(["pkill", "-f", "%s/agentdo-broker.py" % self.dir],
                       capture_output=True)
        shutil.rmtree(self.dir, ignore_errors=True)

    # -- fixtures ---------------------------------------------------------- #

    def write_sudo(self, body):
        """Install a fake `sudo` early on PATH.

        It is called twice by the launcher: once as `sudo -v` to authenticate,
        and once to actually launch the broker. `body` decides how each behaves.
        """
        path = os.path.join(self.shim, "sudo")
        with open(path, "w") as f:
            f.write("#!/usr/bin/env bash\n" + textwrap.dedent(body))
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP
                 | stat.S_IXOTH)
        return path

    def write_broker_stub(self, delay=0.2):
        """A stand-in broker that binds the command socket and then idles."""
        path = os.path.join(self.dir, "agentdo-broker.py")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""\
                import os, socket, time
                time.sleep(%r)
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.bind(os.environ["AGENTDO_SOCK"])
                s.listen(1)
                time.sleep(20)
                """ % delay))
        return path

    def run_launcher(self, *args, timeout=60):
        env = dict(
            os.environ,
            PATH=self.shim + os.pathsep + os.environ["PATH"],
            AGENTDO_INSTALL_DIR=self.dir,
            AGENTDO_SOCK=os.path.join(self.dir, "s.sock"),
            AGENTDO_REG=os.path.join(self.dir, "r.sock"),
            AGENTDO_BOOT_LOG=os.path.join(self.dir, "boot.log"),
        )
        started = time.time()
        proc = subprocess.run([LAUNCHER, *(args or ("true",))], env=env,
                              capture_output=True, text=True, timeout=timeout)
        return proc, time.time() - started

    # -- argument handling -------------------------------------------------- #

    def test_no_arguments_is_a_usage_error(self):
        """Bare `agentrun` must not guess a command to run.

        Invoked directly rather than through run_launcher, which supplies a
        default argument; the point here is the empty argument list.
        """
        proc = subprocess.run([LAUNCHER], capture_output=True, text=True,
                              timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("usage:", proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_refuses_to_run_as_root(self):
        """The client must run as a normal user, so root-owned files are not
        strewn through the user's home and working tree.

        The guard reads `id -u`, so a fake `id` reporting 0 exercises the real
        branch without the suite needing to be root.
        """
        fake_id = os.path.join(self.shim, "id")
        with open(fake_id, "w") as f:
            f.write('#!/usr/bin/env bash\necho 0\n')
        os.chmod(fake_id, 0o755)
        self.write_sudo('exit 0\n')
        proc, _ = self.run_launcher("true")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not root", proc.stderr)

    # -- the sudo prompt ---------------------------------------------------- #

    def test_slow_password_entry_does_not_time_out(self):
        """The regression this module exists for.

        The sudo that starts the broker used to be backgrounded while a
        five-second wait loop ran, so a user who typed slowly saw "broker
        failed to start" even though authentication was still pending.
        """
        self.write_broker_stub()
        self.write_sudo("""
            if [[ "$1" == "-v" ]]; then
              sleep 8          # user is slow to type their password
              exit 0
            fi
            shift_args=("$@")
            exec env "${shift_args[@]}"
            """)
        proc, elapsed = self.run_launcher("true")
        self.assertIn("broker is up", proc.stderr,
                      "launcher gave up while sudo was still prompting")
        self.assertGreaterEqual(elapsed, 8,
                                "the launcher did not actually wait for sudo")

    def test_failed_authentication_aborts_without_starting_broker(self):
        self.write_broker_stub()
        self.write_sudo("""
            if [[ "$1" == "-v" ]]; then
              echo "Sorry, try again." >&2
              exit 1
            fi
            echo "REACHED-BROKER-LAUNCH" >&2
            exit 0
            """)
        proc, _ = self.run_launcher("true")
        self.assertIn("sudo authentication failed", proc.stderr)
        self.assertNotIn("REACHED-BROKER-LAUNCH", proc.stderr,
                         "the broker was launched despite failed auth")
        self.assertNotEqual(proc.returncode, 0)

    def test_authentication_is_not_prompted_twice(self):
        """`sudo -v` primes the credential cache, so the launch call should
        not prompt again. A second prompt would block a real user."""
        self.write_broker_stub()
        counter = os.path.join(self.dir, "prompts")
        self.write_sudo("""
            if [[ "$1" == "-v" ]]; then
              echo p >> %s
              exit 0
            fi
            shift_args=("$@")
            exec env "${shift_args[@]}"
            """ % counter)
        self.run_launcher("true")
        with open(counter) as f:
            self.assertEqual(len(f.read().split()), 1,
                             "sudo authenticated more than once")

    # -- broker startup ----------------------------------------------------- #

    def test_broker_launch_failure_is_reported_promptly(self):
        """A broker that dies immediately should not burn the whole timeout."""
        self.write_sudo("""
            if [[ "$1" == "-v" ]]; then exit 0; fi
            exit 1        # the broker never starts
            """)
        proc, elapsed = self.run_launcher("true")
        self.assertIn("broker failed to start", proc.stderr)
        self.assertLess(elapsed, 4.0,
                        "waited out the full timeout for a broker already dead")

    def test_existing_socket_skips_broker_startup(self):
        """With a broker already running, the launcher must not sudo at all."""
        sock = os.path.join(self.dir, "s.sock")
        import socket as _socket
        srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        srv.bind(sock)
        srv.listen(1)
        try:
            self.write_sudo("""
                echo "SUDO-WAS-CALLED" >&2
                exit 1
                """)
            proc, _ = self.run_launcher("true")
            self.assertNotIn("broker not running", proc.stderr)
            # Registration still needs sudo; only the STARTUP path is skipped.
            self.assertNotIn("starting it", proc.stderr)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
