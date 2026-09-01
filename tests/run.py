#!/usr/bin/env python3
"""Run the whole agentdo suite.

    python3 tests/run.py            # everything
    python3 tests/run.py gate       # one module (gate | protocol | signals)

Runs entirely as your own user: the broker's root check lives in main(), and
these tests drive the servers directly, so commands execute with your
privileges rather than root's. Nothing here needs sudo and nothing touches
/run, /var/log, or an installed copy -- each test gets its own broker on a
private socket under /tmp.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MODULES = ("test_gate", "test_protocol", "test_signals")


def main():
    sys.path.insert(0, HERE)
    wanted = sys.argv[1:]
    names = []
    for m in MODULES:
        short = m.replace("test_", "")
        if not wanted or short in wanted or m in wanted:
            names.append(m)
    if not names:
        sys.exit("no matching test modules; choose from: %s"
                 % ", ".join(m.replace("test_", "") for m in MODULES))

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for name in names:
        suite.addTests(loader.loadTestsFromName(name))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
