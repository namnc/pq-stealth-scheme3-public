#!/usr/bin/env python3
"""Run the tooling self-tests through Python's standard test runner.

    python3 tools/run_selftests.py

The working directory is forced to the repo root so invocation from elsewhere
(CI, an absolute path, `/tmp`) does not change what the suite can see.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(ROOT / "tools"),
            "-p",
            "test_tool_selftests.py",
            "-v",
        ],
        cwd=ROOT,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
