"""Standard test-runner entry point for the standalone tooling self-tests."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ToolSelfTests(unittest.TestCase):
    """Run each executable self-test and preserve its diagnostics on failure."""

    def run_script(self, name: str) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / name)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}".strip(),
        )

    def test_derive_sizes(self) -> None:
        self.run_script("test-derive-sizes.py")

    def test_gen_vectors(self) -> None:
        self.run_script("test-gen-vectors.py")

    def test_check_measured(self) -> None:
        self.run_script("test-check-measured.py")


if __name__ == "__main__":
    unittest.main()
