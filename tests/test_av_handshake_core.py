"""Hardware-free execution of the shared C probe controller, never the XBE."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


class AvHandshakeCoreTests(unittest.TestCase):
    def test_scripted_mmio_and_clock(self):
        root = Path(__file__).resolve().parents[1]
        compiler = ("C:/msys64/mingw64/bin/gcc.exe" if os.name == "nt"
                    else shutil.which("cc"))
        self.assertTrue(compiler and Path(compiler).is_file(), "C compiler required for probe safety tests")
        with tempfile.TemporaryDirectory(prefix="av-handshake-test-") as directory:
            executable = Path(directory) / ("mock.exe" if os.name == "nt" else "mock")
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(root / "tests/av_handshake_mock.c"), "-o", str(executable)],
                           check=True, capture_output=True, text=True)
            result = subprocess.run([str(executable)], check=True, capture_output=True,
                                    text=True, timeout=10)
            self.assertIn("PASS:", result.stdout)
