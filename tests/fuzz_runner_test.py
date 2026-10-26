"""Check the fuzz runner's stopping rule without running a fuzz target."""

import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import fuzz


class FuzzRunnerTest(unittest.TestCase):
    def run_rounds(self, outputs, quiet=120):
        commands = []
        outputs = iter(outputs)

        def execute(command, **kwargs):
            commands.append(command)
            if "cmin" in command:
                return subprocess.CompletedProcess(command, 0)
            code, output = next(outputs)
            kwargs["stdout"].write(output)
            return subprocess.CompletedProcess(command, code)

        args = type("Arguments", (), {"rounds": 5, "seconds": 60, "quiet": quiet})()
        with tempfile.TemporaryDirectory(dir=fuzz.ROOT / "target") as directory:
            with (
                mock.patch.object(fuzz, "ROOT", Path(directory)),
                mock.patch.object(fuzz.subprocess, "run", side_effect=execute),
                mock.patch.object(fuzz.time, "monotonic", side_effect=range(0, 100000, 10000)),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                success = fuzz.run("elf", args)
        return success, commands

    def test_build_time_cannot_satisfy_the_quiet_interval(self):
        outputs = [
            (0, "cov: 10 ft: 12\nDone 100 runs in 60 second(s)\n"),
            (0, "cov: 10 ft: 12\nDone 100 runs in 1 second(s)\n"),
            (0, "cov: 10 ft: 12\nDone 100 runs in 119 second(s)\n"),
        ]
        success, commands = self.run_rounds(outputs)
        self.assertTrue(success)
        self.assertEqual(sum("run" in command for command in commands), 3)
        self.assertEqual(sum("cmin" in command for command in commands), 1)

    def test_coverage_growth_restarts_the_quiet_interval(self):
        outputs = [
            (0, f"cov: {coverage} ft: 12\nDone 100 runs in 60 second(s)\n")
            for coverage in [10, 10, 11, 11, 11]
        ]
        success, commands = self.run_rounds(outputs)
        self.assertTrue(success)
        self.assertEqual(sum("run" in command for command in commands), 5)

    def test_crashes_are_failures_without_minimizing(self):
        success, commands = self.run_rounds([(1, "ERROR: AddressSanitizer\n")])
        self.assertFalse(success)
        self.assertFalse(any("cmin" in command for command in commands))

    def test_missing_coverage_is_a_failure(self):
        success, commands = self.run_rounds([(0, "Done 100 runs in 60 second(s)\n")])
        self.assertFalse(success)
        self.assertFalse(any("cmin" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
