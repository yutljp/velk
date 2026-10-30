"""Compare Windows emulation with saved executable stdout and exit statuses."""

import argparse
import difflib
import json
from pathlib import Path
import subprocess


def registry_output(text):
    """Select shared cases from captures that also contain velk-only checks."""
    lines = text.splitlines(keepends=True)
    modes = ["0", "1", "2", "4", "5", "6"]
    if (len(lines) != 7 or len(lines[0].split()) != 2
            or any(len(line.split()) != 2 or line.split()[0] != mode
                   for line, mode in zip(lines[1:], modes))):
        return text
    return lines[0].split()[0] + "\n" + "".join(
        line for line, mode in zip(lines[1:], modes) if mode not in ["0", "2"]
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    binary = Path("target/release/velk").resolve()
    failures = 0
    paths = sorted(args.directory.glob("*.exe"))
    if not paths:
        parser.error("the directory contains no executables")
    print("Registry comparisons exclude unsupported open flags, non-registry handles, "
          "and unterminated setter input; these have separate emulation tests.", flush=True)
    for path in paths:
        options = {"stepLimit": 50000000, "timeLimitMs": 60000}
        if ".registry." in path.name:
            options["windows"] = {"registry": {
                "HKEY_CURRENT_USER\\Software\\VelkEmulationTest": {
                    "Number": {"type": 4, "bytes": [239, 205, 171, 137]},
                    "Text": {"type": 1, "bytes": [72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 0, 0]},
                    "": {"type": 1, "bytes": [229, 101, 0, 0]},
                    "Bytes": {"type": 3, "bytes": [0, 255, 7]},
                    "Raw": {"type": 1, "bytes": [88, 0]},
                }
            }}
        if any(f".{group}." in path.name for group in ["crt", "ucrt"]):
            options["files"] = {"crt.bin": []}
        if any(f".{group}." in path.name for group in ["exit", "ucrt_exit"]):
            options["files"] = {"exit.bin": []}
        try:
            output = subprocess.run(
                [str(binary), "--emulate", "--json", str(path.resolve()),
                 "entry", "--emulation-options", json.dumps(options)],
                capture_output=True, text=True, timeout=90, check=False,
            )
            report = json.loads(output.stdout)
            expected = Path(f"{path}.stdout").read_text()
            status = int(Path(f"{path}.status").read_text())
            actual = report["stdout"].replace("\r\n", "\n")
            if ".registry." in path.name:
                expected = registry_output(expected)
                actual = registry_output(actual)
            matches = (output.returncode == 0 and report["reason"] == "exit"
                       and int(report["returnValue"], 16) & 255 == status
                       and actual == expected)
            print(f"{'PASS' if matches else 'FAIL'} {path.name}", flush=True)
            if not matches:
                failures += 1
                print(f"  reason={report['reason']} return={report['returnValue']} "
                      f"status={status} error={report.get('error')}")
                print("".join(difflib.unified_diff(
                    expected.splitlines(keepends=True),
                    actual.splitlines(keepends=True),
                    fromfile="reference", tofile="emulation")), end="", flush=True)
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            failures += 1
            print(f"FAIL {path.name}: {error}", flush=True)
    print(f"{len(paths) - failures}/{len(paths)} passed; {failures} failed")
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
