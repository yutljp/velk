"""Evaluate bounded searches and replay their inputs against Linux libc binaries.

Run with uv run tests/crackmes.py --help. Results are JSON lines, including elapsed
seconds and diagnostics for every search. Generated files belong under target/.
"""

import argparse
import json
import os
import platform
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import time


def symbols(path):
    """Read the three named targets from a little-endian ELF64 symbol table."""
    data = path.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", path
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count = struct.unpack_from("<HH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size)
                for i in range(count)]
    result = {}
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        for start in range(section[4], section[4] + section[5], section[9]):
            name, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, start)
            begin = strings[4] + name
            text = data[begin:data.index(0, begin)].decode()
            if text in ("success", "failure", "check"):
                result[text] = hex(value)
    return result


def replay(directory, arch, opt, name, inputs, mode, linkage):
    """Use the same architecture if runnable, otherwise the host C build."""
    host = {"AMD64": "x86_64", "arm64": "aarch64"}.get(
        platform.machine(), platform.machine())
    replay_arch = arch
    prefix = []
    if arch != host:
        emulator = shutil.which("qemu-" + arch)
        if emulator:
            prefix = [emulator]
            if linkage != "static":
                prefix += ["-L", "/usr/" + arch + "-linux-gnu"]
        else:
            replay_arch = host
    executable = directory / f"{replay_arch}-O{opt}-{name}-{linkage}"
    if not executable.exists():
        return "unavailable", replay_arch
    stdin = bytes(inputs["stdin"])
    argv = []
    if mode == "solve":
        memory = {int(address, 0): value for address, value in inputs["memory"].items()}
        stdin = bytes(memory[0x10000000 + i] for i in range(4))
        if name == "argv":
            argv = [stdin]
    elif name == "argv":
        argv = [bytes(inputs["argv"][1])]
    try:
        output = subprocess.run(prefix + [str(executable)] + argv, input=stdin,
                                capture_output=True, timeout=10)
    except (ValueError, subprocess.TimeoutExpired) as error:
        return str(error), replay_arch
    valid = output.returncode == 0 and output.stdout == b"success\n"
    return "passed" if valid else "wrong", replay_arch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", default="target/release/velk")
    parser.add_argument("--directory", type=Path, default=Path("target/crackmes"))
    parser.add_argument("--variants", nargs="+", default=["elf", "dynamic", "static"])
    parser.add_argument("--cases", nargs="+")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    names = args.cases or sorted(p.stem for p in Path("tests/data/crackmes").glob("*.c"))
    for arch in ("x86_64", "aarch64"):
        for opt in (0, 2):
            for name in names:
                for variant in args.variants:
                    path = args.directory / f"{arch}-O{opt}-{name}{'.elf' if variant == 'elf' else '-' + variant}"
                    if not path.exists():
                        continue
                    targets = symbols(path)
                    for mode in ("explore", "solve"):
                        options = {"stdin": 4}
                        command = [args.bin, "--" + mode, "main" if mode == "explore" else "check", "--json", "--cache", "off"]
                        if mode == "explore":
                            command += ["--find", targets["success"], "--avoid", targets["failure"]]
                            if name == "argv":
                                options = {"argv": [1, 4]}
                        else:
                            command += ["--returns", "eq:1"]
                            options = {"argumentValues": ["0x10000000"],
                                       "memory": [{"address": "0x10000000", "size": 4}]}
                            # String checks need a concrete terminator after the symbolic bytes.
                            # Initial unmapped bytes are zero, as in concrete emulation.
                        command += ["--symbolic-options", json.dumps(options), str(path)]
                        start = time.monotonic()
                        result = {"arch": arch, "opt": opt, "case": name, "variant": variant,
                                  "mode": mode, "options": options}
                        result["targets"] = ({"start": "main", "find": [targets["success"]],
                                              "avoid": [targets["failure"]]} if mode == "explore"
                                             else {"start": "check", "returns": {"eq": 1}})
                        try:
                            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                  start_new_session=True) as process:
                                try:
                                    stdout, stderr = process.communicate(timeout=args.timeout)
                                except subprocess.TimeoutExpired:
                                    try:
                                        os.killpg(process.pid, signal.SIGKILL)
                                    except ProcessLookupError:
                                        pass
                                    process.communicate()
                                    raise
                            report = json.loads(stdout) if stdout else {}
                            result.update(status="solved" if report.get("found") else "not solved",
                                          diagnostic=report.get("diagnostics", []) + [report.get(
                                              "reason", stderr.decode().strip() or
                                              f"process exited {process.returncode}")])
                            if report.get("found"):
                                replays = {}
                                for linkage in ("dynamic", "static"):
                                    replay_status, replay_arch = replay(args.directory, arch, opt, name, report["inputs"], mode, linkage)
                                    replays[linkage] = {"status": replay_status, "arch": replay_arch}
                                    if replay_status == "wrong":
                                        result["status"] = "wrong"
                                    elif replay_status != "passed" and result["status"] != "wrong":
                                        result["status"] = "unverified"
                                result["replay"] = replays
                                result["inputs"] = report["inputs"]
                        except subprocess.TimeoutExpired:
                            result.update(status="not solved", diagnostic=["evaluation timeout"])
                        except json.JSONDecodeError as error:
                            result.update(status="not solved", diagnostic=[f"invalid JSON report: {error}"])
                        result["seconds"] = round(time.monotonic() - start, 6)
                        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
