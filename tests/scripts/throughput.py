"""Measure all functions through one script session: uv run python tests/scripts/throughput.py BIN FIXTURE."""

import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time


binary, fixture = sys.argv[1:]
with tempfile.TemporaryDirectory(dir="target") as directory:
    script = Path(directory) / "all.js"
    script.write_text(
        f"const binary = velk.open({json.dumps(fixture)});\n"
        "const functions = binary.functions();\n"
        "let failed = 0;\n"
        "for (const result of binary.decompile(functions)) {\n"
        "  console.log(result.addr);\n"
        "  if (result.error === null) console.log(result.code);\n"
        "  else { failed++; console.log(result.error); }\n"
        "}\n"
        "console.log(JSON.stringify({functions: functions.length, failed}));\n"
    )
    with tempfile.TemporaryFile() as output:
        start = time.perf_counter()
        subprocess.run([binary, "--run", str(script)], stdout=output, check=True)
        elapsed = time.perf_counter() - start
        rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if sys.platform != "darwin":
            rss *= 1024
        output.seek(0)
        digest = hashlib.file_digest(output, "sha256").hexdigest()
        output.seek(0)
        summary = b""
        for line in output:
            summary = line
        result = json.loads(summary)
        result.update(wall_seconds=round(elapsed, 3), peak_rss_bytes=rss, sha256=digest)
        print(json.dumps(result))
