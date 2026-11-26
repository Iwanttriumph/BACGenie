from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from verifier.sandbox import remote_payload

PAYLOAD_PATH = Path(remote_payload.__file__).resolve()


def run_two_container_batch(
    deliverables_dir: str,
    cves: List[str],
    ssh_host: Optional[str] = None,
    concurrency: int = 3,
    skip_dynamic: bool = False,
    on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Execute the Two-Container Flag-Capture engine locally or over SSH.

    Streams per-CVE JSON records (`BACVER_RESULT <json>`) so results can be
    persisted incrementally as each container stack completes.
    """
    cfg = {
        "deliverables_dir": deliverables_dir,
        "cves": cves,
        "concurrency": max(1, concurrency),
        "skip_dynamic": skip_dynamic,
    }

    if ssh_host:
        script_src = PAYLOAD_PATH.read_text(encoding="utf-8").replace("\r\n", "\n")
        # Upload payload to a clean temporary script on remote host, then pipe JSON config via stdin
        remote_cmd = (
            "tmp_py=$(mktemp /tmp/bacver_engine_XXXXXX.py) && "
            "trap 'rm -f \"$tmp_py\"' EXIT && "
            "cat << 'BACVER_EOF_PY' > \"$tmp_py\"\n"
            + script_src
            + "\nBACVER_EOF_PY\n"
            "python3 \"$tmp_py\" --config-stdin"
        )
        # Wait: stdin cannot feed BOTH heredoc and python3 stdin unless bash -c holds the script or we embed cfg!
        # Embedding json cfg directly inside a tiny wrapper avoids stdin multiplexing completely!
        cfg_json = json.dumps(cfg, ensure_ascii=False)
        bootstrap = (
            script_src
            + "\n\n# --- Embedded Invocation ---\n"
            + f"_EMBEDDED_CFG = json.loads({cfg_json!r})\n"
            + "if __name__ == '__main__':\n"
            + "    pass\n"
        )
        # Replace bottom entrypoint cleanly so python3 - reads script from stdin with zero quoting issues!
        marker = 'if __name__ == "__main__":\n    sys.exit(main())'
        invoke_block = (
            "if __name__ == '__main__':\n"
            f"    _cfg = json.loads({cfg_json!r})\n"
            "    import io\n"
            "    sys.stdin = io.StringIO(json.dumps(_cfg))\n"
            "    sys.argv = ['remote_payload.py', '--config-stdin']\n"
            "    sys.exit(main())\n"
        )
        if marker not in script_src:
            raise RuntimeError("Could not locate entrypoint marker in remote_payload.py")
        head, tail = script_src.rsplit(marker, 1)
        stdin_payload = head + invoke_block + tail
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=30",
            ssh_host,
            "python3 -",
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdin is not None
        proc.stdin.write(stdin_payload)
        proc.stdin.close()
    else:
        cmd = [sys.executable, str(PAYLOAD_PATH), "--config-stdin"]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(cfg, ensure_ascii=False))
        proc.stdin.close()

    results: Dict[str, Dict[str, Any]] = {}
    assert proc.stdout is not None
    for raw_line in proc.stdout:
        line = raw_line.strip()
        if line.startswith("BACVER_RESULT "):
            payload = json.loads(line[len("BACVER_RESULT "):])
            cve_id = payload["cve_id"]
            results[cve_id] = payload
            if on_result is not None:
                on_result(payload)

    stderr_text = proc.stderr.read() if proc.stderr is not None else ""
    rc = proc.wait()
    if rc != 0 and not results:
        raise RuntimeError(f"Two-container runner exited with code {rc}: {stderr_text[-2000:]}")
    return results
