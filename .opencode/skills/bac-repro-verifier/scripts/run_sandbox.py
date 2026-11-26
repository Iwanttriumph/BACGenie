#!/usr/bin/env python3
"""Skill helper script: executes ONLY the deterministic Two-Container Flag-Gate sandbox
and writes `verifier_results/<CVE>/dynamic_run.json` for `bac-repro-verifier` auditing."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from verifier.config import DEFAULT_LOCAL_DELIVERABLES, DEFAULT_REMOTE_DELIVERABLES, DEFAULT_RESULTS_DIR
from verifier.reporting.report_builder import atomic_write_json
from verifier.sandbox.runner import run_two_container_batch


def main() -> int:
    ap = argparse.ArgumentParser(description="Run Two-Container Flag-Gate Sandbox for bac-repro-verifier skill")
    ap.add_argument("--cve", nargs="+", required=True, help="CVE ID(s) to run in isolated two-container sandbox")
    ap.add_argument("--ssh", type=str, default="", help="Optional remote Docker SSH host")
    ap.add_argument("--deliverables-dir", type=str, default="", help="Deliverables root directory")
    ap.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR, help="Output directory for dynamic_run.json")
    ap.add_argument("--concurrency", type=int, default=2)
    args = ap.parse_args()

    deliv = args.deliverables_dir.strip() or (
        DEFAULT_REMOTE_DELIVERABLES if args.ssh.strip() else str(DEFAULT_LOCAL_DELIVERABLES)
    )
    out_root = args.results_dir.resolve()

    def _on_res(rec: dict) -> None:
        cid = rec["cve_id"]
        out_file = out_root / cid / "dynamic_run.json"
        atomic_write_json(out_file, rec)
        print(f"[sandbox] {cid}: status={rec.get('status')} -> {out_file}", flush=True)

    run_two_container_batch(
        deliverables_dir=deliv,
        cves=args.cve,
        ssh_host=args.ssh.strip() or None,
        concurrency=args.concurrency,
        on_result=_on_res,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
