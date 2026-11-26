#!/usr/bin/env python3
"""Unified BACGenie End-to-End Pipeline Orchestrator.

Chains the complete 3-stage BACGenie workflow in one project:
  Stage 1 (`reproduce`)      : OpenCode Primary/Worker dynamic reproduction (TP + Oracle + Prep + Blind Client + Gate)
  Stage 2 (`bundle`)         : Standardized Harbor 0.22.0 deliverable packaging (`experiment/build_harbor_bundle.py`)
  Stage 3 (`verify`)         : Two-Container Flag-Capture + Source-Grounded Agent Verifier (`verifier/main.py`)

Composite stages:
  `post-reproduce`           : `bundle` -> `verify`
  `all`                      : `reproduce` -> `bundle` -> `verify`
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="BACGenie Unified Pipeline (Reproduce -> Bundle -> Verify)")
    ap.add_argument(
        "--stage",
        choices=["reproduce", "bundle", "verify", "post-reproduce", "all"],
        default="verify",
        help="Pipeline stage to execute (default: verify)",
    )
    ap.add_argument("--cve", nargs="*", default=[], help="Target CVE ID(s); omit to run full benchmark")
    ap.add_argument("--ssh", type=str, default="", help="Optional SSH Docker host for verify stage (e.g. ddk@10.176.46.12)")
    ap.add_argument(
        "--deliverables-dir",
        type=str,
        default="",
        help="Deliverables bundle directory (auto-resolved for local or --ssh if omitted)",
    )
    ap.add_argument(
        "--bench-input-dir",
        type=Path,
        default=REPO_ROOT / "bench_input",
        help="Ground-truth CVE-*.json directory (default: ./bench_input)",
    )
    ap.add_argument(
        "--verifier-results-dir",
        type=Path,
        default=REPO_ROOT / "verifier_results",
        help="Output directory for Verifier reports (default: ./verifier_results)",
    )
    ap.add_argument("--concurrency", type=int, default=3, help="Parallel workers for batch / container verification")
    ap.add_argument("--round", type=int, default=1, help="Experiment round index for batch reproduction")
    ap.add_argument("--timeout", type=int, default=2700, help="Per-CVE timeout (seconds) for reproduction")
    ap.add_argument("--skip-image-export", action="store_true", default=True, help="Skip exporting large .tar.gz images during bundle stage")
    ap.add_argument("--export-images", action="store_true", help="Export full Docker .tar.gz archives during bundle stage")
    ap.add_argument("--reuse-dynamic", action="store_true", help="Reuse cached dynamic_run.json in verify stage")
    ap.add_argument("--skip-dynamic", action="store_true", help="Run verify static/Agent audit without starting containers")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite existing cached stage outputs")
    ap.add_argument("--model", type=str, default="", help="Override LLM model name")
    ap.add_argument("--base-url", type=str, default="", help="Override OpenAI-compatible API base URL")
    ap.add_argument("--sample-rate", type=float, default=0.30, help="Stratified spot-check sample rate for True verdicts")
    return ap


def _run_subcmd(cmd: List[str]) -> int:
    print(f"[pipeline] exec: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT))
    return proc.returncode


def run_pipeline(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    py = sys.executable

    if args.stage in ("reproduce", "all"):
        if os.name == "nt" and not args.ssh:
            print("[pipeline] Note: OpenCode reproduction requires a Linux Docker host.", file=sys.stderr)
            return 2
        if len(args.cve) == 1 and (REPO_ROOT / "bacgenie_run.sh").exists() and os.name != "nt":
            cmd = ["bash", str(REPO_ROOT / "bacgenie_run.sh"), args.cve[0]]
            if args.model:
                cmd.append(args.model)
        else:
            cmd = [
                py,
                str(REPO_ROOT / "experiment" / "run_batch.py"),
                "--round", str(args.round),
                "--jobs", str(args.concurrency),
                "--timeout", str(args.timeout),
            ]
            if args.cve:
                cmd.extend(["--cves"] + args.cve)
        rc = _run_subcmd(cmd)
        if rc != 0:
            return rc
        if args.stage == "reproduce":
            return 0

    local_bundle_dir = REPO_ROOT / "deliverables" / "BACGenie"
    if args.stage in ("bundle", "post-reproduce", "all"):
        bundle_out = Path(args.deliverables_dir) if (args.deliverables_dir and not args.ssh) else local_bundle_dir
        cmd = [
            py,
            str(REPO_ROOT / "experiment" / "build_harbor_bundle.py"),
            "--out-bundle", str(bundle_out),
        ]
        if args.skip_image_export and not args.export_images:
            cmd.append("--skip-image-export")
        if args.cve:
            cmd.extend(["--cves"] + args.cve)
        rc = _run_subcmd(cmd)
        if rc != 0:
            return rc
        if args.stage == "bundle":
            return 0

    if args.stage in ("verify", "post-reproduce", "all"):
        from verifier.config import DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_REMOTE_DELIVERABLES
        from verifier.main import run_cli

        if args.deliverables_dir:
            deliv = args.deliverables_dir
        elif args.ssh:
            deliv = DEFAULT_REMOTE_DELIVERABLES
        else:
            deliv = str(local_bundle_dir)

        ver_argv: List[str] = [
            "--deliverables-dir", deliv,
            "--bench-input-dir", str(args.bench_input_dir),
            "--results-dir", str(args.verifier_results_dir),
            "--concurrency", str(args.concurrency),
            "--sample-rate", str(args.sample_rate),
            "--model", args.model or DEFAULT_MODEL,
            "--base-url", args.base_url or DEFAULT_BASE_URL,
        ]
        if args.ssh:
            ver_argv.extend(["--ssh", args.ssh])
        if args.cve:
            ver_argv.extend(["--cve"] + args.cve)
        if args.reuse_dynamic:
            ver_argv.append("--reuse-dynamic")
        if args.skip_dynamic:
            ver_argv.append("--skip-dynamic")
        if args.overwrite:
            ver_argv.append("--overwrite")
        return run_cli(ver_argv)

    return 0


if __name__ == "__main__":
    sys.exit(run_pipeline())
