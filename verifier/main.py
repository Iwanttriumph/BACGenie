from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from verifier.agents.repro_auditor import audit_cve_reproduction
from verifier.config import (
    DEFAULT_BASE_URL,
    DEFAULT_BENCHMARK_FILE,
    DEFAULT_LOCAL_DELIVERABLES,
    DEFAULT_MODEL,
    DEFAULT_REMOTE_DELIVERABLES,
    DEFAULT_RESULTS_DIR,
    DEFAULT_SAMPLE_RATE,
    DEFAULT_SAMPLE_SEED,
    ROOT_DIR,
)
from verifier.reporting.report_builder import (
    atomic_write_json,
    atomic_write_text,
    render_oracle_markdown,
    write_global_reports,
)
from verifier.sandbox.runner import run_two_container_batch
from verifier.toolbox.llm_client import LLMClient, resolve_api_key


def _resolve_cached_source_dir(entry: Dict[str, Any], source_root: Optional[Path]) -> Optional[Path]:
    if source_root is None or not source_root.is_dir():
        return None
    cve_id = str(entry.get("cve") or "")
    project = str(entry.get("project") or "")
    ver = str(entry.get("version") or "")
    prefix_map = {
        "Lunary": f"Lunary_{ver}",
        "MobSF": f"MobSF_{ver}",
        "Nextcloud Server": f"Nextcloud_{ver}",
        "Mastodon": f"Mastodon_{ver}",
        "ZITADEL": f"ZITADEL_{ver}",
        "Autolab": f"Autolab_{ver}",
    }
    folder_name = prefix_map.get(project)
    if folder_name and (source_root / folder_name).is_dir():
        return (source_root / folder_name).resolve()
    if cve_id and (source_root / cve_id).is_dir():
        subs = [d for d in (source_root / cve_id).iterdir() if d.is_dir()]
        return subs[0].resolve() if len(subs) == 1 else (source_root / cve_id).resolve()
    return None


def load_benchmark_catalog(
    benchmark_file: Optional[Path],
    source_cache_dir: Optional[Path] = None,
) -> Dict[str, Tuple[Dict[str, Any], Optional[Path]]]:
    """Load CVE metadata from experiment/benchmark_23.json (and resolve optional local source cache)."""
    catalog: Dict[str, Tuple[Dict[str, Any], Optional[Path]]] = {}
    if benchmark_file is None or not benchmark_file.is_file():
        return catalog

    default_cache = source_cache_dir or (ROOT_DIR / "bench_cache" / "sources")
    entries = json.loads(benchmark_file.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        return catalog

    for item in entries:
        if not isinstance(item, dict) or not item.get("cve"):
            continue
        cve_id = str(item["cve"])
        normalized = {
            "cve_id": cve_id,
            "project": item.get("project", ""),
            "sw_version": item.get("version", ""),
            "cwes": item.get("cwe", []),
            "patch_commits": item.get("patch_commits", []),
            "description": item.get("description", ""),
            "sec_adv": [],
        }
        repo_path = _resolve_cached_source_dir(item, default_cache)
        catalog[cve_id] = (normalized, repo_path)
    return catalog


def build_record_entry(
    cve_id: str,
    bench_meta: Dict[str, Any],
    dyn_record: Dict[str, Any],
    report: Dict[str, Any],
) -> Dict[str, Any]:
    ora = (dyn_record.get("artifacts") or {}).get("oracle_contract") or {}
    tp_src = ((dyn_record.get("artifacts") or {}).get("tp_json") or {}).get("source_grounding") or {}
    proof = dyn_record.get("two_container_proof") or {}
    exp_run = proof.get("exploit_run") or {}
    noop_probe = proof.get("noop_probe") or {}
    return {
        "cve_id": cve_id,
        "app": dyn_record.get("app") or bench_meta.get("project"),
        "version": bench_meta.get("sw_version") or tp_src.get("vulnerable_version"),
        "oracle_type": ora.get("oracle_type"),
        "effect_type": ora.get("effect_type"),
        "dynamic_status": dyn_record.get("status"),
        "flag_captured": exp_run.get("flag_captured_in_attacker_stdout"),
        "noop_blocked": (not noop_probe["flag_captured"]) if "flag_captured" in noop_probe else None,
        "report": report,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Automated Two-Container Flag-Capture + Agentic Reproduction Verifier"
    )
    ap.add_argument(
        "--deliverables-dir",
        type=str,
        default="",
        help="Path to BACGenie deliverables directory (defaults to local ./deliverables/BACGenie, or remote path when --ssh is set)",
    )
    ap.add_argument(
        "--ssh",
        type=str,
        default="",
        help="Optional SSH target for remote Docker execution, e.g. ddk@10.176.46.12",
    )
    ap.add_argument(
        "--benchmark-file",
        type=Path,
        default=DEFAULT_BENCHMARK_FILE,
        help="Benchmark JSON metadata file (default: ./experiment/benchmark_23.json)",
    )
    ap.add_argument(
        "--source-cache-dir",
        type=Path,
        default=None,
        help="Optional local directory holding unpacked target source repositories",
    )
    ap.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Output directory for per-CVE evidence, verdicts, and summary reports",
    )
    ap.add_argument("--cve", nargs="*", default=[], help="Specific CVE ID(s) to verify (default: all 23 benchmark CVEs)")
    ap.add_argument("--concurrency", type=int, default=3, help="Parallel container stacks on Docker host")
    ap.add_argument("--reuse-dynamic", action="store_true", help="Reuse cached dynamic_run.json if present")
    ap.add_argument("--skip-dynamic", action="store_true", help="Collect deliverable code without starting containers")
    ap.add_argument("--overwrite", action="store_true", help="Re-run Agent audit even if verdict_report.json exists")
    ap.add_argument("--model", type=str, default=DEFAULT_MODEL, help="LLM model identifier")
    ap.add_argument("--base-url", type=str, default=DEFAULT_BASE_URL, help="OpenAI-compatible API base URL")
    ap.add_argument("--sample-rate", type=float, default=DEFAULT_SAMPLE_RATE, help="Spot-check sample rate for True verdicts")
    ap.add_argument("--sample-seed", type=int, default=DEFAULT_SAMPLE_SEED, help="Deterministic RNG seed for True sampling")
    return ap


def run_cli(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    deliverables_dir = args.deliverables_dir.strip()
    if not deliverables_dir:
        deliverables_dir = DEFAULT_REMOTE_DELIVERABLES if args.ssh.strip() else str(DEFAULT_LOCAL_DELIVERABLES)
    results_dir: Path = args.results_dir.resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    catalog = load_benchmark_catalog(args.benchmark_file, args.source_cache_dir)
    if args.cve:
        target_cves = sorted(set(args.cve))
    elif catalog:
        target_cves = sorted(catalog.keys())
    else:
        target_cves = []

    dyn_map: Dict[str, Dict[str, Any]] = {}
    need_dynamic: List[str] = []
    for cve in target_cves:
        cached_dyn = results_dir / cve / "dynamic_run.json"
        if args.reuse_dynamic and cached_dyn.exists():
            dyn_map[cve] = json.loads(cached_dyn.read_text(encoding="utf-8"))
        else:
            need_dynamic.append(cve)

    if need_dynamic or not target_cves:
        def _save_dyn(rec: Dict[str, Any]) -> None:
            cid = rec["cve_id"]
            atomic_write_json(results_dir / cid / "dynamic_run.json", rec)
            print(f"[sandbox] {cid}: status={rec.get('status')} ({rec.get('duration_sec', 0)}s)", flush=True)

        fetched = run_two_container_batch(
            deliverables_dir=deliverables_dir,
            cves=need_dynamic,
            ssh_host=args.ssh.strip() or None,
            concurrency=args.concurrency,
            skip_dynamic=args.skip_dynamic,
            on_result=_save_dyn,
        )
        dyn_map.update(fetched)
        if not target_cves:
            target_cves = sorted(dyn_map.keys())

    llm_client: Optional[LLMClient] = None
    all_records: List[Dict[str, Any]] = []

    for cve in target_cves:
        cve_out_dir = results_dir / cve
        verdict_path = cve_out_dir / "verdict_report.json"
        bench_meta, repo_path = catalog.get(cve, ({}, None))
        dyn_rec = dyn_map.get(cve) or {
            "cve_id": cve,
            "app": None,
            "status": "MISSING_DELIVERABLE",
            "reason": "No dynamic record found",
            "two_container_proof": None,
            "evidence": {},
            "artifacts": {},
        }

        if verdict_path.exists() and not args.overwrite:
            report = json.loads(verdict_path.read_text(encoding="utf-8"))
            print(f"[cached]  {cve}: verdict={report['verdict']}", flush=True)
            all_records.append(build_record_entry(cve, bench_meta, dyn_rec, report))
            continue

        if llm_client is None and dyn_rec.get("status") not in (
            "MISSING_DELIVERABLE", "ENV_ERROR", "STATIC_VIOLATION", "LEAK_DETECTED", "NOOP_CONTAMINATED"
        ):
            api_key = resolve_api_key()
            llm_client = LLMClient(api_key=api_key, model=args.model, base_url=args.base_url)

        audit_out = audit_cve_reproduction(
            cve_id=cve,
            bench_meta=bench_meta,
            dyn_record=dyn_rec,
            llm_client=llm_client,
            repo_path=repo_path,
        )
        report = audit_out["report"]
        atomic_write_json(cve_out_dir / "llm_trace.json", audit_out["llm_trace"])
        atomic_write_json(cve_out_dir / "source_audit.json", audit_out["source_audit_log"])
        atomic_write_text(cve_out_dir / "oracle_table.md", render_oracle_markdown(report))
        atomic_write_json(verdict_path, report)

        print(f"[auditor] {cve}: verdict={report['verdict']} ({report['human_review_policy']})", flush=True)
        all_records.append(build_record_entry(cve, bench_meta, dyn_rec, report))

    seen_cves = {r["cve_id"] for r in all_records}
    for sub_vp in sorted(results_dir.glob("CVE-*/verdict_report.json")):
        other_cve = sub_vp.parent.name
        if other_cve in seen_cves:
            continue
        try:
            other_rep = json.loads(sub_vp.read_text(encoding="utf-8"))
            other_dyn_path = sub_vp.parent / "dynamic_run.json"
            other_dyn = json.loads(other_dyn_path.read_text(encoding="utf-8")) if other_dyn_path.exists() else {}
            other_meta, _ = catalog.get(other_cve, ({}, None))
            all_records.append(build_record_entry(other_cve, other_meta, other_dyn, other_rep))
        except Exception:
            continue

    summary = write_global_reports(
        results_dir=results_dir,
        records=all_records,
        sample_rate=args.sample_rate,
        sample_seed=args.sample_seed,
    )
    vc = summary["verdict_counts"]
    print(
        f"\nDone. Total={summary['total_tasks']} | True={vc['True']} "
        f"(sampled={summary['review_queues']['true_sampled_for_spot_check']['count']}) | "
        f"False={vc['False']} | unknown={vc['unknown']} (mandatory=100%)\n"
        f"Summary written to: {results_dir / 'SUMMARY.md'}",
        flush=True,
    )
    return 0
