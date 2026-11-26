from __future__ import annotations

import csv
import json
import math
import os
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from verifier.config import DEFAULT_SAMPLE_RATE, DEFAULT_SAMPLE_SEED, MIN_TRUE_SAMPLES


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def atomic_write_json(path: Path, obj: Any) -> None:
    atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def render_oracle_markdown(report: Dict[str, Any]) -> str:
    lines = [
        f"## {report['cve_id']} — Verdict: `{report['verdict']}` (`{report['human_review_policy']}`)",
        "",
        f"- **Summary**: {report['summary_reason']}",
        f"- **Criterion 1 (Flag Proof)**: `{report['criteria']['criterion_1_flag_proof']['status']}` — {report['criteria']['criterion_1_flag_proof']['evidence']}",
        f"- **Criterion 2 (Workflow Integrity)**: `{report['criteria']['criterion_2_workflow_integrity']['status']}` "
        f"(`caller_is_unprivileged={report['criteria']['criterion_2_workflow_integrity']['caller_is_unprivileged']}`) — "
        f"{report['criteria']['criterion_2_workflow_integrity']['evidence']}",
        "",
        "| 阶段 | 操作 / 请求接口 | 返回值 / 状态核验 |",
        "| :--- | :--- | :--- |",
    ]
    for row in report.get("oracle_table") or []:
        st = str(row.get("stage", "")).replace("|", "\\|").replace("\n", "<br>")
        act = str(row.get("action_or_api", "")).replace("|", "\\|").replace("\n", "<br>")
        rsp = str(row.get("response_or_state", "")).replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {st} | {act} | {rsp} |")
    lines.append("")
    return "\n".join(lines)


def select_stratified_true_samples(
    records: List[Dict[str, Any]],
    sample_rate: float = DEFAULT_SAMPLE_RATE,
    min_samples: int = MIN_TRUE_SAMPLES,
    seed: int = DEFAULT_SAMPLE_SEED,
) -> List[str]:
    """Stratified random sampling over `True` items across `(app, oracle_type, effect_type)`."""
    true_items = [r for r in records if r["report"]["verdict"] == "True"]
    if not true_items:
        return []

    target_k = min(len(true_items), max(min_samples, math.ceil(len(true_items) * sample_rate)))
    rng = random.Random(seed)

    strata: Dict[str, List[str]] = defaultdict(list)
    for rec in sorted(true_items, key=lambda x: x["cve_id"]):
        app = rec.get("app") or "UnknownApp"
        ora = rec.get("oracle_type") or "O?"
        eff = rec.get("effect_type") or "E?"
        strata[f"{app}:{ora}:{eff}"].append(rec["cve_id"])

    for bucket in strata.values():
        rng.shuffle(bucket)

    selected: List[str] = []
    # Pass 1: pick 1 from rare/distinct strata first (smallest strata first so multi-app & O2 get covered)
    ordered_keys = sorted(strata.keys(), key=lambda k: (len(strata[k]), k))
    for key in ordered_keys:
        if len(selected) >= target_k:
            break
        if strata[key]:
            selected.append(strata[key].pop(0))

    # Pass 2: fill remaining quota uniformly from leftover pool
    leftovers = [cve for key in ordered_keys for cve in strata[key]]
    rng.shuffle(leftovers)
    while len(selected) < target_k and leftovers:
        selected.append(leftovers.pop(0))

    return sorted(selected)


def write_global_reports(
    results_dir: Path,
    records: List[Dict[str, Any]],
    sample_rate: float = DEFAULT_SAMPLE_RATE,
    sample_seed: int = DEFAULT_SAMPLE_SEED,
) -> Dict[str, Any]:
    ordered = sorted(records, key=lambda x: x["cve_id"])
    counts = {"True": 0, "False": 0, "unknown": 0}
    for r in ordered:
        v = r["report"]["verdict"]
        counts[v] = counts.get(v, 0) + 1

    sampled_true = select_stratified_true_samples(
        ordered, sample_rate=sample_rate, seed=sample_seed
    )
    mandatory_unknown = [r["cve_id"] for r in ordered if r["report"]["verdict"] == "unknown"]
    rejected_false = [r["cve_id"] for r in ordered if r["report"]["verdict"] == "False"]

    summary_payload = {
        "total_tasks": len(ordered),
        "verdict_counts": counts,
        "review_queues": {
            "true_sampled_for_spot_check": {
                "policy": "大多数为 True，按分层随机抽样进行人工核验",
                "sample_rate": sample_rate,
                "sample_seed": sample_seed,
                "count": len(sampled_true),
                "cves": sampled_true,
            },
            "unknown_mandatory_manual_review": {
                "policy": "unknown 样本 100% 逐条人工核验",
                "count": len(mandatory_unknown),
                "cves": mandatory_unknown,
            },
            "false_rejected": {
                "policy": "False 样本（未取得有效动态标识或违背低权限完整流程）",
                "count": len(rejected_false),
                "cves": rejected_false,
            },
        },
        "tasks": [
            {
                "cve_id": r["cve_id"],
                "app": r.get("app"),
                "version": r.get("version"),
                "oracle_type": r.get("oracle_type"),
                "effect_type": r.get("effect_type"),
                "dynamic_status": r.get("dynamic_status"),
                "flag_captured": r.get("flag_captured"),
                "noop_blocked": r.get("noop_blocked"),
                "verdict": r["report"]["verdict"],
                "human_review_policy": r["report"]["human_review_policy"],
                "selected_for_human_review": (
                    r["cve_id"] in sampled_true or r["report"]["verdict"] == "unknown"
                ),
                "criterion_1_status": r["report"]["criteria"]["criterion_1_flag_proof"]["status"],
                "criterion_2_status": r["report"]["criteria"]["criterion_2_workflow_integrity"]["status"],
                "caller_is_unprivileged": r["report"]["criteria"]["criterion_2_workflow_integrity"]["caller_is_unprivileged"],
                "summary_reason": r["report"]["summary_reason"],
            }
            for r in ordered
        ],
    }

    atomic_write_json(results_dir / "summary.json", summary_payload)

    # Write CSV summary
    csv_path = results_dir / "summary.csv"
    csv_tmp = csv_path.with_suffix(".csv.tmp")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "cve_id", "app", "version", "oracle_type", "effect_type",
        "dynamic_status", "flag_captured", "noop_blocked",
        "verdict", "human_review_policy", "selected_for_human_review",
        "criterion_1_status", "criterion_2_status", "caller_is_unprivileged",
        "summary_reason",
    ]
    with open(csv_tmp, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary_payload["tasks"]:
            writer.writerow(row)
    os.replace(csv_tmp, csv_path)

    # Write Markdown summary
    md_lines = [
        "# 复现结果自动化核验报告（Two-Container Flag Gate + Agent Auditor）",
        "",
        "## 1. 总体分布与人工复核队列",
        "",
        f"- **总任务数**：`{len(ordered)}`",
        f"- **`True`（双标准均通过，按分层随机抽样人工核验）**：`{counts['True']}`（本次抽样 `{len(sampled_true)}` 条：`{', '.join(sampled_true) or '无'}`）",
        f"- **`unknown`（证据缺口或未构建，100% 逐条人工核验）**：`{counts['unknown']}`（`{', '.join(mandatory_unknown) or '无'}`）",
        f"- **`False`（未通过动态标识或违背无权限流程完整性）**：`{counts['False']}`（`{', '.join(rejected_false) or '无'}`）",
        "",
        "## 2. 逐题判定总表",
        "",
        "| CVE | 应用与版本 | 类型 | 双容器状态 | Flag捕获 | No-Op拦截 | 标准1(Flag) | 标准2(低权限完整流) | 最终裁决 | 人工核验安排 | 核心结论 |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for row in summary_payload["tasks"]:
        app_ver = f"{row['app'] or '-'} {row['version'] or ''}".strip()
        typ = f"{row['oracle_type'] or '-'} / {row['effect_type'] or '-'}"
        review_tag = (
            "必审 (unknown)" if row["verdict"] == "unknown"
            else ("抽中核验" if row["cve_id"] in sampled_true else ("免抽" if row["verdict"] == "True" else "剔除/复盘"))
        )
        reason_clean = str(row["summary_reason"]).replace("|", "\\|").replace("\n", " ")
        md_lines.append(
            f"| `{row['cve_id']}` | {app_ver} | `{typ}` | `{row['dynamic_status']}` | "
            f"`{row['flag_captured']}` | `{row['noop_blocked']}` | `{row['criterion_1_status']}` | "
            f"`{row['criterion_2_status']}` | **`{row['verdict']}`** | {review_tag} | {reason_clean} |"
        )

    md_lines.extend([
        "",
        "## 3. 各题四阶段 Oracle 与证据明细",
        "",
    ])
    for r in ordered:
        md_lines.append(render_oracle_markdown(r["report"]))

    atomic_write_text(results_dir / "SUMMARY.md", "\n".join(md_lines))
    return summary_payload
