from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema

from verifier.config import MAX_TOOL_ROUNDS, SKILL_MD_PATH, SKILL_REFS_DIR
from verifier.toolbox.llm_client import parse_json_response, run_validated_json_stage
from verifier.toolbox.source_tools import ReadOnlySourceWorkspace

VERDICT_SCHEMA = json.loads((SKILL_REFS_DIR / "verdict.schema.json").read_text(encoding="utf-8"))
SYSTEM_PROMPT = (
    (SKILL_MD_PATH.read_text(encoding="utf-8") + "\n\n---\n\n" if SKILL_MD_PATH.exists() else "")
    + (SKILL_REFS_DIR / "auditor_prompt.md").read_text(encoding="utf-8")
)
REPAIR_TEMPLATE = (SKILL_REFS_DIR / "repair_prompt.md").read_text(encoding="utf-8")


def _default_oracle_table(note: str) -> List[Dict[str, str]]:
    return [
        {"stage": "数据准备", "action_or_api": note, "response_or_state": "N/A"},
        {"stage": "前置检查 (PRE)", "action_or_api": note, "response_or_state": "N/A"},
        {"stage": "目标触发 (ACTION)", "action_or_api": note, "response_or_state": "N/A"},
        {"stage": "后置验证 (POST)", "action_or_api": note, "response_or_state": "N/A"},
    ]


def validate_verdict_payload(data: Any, expected_cve: str, has_dynamic_pass: Optional[bool]) -> None:
    jsonschema.validate(instance=data, schema=VERDICT_SCHEMA)
    if data["cve_id"] != expected_cve:
        raise ValueError(f"cve_id mismatch: expected {expected_cve}, got {data['cve_id']}")

    verdict = data["verdict"]
    policy = data["human_review_policy"]
    c1 = data["criteria"]["criterion_1_flag_proof"]["status"]
    c2 = data["criteria"]["criterion_2_workflow_integrity"]["status"]
    unpriv = data["criteria"]["criterion_2_workflow_integrity"]["caller_is_unprivileged"]

    if verdict == "True":
        if policy != "sample_audit":
            raise ValueError("verdict='True' requires human_review_policy='sample_audit'")
        if c1 != "PASS" or c2 != "PASS" or unpriv is not True:
            raise ValueError("verdict='True' requires both criteria PASS and caller_is_unprivileged=true")
        if has_dynamic_pass is not True:
            raise ValueError("verdict='True' is forbidden when dynamic two-container flag proof is missing or failed")
    elif verdict == "False":
        if policy != "rejected":
            raise ValueError("verdict='False' requires human_review_policy='rejected'")
        if c1 != "FAIL" and c2 != "FAIL":
            raise ValueError("verdict='False' requires at least one criterion to be FAIL")
    elif verdict == "unknown":
        if policy != "mandatory_manual_audit":
            raise ValueError("verdict='unknown' requires human_review_policy='mandatory_manual_audit'")
        if c1 == "FAIL" or c2 == "FAIL":
            raise ValueError("verdict='unknown' cannot have a definitive FAIL criterion (use verdict='False')")
        if c1 == "PASS" and c2 == "PASS" and unpriv is True and has_dynamic_pass is True:
            raise ValueError("Both criteria PASS with valid dynamic proof should be verdict='True', not 'unknown'")


def build_deterministic_shortcircuit(cve_id: str, dyn_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Deterministic hard gates before invoking LLM when deliverables are missing or demonstrably broken."""
    status = dyn_record.get("status")
    reason = str(dyn_record.get("reason") or status)

    if status == "MISSING_DELIVERABLE":
        return {
            "cve_id": cve_id,
            "verdict": "unknown",
            "human_review_policy": "mandatory_manual_audit",
            "summary_reason": f"未找到已构建的交付包产物（{reason}），需人工核查靶场构建或补跑状态。",
            "criteria": {
                "criterion_1_flag_proof": {"status": "UNKNOWN", "evidence": reason},
                "criterion_2_workflow_integrity": {
                    "status": "UNKNOWN",
                    "caller_is_unprivileged": None,
                    "evidence": "缺少 prep.py / verify.py / exploit.py 交付物，无法自动核验。",
                },
            },
            "dimension_checks": {
                "credential_and_secret_isolation": {"status": "UNKNOWN", "evidence": "产物缺失"},
                "caller_low_privilege_verified": {"status": "UNKNOWN", "evidence": "产物缺失"},
                "positive_and_negative_controls": {"status": "UNKNOWN", "evidence": "产物缺失"},
                "authoritative_post_observation": {"status": "UNKNOWN", "evidence": "产物缺失"},
                "setup_and_patch_alignment": {"status": "UNKNOWN", "evidence": "产物缺失"},
            },
            "oracle_table": _default_oracle_table("交付产物缺失（未构建靶场）"),
        }

    if status == "ENV_ERROR":
        return {
            "cve_id": cve_id,
            "verdict": "unknown",
            "human_review_policy": "mandatory_manual_audit",
            "summary_reason": f"双容器环境启动或健康检查异常（{reason}），无法完成动态裁决，需人工核验。",
            "criteria": {
                "criterion_1_flag_proof": {"status": "UNKNOWN", "evidence": reason},
                "criterion_2_workflow_integrity": {
                    "status": "UNKNOWN",
                    "caller_is_unprivileged": None,
                    "evidence": "容器环境未就绪，动态证据缺失。",
                },
            },
            "dimension_checks": {
                "credential_and_secret_isolation": {"status": "UNKNOWN", "evidence": reason},
                "caller_low_privilege_verified": {"status": "UNKNOWN", "evidence": reason},
                "positive_and_negative_controls": {"status": "UNKNOWN", "evidence": reason},
                "authoritative_post_observation": {"status": "UNKNOWN", "evidence": reason},
                "setup_and_patch_alignment": {"status": "UNKNOWN", "evidence": reason},
            },
            "oracle_table": _default_oracle_table("容器环境启动异常"),
        }

    if status in ("STATIC_VIOLATION", "LEAK_DETECTED", "NOOP_CONTAMINATED"):
        c1_status = "FAIL" if status == "NOOP_CONTAMINATED" else "UNKNOWN"
        return {
            "cve_id": cve_id,
            "verdict": "False",
            "human_review_policy": "rejected",
            "summary_reason": f"确定性反作弊门禁拦截（{status}）：{reason}",
            "criteria": {
                "criterion_1_flag_proof": {"status": c1_status, "evidence": reason},
                "criterion_2_workflow_integrity": {
                    "status": "FAIL",
                    "caller_is_unprivileged": False if status == "LEAK_DETECTED" else None,
                    "evidence": reason,
                },
            },
            "dimension_checks": {
                "credential_and_secret_isolation": {
                    "status": "FAIL" if status in ("STATIC_VIOLATION", "LEAK_DETECTED") else "PASS",
                    "evidence": reason,
                },
                "caller_low_privilege_verified": {"status": "UNKNOWN", "evidence": "已被前置门禁拦截"},
                "positive_and_negative_controls": {
                    "status": "FAIL" if status == "NOOP_CONTAMINATED" else "UNKNOWN",
                    "evidence": reason,
                },
                "authoritative_post_observation": {"status": "UNKNOWN", "evidence": "已被前置门禁拦截"},
                "setup_and_patch_alignment": {"status": "UNKNOWN", "evidence": "已被前置门禁拦截"},
            },
            "oracle_table": _default_oracle_table(f"确定性门禁拦截: {status}"),
        }

    return None


def _assemble_user_context(
    cve_id: str,
    bench_meta: Dict[str, Any],
    dyn_record: Dict[str, Any],
    source_ws: ReadOnlySourceWorkspace,
) -> str:
    artifacts = dyn_record.get("artifacts") or {}
    proof = dyn_record.get("two_container_proof") or {}
    evidence = dyn_record.get("evidence") or {}

    patches = []
    for item in bench_meta.get("patch_commits") or []:
        if isinstance(item, dict):
            patches.append(f"URL: {item.get('url', '')}\n{str(item.get('content', ''))[:12000]}")
        else:
            patches.append(str(item)[:4000])

    advisories = []
    for adv in bench_meta.get("sec_adv") or []:
        if isinstance(adv, dict):
            advisories.append(str(adv.get("content", ""))[:5000])

    sections = [
        f"<cve_ground_truth>\nCVE_ID: {cve_id}\nVersion: {bench_meta.get('sw_version', '')}\n"
        f"CWEs: {json.dumps(bench_meta.get('cwes', []), ensure_ascii=False)}\n"
        f"Description: {bench_meta.get('description', '')}\n"
        f"Source_Repo_Available: {source_ws.available}\n"
        f"Advisory_Excerpt:\n{chr(10).join(advisories)[:6000]}\n"
        f"Official_Patch_Diff:\n{chr(10).join(patches)[:14000]}\n</cve_ground_truth>",
        f"<two_container_execution_summary>\nStatus: {dyn_record.get('status')}\n"
        f"Reason: {dyn_record.get('reason')}\n"
        f"Proof:\n{json.dumps(proof, ensure_ascii=False, indent=2)}\n"
        f"Sanitized_Public_Input:\n{json.dumps(evidence.get('public_attacker_sanitized'), ensure_ascii=False, indent=2)}\n"
        f"Before_Evidence:\n{json.dumps(evidence.get('before_evidence'), ensure_ascii=False, indent=2)[:8000]}\n"
        f"Action_Trace:\n{json.dumps(evidence.get('attack_trace'), ensure_ascii=False, indent=2)[:8000]}\n"
        f"After_Evidence:\n{json.dumps(evidence.get('after_evidence'), ensure_ascii=False, indent=2)[:6000]}\n"
        f"</two_container_execution_summary>",
        f"<deliverable_code>\n"
        f"--- 01_tp.json ---\n{json.dumps(artifacts.get('tp_json'), ensure_ascii=False, indent=2)}\n"
        f"--- 02_oracle_contract.json ---\n{json.dumps(artifacts.get('oracle_contract'), ensure_ascii=False, indent=2)}\n"
        f"--- prep.py ---\n{str(artifacts.get('prep_code', ''))[:14000]}\n"
        f"--- verify.py ---\n{str(artifacts.get('verify_code', ''))[:14000]}\n"
        f"--- client script (exploit.py) ---\n{str(artifacts.get('exploit_code', ''))[:12000]}\n"
        f"</deliverable_code>",
        "请结合官方补丁（必要时先调用只读源码检索 `tool_requests` 核实角色权限矩阵与路由鉴权逻辑）、双容器动态 Flag 验证结果以及产物代码，"
        "严格核验【标准1：动态效果 Flag 证明】与【标准2：流程完整且调用方绝非本就有权限的用户】，输出最终裁决 JSON。",
    ]
    return "\n\n".join(sections)


def audit_cve_reproduction(
    cve_id: str,
    bench_meta: Dict[str, Any],
    dyn_record: Dict[str, Any],
    llm_client: Any,
    repo_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run deterministic gates + Source-Grounded Agent Auditor for a single CVE."""
    short = build_deterministic_shortcircuit(cve_id, dyn_record)
    if short is not None:
        return {
            "report": short,
            "llm_trace": [],
            "source_audit_log": [],
            "short_circuited": True,
        }

    proof = dyn_record.get("two_container_proof") or {}
    exp_run = proof.get("exploit_run") or {}
    noop_probe = proof.get("noop_probe") or {}
    status = dyn_record.get("status")

    if status == "COMPLETED":
        has_dynamic_pass: Optional[bool] = (
            bool(exp_run.get("flag_captured_in_attacker_stdout"))
            and bool(exp_run.get("flag_granted_by_gate"))
            and not bool(noop_probe.get("flag_captured"))
        )
    elif status == "PRE_CHECK_FAILED":
        has_dynamic_pass = False
    else:
        # e.g. STATIC_ONLY mode: cannot issue 'True' without live dynamic flag proof
        has_dynamic_pass = None

    source_ws = ReadOnlySourceWorkspace(repo_path)
    user_prompt = _assemble_user_context(cve_id, bench_meta, dyn_record, source_ws)
    messages: List[Dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    llm_trace: List[Dict[str, Any]] = []

    # Optional read-only source navigation loop
    if source_ws.available:
        for round_idx in range(MAX_TOOL_ROUNDS):
            raw = llm_client.complete(messages, stage=f"tool_or_audit_r{round_idx + 1}")
            llm_trace.append({"stage": f"round_{round_idx + 1}", "content": raw})
            parsed = parse_json_response(raw)
            if isinstance(parsed, dict) and isinstance(parsed.get("tool_requests"), list) and parsed["tool_requests"]:
                tool_out = source_ws.execute_ops(parsed["tool_requests"])
                messages.append({"role": "assistant", "content": raw})
                messages.append({
                    "role": "user",
                    "content": (
                        "源码只读检索结果：\n"
                        + json.dumps(tool_out, ensure_ascii=False, indent=2)
                        + "\n若证据已充分，请直接输出最终裁决 JSON；若仍需补充读取，可继续发送 `tool_requests`。"
                    ),
                })
                continue
            # Model produced final answer candidate directly; validate or repair
            try:
                validate_verdict_payload(parsed, cve_id, has_dynamic_pass)
                return {
                    "report": parsed,
                    "llm_trace": llm_trace,
                    "source_audit_log": source_ws.audit_log,
                    "short_circuited": False,
                }
            except Exception as exc:
                messages.append({"role": "assistant", "content": raw})
                messages.append({
                    "role": "user",
                    "content": REPAIR_TEMPLATE.replace("{{error}}", str(exc)),
                })
                break

    def _validator(candidate: Any) -> None:
        validate_verdict_payload(candidate, cve_id, has_dynamic_pass)

    def _repair(err: Exception, _raw: str) -> str:
        return REPAIR_TEMPLATE.replace("{{error}}", str(err))

    final_report = run_validated_json_stage(
        client=llm_client,
        messages=messages,
        validator=_validator,
        stage="final_verdict",
        trace_log=llm_trace,
        max_repairs=2,
        repair_prompt_builder=_repair,
    )
    return {
        "report": final_report,
        "llm_trace": llm_trace,
        "source_audit_log": source_ws.audit_log,
        "short_circuited": False,
    }
