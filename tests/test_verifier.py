from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from verifier.agents.repro_auditor import (
    audit_cve_reproduction,
    build_deterministic_shortcircuit,
    validate_verdict_payload,
)
from verifier.reporting.report_builder import select_stratified_true_samples, write_global_reports
from verifier.sandbox.remote_payload import (
    audit_exploit_ast,
    build_isolation_compose_yaml,
    parse_test_sh_env,
    sanitize_and_compact_trace,
    sanitize_public_input,
)
from verifier.toolbox.source_tools import ReadOnlySourceWorkspace


class FakeLLMClient:
    def __init__(self, responses: List[Dict[str, Any]]) -> None:
        self._responses = [json.dumps(r, ensure_ascii=False) for r in responses]
        self.calls: List[Dict[str, Any]] = []

    def complete(self, messages: List[Dict[str, str]], stage: str = "audit") -> str:
        self.calls.append({"stage": stage, "messages_len": len(messages)})
        if not self._responses:
            raise AssertionError("FakeLLMClient ran out of scripted responses")
        return self._responses.pop(0)


def _sample_oracle_table() -> List[Dict[str, str]]:
    return [
        {"stage": "数据准备", "action_or_api": "POST /auth/signup 创建独立低权限账号", "response_or_state": "200 OK，未暴露高权限凭据"},
        {"stage": "前置检查 (PRE)", "action_or_api": "GET /v1/users/me + 负控 GET /v1/templates/14", "response_or_state": "role=viewer，负控返回 404 并纳入断言"},
        {"stage": "目标触发 (ACTION)", "action_or_api": "隔离容器请求目标接口并提交轨迹至 flag-gate", "response_or_state": "200 OK，捕获动态 FLAG"},
        {"stage": "后置验证 (POST)", "action_or_api": "独立观察者回读目标状态", "response_or_state": "200 OK，动态随机标识一致且通道健康"},
    ]


def _make_valid_verdict(cve_id: str, verdict: str = "True") -> Dict[str, Any]:
    if verdict == "True":
        return {
            "cve_id": cve_id,
            "verdict": "True",
            "human_review_policy": "sample_audit",
            "summary_reason": "双容器隔离捕获动态 Flag，且源码核实调用方确属无权限主体，五维控制闭环。",
            "criteria": {
                "criterion_1_flag_proof": {"status": "PASS", "evidence": "No-Op 未获 Flag，隔离容器实测捕获当轮 FLAG"},
                "criterion_2_workflow_integrity": {
                    "status": "PASS",
                    "caller_is_unprivileged": True,
                    "evidence": "prep.py 仅向客户端提供低权限凭据，before/after 独立断言完备",
                },
            },
            "dimension_checks": {
                "credential_and_secret_isolation": {"status": "PASS", "evidence": "public_attacker.json 无秘密泄漏"},
                "caller_low_privilege_verified": {"status": "PASS", "evidence": "verify.py:85 核验受限身份"},
                "positive_and_negative_controls": {"status": "PASS", "evidence": "verify.py:110 正负控均断言"},
                "authoritative_post_observation": {"status": "PASS", "evidence": "verify.py:165 独立回读"},
                "setup_and_patch_alignment": {"status": "PASS", "evidence": "与官方补丁鉴权条件严格一致"},
            },
            "oracle_table": _sample_oracle_table(),
        }
    if verdict == "False":
        return {
            "cve_id": cve_id,
            "verdict": "False",
            "human_review_policy": "rejected",
            "summary_reason": "调用方被赋予了本来就拥有 settings:update 权限的 admin 角色，属于有权限主体直接读取。",
            "criteria": {
                "criterion_1_flag_proof": {"status": "PASS", "evidence": "捕获了 Flag"},
                "criterion_2_workflow_integrity": {
                    "status": "FAIL",
                    "caller_is_unprivileged": False,
                    "evidence": "roles.ts 显示 admin 默认具备 settings:update 权限",
                },
            },
            "dimension_checks": {
                "credential_and_secret_isolation": {"status": "PASS", "evidence": "无跨文件泄漏"},
                "caller_low_privilege_verified": {"status": "FAIL", "evidence": "admin 本就具备合法权限"},
                "positive_and_negative_controls": {"status": "FAIL", "evidence": "缺少针对该角色的合法拒绝基线"},
                "authoritative_post_observation": {"status": "PASS", "evidence": "独立回读正常"},
                "setup_and_patch_alignment": {"status": "FAIL", "evidence": "角色选择与补丁修复边界不符"},
            },
            "oracle_table": _sample_oracle_table(),
        }
    return {
        "cve_id": cve_id,
        "verdict": "unknown",
        "human_review_policy": "mandatory_manual_audit",
        "summary_reason": "动态拿到 Flag，但前置数据通过直接 SQL 写入且未覆盖业务前置约束校验，需人工复核。",
        "criteria": {
            "criterion_1_flag_proof": {"status": "PASS", "evidence": "隔离运行拿到 Flag"},
            "criterion_2_workflow_integrity": {
                "status": "UNKNOWN",
                "caller_is_unprivileged": True,
                "evidence": "prep.py 直接写库构造状态，缺少 API 层前置校验闭环",
            },
        },
        "dimension_checks": {
            "credential_and_secret_isolation": {"status": "PASS", "evidence": "隔离正常"},
            "caller_low_privilege_verified": {"status": "PASS", "evidence": "低权限角色"},
            "positive_and_negative_controls": {"status": "UNKNOWN", "evidence": "负控覆盖不完整"},
            "authoritative_post_observation": {"status": "PASS", "evidence": "独立回读"},
            "setup_and_patch_alignment": {"status": "UNKNOWN", "evidence": "SQL 直插需人工核对"},
        },
        "oracle_table": _sample_oracle_table(),
    }


def _completed_dyn_record(cve_id: str, flag_ok: bool = True, noop_captured: bool = False) -> Dict[str, Any]:
    return {
        "cve_id": cve_id,
        "app": "Lunary",
        "status": "NOOP_CONTAMINATED" if noop_captured else "COMPLETED",
        "reason": "Pre-contaminated" if noop_captured else "All checks verified",
        "two_container_proof": {
            "victim_service": "api",
            "isolation_checks": {
                "running_uid": 65534,
                "db_5432_unreachable": True,
                "private_mounts_absent": True,
            },
            "noop_probe": {"flag_captured": noop_captured, "gate_verdict": "PROVEN" if noop_captured else "NOT_OBSERVED"},
            "exploit_run": {
                "flag_captured_in_attacker_stdout": flag_ok,
                "flag_granted_by_gate": flag_ok,
                "gate_verdict": "PROVEN" if flag_ok else "NOT_OBSERVED",
            },
        },
        "evidence": {
            "public_attacker_sanitized": {"base_url": "http://api:3333", "attacker_auth": {"jwt": "<redacted len=120>"}},
            "before_evidence": {"permission_checks": {"passed": True}},
            "attack_trace": {"requests_sent": [{"step": "req1", "response": {"status": 200}}]},
            "after_evidence": {"after_observation": {"passed": True, "channel_healthy": True}},
        },
        "artifacts": {
            "tp_json": {"cve_id": cve_id, "classification": ["TP2"]},
            "oracle_contract": {"cve_id": cve_id, "oracle_type": "O1", "effect_type": "READ"},
            "prep_code": "# prep",
            "verify_code": "# verify",
            "exploit_code": "# client",
        },
    }


class TestSandboxHelpers(unittest.TestCase):
    def test_dual_network_compose_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            yml = build_isolation_compose_yaml("mobsf", "bacver_test_atknet", p / "priv", p / "work")
            self.assertIn("internal: true", yml)
            self.assertIn("name: \"bacver_test_atknet\"", yml)
            self.assertIn("  mobsf:\n    networks:\n      default: {}\n      attacker_net:", yml)
            self.assertIn("          - flag-gate", yml)

    def test_ast_isolation_audit(self) -> None:
        clean_code = "import json, urllib.request\nprint('ok')\n"
        self.assertEqual(audit_exploit_ast(clean_code), [])

        bad_import = "import psycopg2\n"
        self.assertTrue(any("psycopg2" in v for v in audit_exploit_ast(bad_import)))

        bad_rpc = "url = 'http://mobsf:19999/exec'\n"
        self.assertTrue(any("19999" in v for v in audit_exploit_ast(bad_rpc)))

    def test_parse_test_sh_and_sanitization(self) -> None:
        tsh = 'export BACGENIE_BASE_URL="http://web:3000"\nexport BACGENIE_RPC_URL="http://web:19999"\n'
        env = parse_test_sh_env(tsh)
        self.assertEqual(env["BACGENIE_BASE_URL"], "http://web:3000")
        self.assertEqual(env["BACGENIE_RPC_URL"], "http://web:19999")

        sanitized = sanitize_public_input({"base_url": "http://api:3333", "attacker_auth": {"private_api_key": "secret12345"}})
        self.assertEqual(sanitized["base_url"], "http://api:3333")
        self.assertTrue(sanitized["attacker_auth"]["private_api_key"].startswith("<redacted"))

        compacted = sanitize_and_compact_trace(
            {"requests_sent": [{"response": {"body": "prefix " + ("A" * 3500) + " bacgenie_canary_abc123"}}]},
            {"canary": "bacgenie_canary_abc123"},
        )
        body_out = compacted["requests_sent"][0]["response"]["body"]
        self.assertNotIn("bacgenie_canary_abc123", body_out)
        self.assertIn("<RUNTIME_CANARY_MATCHED>", body_out)


class TestSourceWorkspace(unittest.TestCase):
    def test_read_search_and_path_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "roles.ts").write_text(
                "export const roles = {\n  viewer: ['logs:list'],\n  admin: ['settings:update'],\n};\n",
                encoding="utf-8",
            )
            ws = ReadOnlySourceWorkspace(root)
            self.assertTrue(ws.available)

            out = ws.execute_ops([
                {"op": "list", "path": "src"},
                {"op": "search", "query": "settings:update"},
                {"op": "read", "path": "src/roles.ts", "start": 1, "end": 4},
                {"op": "read", "path": "../outside.txt"},
            ])
            self.assertIn("roles.ts", out[0]["entries"])
            self.assertEqual(out[1]["matches"][0]["line"], 3)
            self.assertIn("viewer", out[2]["content"])
            self.assertIn("escapes repository root", out[3]["error"])


class TestAuditorAndVerdicts(unittest.TestCase):
    def test_missing_deliverable_maps_to_unknown_mandatory_review(self) -> None:
        dyn = {"cve_id": "CVE-2025-27507", "status": "MISSING_DELIVERABLE", "reason": "Bundle not built"}
        short = build_deterministic_shortcircuit("CVE-2025-27507", dyn)
        self.assertIsNotNone(short)
        assert short is not None
        self.assertEqual(short["verdict"], "unknown")
        self.assertEqual(short["human_review_policy"], "mandatory_manual_audit")

    def test_noop_contamination_maps_to_false(self) -> None:
        dyn = _completed_dyn_record("CVE-2024-10273", flag_ok=True, noop_captured=True)
        out = audit_cve_reproduction("CVE-2024-10273", {}, dyn, llm_client=None)
        self.assertTrue(out["short_circuited"])
        self.assertEqual(out["report"]["verdict"], "False")
        self.assertEqual(out["report"]["human_review_policy"], "rejected")

    def test_true_verdict_with_source_tool_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "roles.ts").write_text("viewer: []\nowner: ['settings:update']\n", encoding="utf-8")
            fake_llm = FakeLLMClient([
                {"tool_requests": [{"op": "read", "path": "roles.ts", "start": 1, "end": 10}]},
                _make_valid_verdict("CVE-2024-11300", "True"),
            ])
            dyn = _completed_dyn_record("CVE-2024-11300", flag_ok=True, noop_captured=False)
            out = audit_cve_reproduction("CVE-2024-11300", {"sw_version": "v1.6.2"}, dyn, fake_llm, repo_path=repo)
            self.assertEqual(out["report"]["verdict"], "True")
            self.assertEqual(len(out["source_audit_log"]), 1)

    def test_privileged_caller_cheat_rejected_as_false(self) -> None:
        fake_llm = FakeLLMClient([_make_valid_verdict("CVE-2024-10273", "False")])
        dyn = _completed_dyn_record("CVE-2024-10273", flag_ok=True, noop_captured=False)
        out = audit_cve_reproduction("CVE-2024-10273", {}, dyn, fake_llm)
        self.assertEqual(out["report"]["verdict"], "False")
        self.assertFalse(out["report"]["criteria"]["criterion_2_workflow_integrity"]["caller_is_unprivileged"])

    def test_true_forbidden_when_dynamic_flag_failed(self) -> None:
        cand = _make_valid_verdict("CVE-2024-11300", "True")
        with self.assertRaises(ValueError):
            validate_verdict_payload(cand, "CVE-2024-11300", has_dynamic_pass=False)
        with self.assertRaises(ValueError):
            validate_verdict_payload(cand, "CVE-2024-11300", has_dynamic_pass=None)


class TestStratifiedSamplingAndReports(unittest.TestCase):
    def test_stratified_sampling_and_summary_generation(self) -> None:
        records = []
        for idx in range(1, 9):
            cid = f"CVE-2024-100{idx}"
            records.append({
                "cve_id": cid,
                "app": "Lunary" if idx <= 6 else ("MobSF" if idx == 7 else "Mastodon"),
                "version": "v1.0",
                "oracle_type": "O2" if idx == 7 else "O1",
                "effect_type": "READ" if idx % 2 == 0 else "UPDATE",
                "dynamic_status": "COMPLETED",
                "flag_captured": True,
                "noop_blocked": True,
                "report": _make_valid_verdict(cid, "True"),
            })
        records.append({
            "cve_id": "CVE-2025-27507",
            "app": None,
            "version": "v2.0",
            "oracle_type": None,
            "effect_type": None,
            "dynamic_status": "MISSING_DELIVERABLE",
            "flag_captured": None,
            "noop_blocked": None,
            "report": _make_valid_verdict("CVE-2025-27507", "unknown"),
        })
        records.append({
            "cve_id": "CVE-2024-9999",
            "app": "Lunary",
            "version": "v1.0",
            "oracle_type": "O1",
            "effect_type": "UPDATE",
            "dynamic_status": "COMPLETED",
            "flag_captured": True,
            "noop_blocked": True,
            "report": _make_valid_verdict("CVE-2024-9999", "False"),
        })

        sampled = select_stratified_true_samples(records, sample_rate=0.35, min_samples=3, seed=42)
        self.assertEqual(len(sampled), 3)
        # Rare single-item strata (MobSF O2 and Mastodon O1) are prioritized in Pass 1
        self.assertIn("CVE-2024-1007", sampled)
        self.assertIn("CVE-2024-1008", sampled)

        with tempfile.TemporaryDirectory() as out_tmp:
            summary = write_global_reports(Path(out_tmp), records, sample_rate=0.35, sample_seed=42)
            self.assertEqual(summary["verdict_counts"], {"True": 8, "False": 1, "unknown": 1})
            self.assertEqual(summary["review_queues"]["unknown_mandatory_manual_review"]["cves"], ["CVE-2025-27507"])
            self.assertTrue((Path(out_tmp) / "SUMMARY.md").exists())
            self.assertTrue((Path(out_tmp) / "summary.csv").exists())


from pipeline import build_parser as build_pipeline_parser


class TestUnifiedPipelineCLI(unittest.TestCase):
    def test_pipeline_parser_stages_and_defaults(self) -> None:
        parser = build_pipeline_parser()
        args = parser.parse_args(["--stage", "post-reproduce", "--cve", "CVE-2024-11300", "--ssh", "ddk@10.176.46.12"])
        self.assertEqual(args.stage, "post-reproduce")
        self.assertEqual(args.cve, ["CVE-2024-11300"])
        self.assertEqual(args.ssh, "ddk@10.176.46.12")

    def test_load_benchmark_23_catalog(self) -> None:
        from verifier.config import DEFAULT_BENCHMARK_FILE
        from verifier.main import load_benchmark_catalog
        cat = load_benchmark_catalog(DEFAULT_BENCHMARK_FILE)
        self.assertEqual(len(cat), 23)
        self.assertIn("CVE-2024-10273", cat)

    def test_skill_bundle_integrity(self) -> None:
        from verifier.config import ROOT_DIR, SKILL_DIR, SKILL_MD_PATH, SKILL_REFS_DIR
        self.assertTrue(SKILL_MD_PATH.is_file())
        self.assertIn("name: bac-repro-verifier", SKILL_MD_PATH.read_text(encoding="utf-8"))
        self.assertTrue((SKILL_REFS_DIR / "auditor_prompt.md").is_file())
        self.assertTrue((SKILL_REFS_DIR / "repair_prompt.md").is_file())
        self.assertTrue((SKILL_REFS_DIR / "verdict.schema.json").is_file())
        self.assertTrue((SKILL_DIR / "scripts" / "run_sandbox.py").is_file())
        self.assertTrue((ROOT_DIR / ".opencode" / "agents" / "bacgenie-verifier.md").is_file())


if __name__ == "__main__":
    unittest.main()
