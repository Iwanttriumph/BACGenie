#!/usr/bin/env python3
"""Unit & integration tests for harness/gate.py double-blind & anti-cheat invariants."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GATE = Path(__file__).resolve().parent / "gate.py"


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class GateHarnessTest(unittest.TestCase):
    def _base_contracts(self, rdir: Path, oracle_type="O1", effect_type="UPDATE"):
        tp = {
            "cve_id": "CVE-2025-27507",
            "classification": ["TP1"],
            "combination_mode": "single",
            "source_grounding": {"proto": "proto/zitadel/admin.proto:L2110"},
            "core_requests": [{"id": "r1", "method": "PUT", "endpoint": "/admin/v1/idps/ldap/{id}"}],
            "interaction": {"victim_request_required": oracle_type == "O3", "relation": "before" if oracle_type == "O3" else None, "condition": None},
        }
        ora = {
            "cve_id": "CVE-2025-27507",
            "oracle_type": oracle_type,
            "effect_type": effect_type,
            "subjects": {
                "attacker": {
                    "is_anonymous": False,
                    "role_description": "ORG_OWNER",
                    "required_permissions": ["org.idp.write"],
                    "forbidden_permissions": ["iam.idp.write"],
                },
                "observer": {
                    "role_description": "IAM_OWNER",
                    "required_permissions": ["iam.idp.read", "iam.idp.write"],
                    "distinct_from_target": True,
                },
            },
            "target_operation": {
                "resource_type": "Instance LDAP IDP",
                "operation": effect_type,
                "restricted_field": "name",
                "expected_policy": "ORG_OWNER must not modify instance LDAP provider",
                "policy_basis": "commit d9d83398",
            },
            "controls": {
                "positive": {"actor": "observer", "action": "PUT isolated provider", "isolation_strategy": "isolated"},
                "negative": {"applicable": True, "action_or_reason": "POST /admin/v1/idps/google -> 403"},
            },
            "observations": {
                "before": {"actor": "observer", "channel": "GET /admin/v1/idps/templates/{id}", "assertion": "name == old_value"},
                "after": {"actor": "observer", "channel": "GET /admin/v1/idps/templates/{id}", "assertion": "name == new_value"},
            },
        }
        if oracle_type == "O2":
            ora["o2_capability"] = {
                "capability_change": "Inject role=app-admin",
                "capability_use_operation": "Install admin plugin",
            }
        if oracle_type == "O3":
            ora["subjects"]["victim"] = {"role_description": "Authenticated admin jane", "required_permissions": ["admin"]}
            ora["o3_schedule"] = {
                "relation": "before",
                "shared_state_condition": "Worker thread residual principal",
                "reset_strategy": "Fresh worker state",
                "attempt_limit": 5,
            }
        write_text(rdir / "01_tp.json", json.dumps(tp, indent=2))
        write_text(rdir / "02_oracle_contract.json", json.dumps(ora, indent=2))

    def test_update_double_blind_proven_and_airgap(self):
        with tempfile.TemporaryDirectory() as tmp:
            rdir = Path(tmp) / "CVE-2025-27507"
            state_file = Path(tmp) / "mock_server_state.json"
            self._base_contracts(rdir, "O1", "UPDATE")

            write_text(rdir / "prep.py", f"""
import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--nonce-in", required=True)
p.add_argument("--public-out", required=True)
p.add_argument("--private-out", required=True)
a = p.parse_args()
nonces = json.loads(Path(a.nonce_in).read_text())
Path({str(state_file)!r}).write_text(json.dumps({{"idp_1": nonces["old_value"]}}))
Path(a.public_out).write_text(json.dumps({{
    "base_url": "http://127.0.0.1:9999",
    "attacker_auth": {{"token": "low_priv_org_token_12345"}},
    "target_id": "idp_1",
    "desired_new_value": nonces["new_value"],
    "state_path_sim": {str(state_file)!r}
}}))
Path(a.private_out).write_text(json.dumps({{
    "observer_token": "super_secret_iam_owner_token_99999",
    "target_id": "idp_1"
}}))
""")

            write_text(rdir / "verify.py", f"""
import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--phase", required=True)
p.add_argument("--private-in", required=True)
p.add_argument("--public-in", required=True)
p.add_argument("--nonce-in")
p.add_argument("--before-in")
p.add_argument("--attack-in")
p.add_argument("--out", required=True)
a = p.parse_args()
state = json.loads(Path({str(state_file)!r}).read_text())
nonces = json.loads(Path(a.nonce_in).read_text())
if a.phase == "before":
    Path(a.out).write_text(json.dumps({{
        "permission_checks": {{"passed": True, "summary": "ok", "transcripts": [{{"role": "ORG_OWNER"}}]}},
        "positive_control": {{"passed": True, "summary": "ok", "transcripts": [{{}}]}},
        "negative_control": {{"passed": True, "summary": "403 on google idp", "transcripts": [{{}}]}},
        "before_observation": {{
            "passed": state["idp_1"] == nonces["old_value"],
            "summary": "matches old",
            "target_id": "idp_1",
            "observed_value": state["idp_1"],
            "raw_evidence": state
        }}
    }}))
elif a.phase == "after":
    Path(a.out).write_text(json.dumps({{
        "after_observation": {{
            "passed": state["idp_1"] == nonces["new_value"],
            "channel_healthy": True,
            "summary": "updated",
            "target_id": "idp_1",
            "observed_value": state["idp_1"],
            "raw_evidence": state
        }}
    }}))
""")

            # Exploit also verifies that no bacgenie_gate_* private files exist anywhere on disk!
            write_text(rdir / "exploit.py", """
import argparse, glob, json, os, tempfile
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--public-in", required=True)
p.add_argument("--out", required=True)
a = p.parse_args()
pub = json.loads(Path(a.public_in).read_text())
leaked = glob.glob(os.path.join(tempfile.gettempdir(), "bacgenie_gate_*", "*.json"))
assert len(leaked) == 0, f"Air-gap broken! Found files: {leaked}"
st_path = Path(pub["state_path_sim"])
st = json.loads(st_path.read_text())
st[pub["target_id"]] = pub["desired_new_value"]
st_path.write_text(json.dumps(st))
Path(a.out).write_text(json.dumps({
    "requests_sent": [{"step": "put_ldap", "request": {"method": "PUT"}, "response": {"status": 200}}]
}))
""")

            res = subprocess.run([sys.executable, str(GATE), "run", str(rdir)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, msg=res.stderr + "\n" + res.stdout)
            verdict = json.loads((rdir / "verdict.json").read_text())
            self.assertEqual(verdict["verdict"], "PROVEN")

    def test_ast_audit_blocks_cheating_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            rdir = Path(tmp) / "CVE-2025-27507"
            rdir.mkdir(parents=True)
            write_text(rdir / "exploit.py", "import sqlite3\nimport subprocess\n")
            res = subprocess.run([sys.executable, str(GATE), "audit-exploit", str(rdir)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            out = json.loads(res.stdout)
            self.assertFalse(out["ok"])
            self.assertEqual(len(out["violations"]), 2)

    def test_leak_detector_catches_admin_token_in_public_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            rdir = Path(tmp) / "CVE-2025-27507"
            self._base_contracts(rdir, "O1", "READ")
            write_text(rdir / "prep.py", """
import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--nonce-in", required=True)
p.add_argument("--public-out", required=True)
p.add_argument("--private-out", required=True)
a = p.parse_args()
n = json.loads(Path(a.nonce_in).read_text())
# Deliberate bug: leaks READ canary into public_out
Path(a.public_out).write_text(json.dumps({"base_url": "http://localhost", "leak": n["canary"]}))
Path(a.private_out).write_text(json.dumps({"observer_token": "admin_secret_tok_999"}))
""")
            write_text(rdir / "verify.py", "pass\n")
            res = subprocess.run([sys.executable, str(GATE), "check-before", str(rdir)], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("READ canary was leaked", res.stdout)


if __name__ == "__main__":
    unittest.main()
