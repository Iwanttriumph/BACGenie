#!/usr/bin/env python3
"""
BACGenie Double-Blind Verification & Replay Gate (Pure Python 3 Stdlib).

Enforces physical privilege separation, runtime cryptographic canary/nonce injection,
sibling sentinel health checks, and three-valued verdict generation:
  - PROVEN: Preconditions, permission boundary, controls, and post-attack independent
    observations (matching fresh runtime nonces) all hold.
  - NOT_OBSERVED: Preconditions and positive control hold, exploit executed cleanly,
    but target protected effect did not occur.
  - INCONCLUSIVE: Precondition/control failure, observation channel failure, contract/
    isolation violation, or O3 concurrency/residual window not hit within attempt_limit.

Subcommands:
  python3 harness/gate.py validate-contract <run_dir>
  python3 harness/gate.py audit-exploit <run_dir>
  python3 harness/gate.py check-before <run_dir>
  python3 harness/gate.py run <run_dir>
"""

import argparse
import ast
import datetime as dt
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

VALID_TP = {"TP1", "TP2", "TP3", "TP4", "TP5"}
VALID_ORACLE_TYPES = {"O1", "O2", "O3"}
VALID_EFFECT_TYPES = {"READ", "CREATE", "UPDATE", "DELETE"}

FORBIDDEN_EXPLOIT_MODULES = {
    "docker",
    "kubernetes",
    "paramiko",
    "fabric",
    "psycopg",
    "psycopg2",
    "asyncpg",
    "pymysql",
    "mysql",
    "MySQLdb",
    "sqlite3",
    "aiosqlite",
    "sqlalchemy",
    "pymongo",
    "redis",
    "subprocess",
    "pty",
    "pexpect",
}

FORBIDDEN_EXPLOIT_OS_ATTRS = {
    "system",
    "popen",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "fork",
    "forkpty",
}

FORBIDDEN_EXPLOIT_PATTERNS = [
    r"admin-pat",
    r"private_verifier",
    r"nonce_bundle",
    r"/var/run/docker\.sock",
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Missing required JSON file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def generate_nonces(seed_tag: str = "") -> Dict[str, str]:
    suffix = seed_tag or secrets.token_hex(6)
    return {
        "run_id": f"run_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(3)}",
        "canary": f"bacgenie_canary_{secrets.token_hex(8)}" if not seed_tag else f"bacgenie_sample_canary_{suffix}",
        "old_value": f"bacgenie_old_{secrets.token_hex(6)}" if not seed_tag else f"bacgenie_sample_old_{suffix}",
        "new_value": f"bacgenie_new_{secrets.token_hex(6)}" if not seed_tag else f"bacgenie_sample_new_{suffix}",
        "create_tag": f"bacgenie_create_{secrets.token_hex(6)}" if not seed_tag else f"bacgenie_sample_create_{suffix}",
    }


def validate_contract_files(run_dir: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    tp_path = run_dir / "01_tp.json"
    ora_path = run_dir / "02_oracle_contract.json"
    tp = load_json(tp_path)
    ora = load_json(ora_path)
    errors: List[str] = []

    cve_id = tp.get("cve_id")
    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        errors.append("01_tp.json: cve_id must be a valid CVE-YYYY-NNNN+ string")
    if ora.get("cve_id") != cve_id:
        errors.append("02_oracle_contract.json: cve_id does not match 01_tp.json")

    cls = tp.get("classification")
    if not isinstance(cls, list) or not cls or any(x not in VALID_TP for x in cls):
        errors.append(f"01_tp.json: classification must be a non-empty list in {sorted(VALID_TP)}")

    if not tp.get("source_grounding"):
        errors.append("01_tp.json: source_grounding must cite target source files/lines or official symbols")

    o_type = ora.get("oracle_type")
    e_type = ora.get("effect_type")
    if o_type not in VALID_ORACLE_TYPES:
        errors.append(f"02_oracle_contract.json: oracle_type must be one of {sorted(VALID_ORACLE_TYPES)}")
    if e_type not in VALID_EFFECT_TYPES:
        errors.append(f"02_oracle_contract.json: effect_type must be one of {sorted(VALID_EFFECT_TYPES)}")

    subjects = ora.get("subjects")
    if not isinstance(subjects, dict):
        errors.append("02_oracle_contract.json: subjects must be an object")
    else:
        attacker = subjects.get("attacker")
        observer = subjects.get("observer")
        if not isinstance(attacker, dict):
            errors.append("subjects.attacker must be an object")
        else:
            is_anon = bool(attacker.get("is_anonymous", False))
            forb = attacker.get("forbidden_permissions")
            if not is_anon and (not isinstance(forb, list) or len(forb) == 0):
                errors.append("subjects.attacker.forbidden_permissions must be a non-empty list when not anonymous")
            if "required_permissions" not in attacker or not isinstance(attacker.get("required_permissions"), list):
                errors.append("subjects.attacker.required_permissions must be a list")
        if not isinstance(observer, dict) or not observer.get("required_permissions"):
            errors.append("subjects.observer must declare non-empty required_permissions")
        if o_type == "O3" and not isinstance(subjects.get("victim"), dict):
            errors.append("O3 contract requires subjects.victim")

    target_op = ora.get("target_operation")
    if not isinstance(target_op, dict):
        errors.append("02_oracle_contract.json: target_operation must be an object")
    else:
        for req_key in ("resource_type", "operation", "expected_policy", "policy_basis"):
            if not target_op.get(req_key):
                errors.append(f"target_operation.{req_key} must be non-empty")

    controls = ora.get("controls")
    if not isinstance(controls, dict) or not isinstance(controls.get("positive"), dict):
        errors.append("controls.positive must be an object describing the isolated authorized control")
    if not isinstance(controls, dict) or not isinstance(controls.get("negative"), dict):
        errors.append("controls.negative must be an object (include applicable=false and reason if inapplicable)")

    obs = ora.get("observations")
    if not isinstance(obs, dict):
        errors.append("observations must be an object with before and after channels")
    else:
        for phase in ("before", "after"):
            p_obj = obs.get(phase)
            if not isinstance(p_obj, dict) or not p_obj.get("channel") or not p_obj.get("assertion"):
                errors.append(f"observations.{phase} must specify non-empty channel and assertion")

    if o_type == "O2":
        cap = ora.get("o2_capability")
        if not isinstance(cap, dict) or not cap.get("capability_change") or not cap.get("capability_use_operation"):
            errors.append("O2 contract requires o2_capability.{capability_change, capability_use_operation}")

    if o_type == "O3":
        sched = ora.get("o3_schedule")
        if not isinstance(sched, dict):
            errors.append("O3 contract requires o3_schedule object")
        else:
            for k in ("relation", "shared_state_condition", "reset_strategy", "attempt_limit"):
                if sched.get(k) in (None, ""):
                    errors.append(f"o3_schedule.{k} must be specified for O3")

    if errors:
        raise ValueError("Contract validation failed:\n  - " + "\n  - ".join(errors))
    return tp, ora


def audit_exploit_script(exploit_path: Path) -> List[str]:
    if not exploit_path.exists():
        raise FileNotFoundError(f"Missing exploit script: {exploit_path}")
    source = exploit_path.read_text(encoding="utf-8")
    violations: List[str] = []

    try:
        tree = ast.parse(source, filename=str(exploit_path))
    except SyntaxError as exc:
        return [f"SyntaxError in exploit.py: {exc}"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".")[0]
                if root_mod in FORBIDDEN_EXPLOIT_MODULES:
                    violations.append(f"Forbidden import '{alias.name}' at line {node.lineno} (exploit.py must be a pure network client)")
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root_mod = node.module.split(".")[0]
                if root_mod in FORBIDDEN_EXPLOIT_MODULES:
                    violations.append(f"Forbidden from-import '{node.module}' at line {node.lineno}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr in FORBIDDEN_EXPLOIT_OS_ATTRS:
                violations.append(f"Forbidden os.{node.attr} call at line {node.lineno}")

    for pat in FORBIDDEN_EXPLOIT_PATTERNS:
        if re.search(pat, source, flags=re.IGNORECASE):
            violations.append(f"Forbidden secret/socket reference matching /{pat}/ in exploit.py")

    return violations


def collect_secret_strings(private_data: Any, min_len: int = 8) -> List[str]:
    found: List[str] = []
    if isinstance(private_data, dict):
        for k, v in private_data.items():
            if any(tok in k.lower() for tok in ("token", "secret", "password", "cookie", "jwt", "key", "cred", "canary", "dsn")):
                if isinstance(v, str) and len(v.strip()) >= min_len:
                    found.append(v.strip())
                else:
                    found.extend(collect_secret_strings(v, min_len=min_len))
            else:
                found.extend(collect_secret_strings(v, min_len=min_len))
    elif isinstance(private_data, list):
        for item in private_data:
            found.extend(collect_secret_strings(item, min_len=min_len))
    return sorted(set(found))


def detect_public_leak(public_data: Dict[str, Any], private_data: Dict[str, Any], nonces: Dict[str, str], effect_type: str) -> List[str]:
    pub_raw = json.dumps(public_data, ensure_ascii=False)
    leaks: List[str] = []
    if effect_type == "READ" and nonces["canary"] in pub_raw:
        leaks.append("READ canary was leaked into public_attacker.json by prep.py")
    if nonces["old_value"] in pub_raw and effect_type == "UPDATE":
        leaks.append("UPDATE old_value canary was leaked into public_attacker.json; attacker should only receive new_value")
    allowed_public_tokens = {
        nonces.get("new_value", ""),
        nonces.get("create_tag", ""),
        nonces.get("run_id", ""),
    }
    attacker_raw = json.dumps(public_data.get("attacker_auth", {}), ensure_ascii=False)
    for sec in collect_secret_strings(private_data):
        if sec and sec not in allowed_public_tokens and sec not in attacker_raw and sec in pub_raw:
            leaks.append(f"Private verifier secret/credential (prefix '{sec[:6]}...') leaked into public_attacker.json")
    return leaks


def run_py(script: Path, args: List[str], cwd: Path, clean_env: bool = False, timeout: int = 180) -> Dict[str, Any]:
    if clean_env:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "PYTHONUNBUFFERED": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
        # Preserve virtualenvs if active so pure HTTP libraries like requests/httpx work
        if os.environ.get("VIRTUAL_ENV"):
            env["VIRTUAL_ENV"] = os.environ["VIRTUAL_ENV"]
        if os.environ.get("PYTHONPATH"):
            env["PYTHONPATH"] = os.environ["PYTHONPATH"]
        if os.name == "nt":
            for win_key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"):
                if os.environ.get(win_key):
                    env[win_key] = os.environ[win_key]
    else:
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        env.setdefault("NO_PROXY", "127.0.0.1,localhost")
        env.setdefault("no_proxy", "127.0.0.1,localhost")

    cmd = [sys.executable, str(script.resolve())] + args
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
        return {
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-12000:],
            "stderr": proc.stderr[-12000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "returncode": -9,
            "stdout": (exc.stdout or "")[-8000:] if isinstance(exc.stdout, str) else "",
            "stderr": f"Timed out after {timeout}s\n" + ((exc.stderr or "")[-8000:] if isinstance(exc.stderr, str) else ""),
            "timed_out": True,
        }


def check_before_Assertions(before_data: Dict[str, Any], ora: Dict[str, Any]) -> List[str]:
    failures: List[str] = []
    perm = before_data.get("permission_checks") or {}
    if perm.get("passed") is not True:
        failures.append(f"permission_checks.passed is not True: {perm.get('summary')}")
    if not perm.get("transcripts"):
        failures.append("permission_checks.transcripts must include raw request/response or query evidence")

    pos = before_data.get("positive_control") or {}
    if pos.get("passed") is not True:
        failures.append(f"positive_control.passed is not True: {pos.get('summary')}")

    neg_spec = ora.get("controls", {}).get("negative", {})
    neg = before_data.get("negative_control") or {}
    if neg_spec.get("applicable", True):
        if neg.get("passed") is not True:
            failures.append(f"negative_control.passed is not True: {neg.get('summary')}")

    obs = before_data.get("before_observation") or {}
    if obs.get("passed") is not True:
        failures.append(f"before_observation.passed is not True: {obs.get('summary')}")
    if not obs.get("raw_evidence"):
        failures.append("before_observation.raw_evidence must record raw HTTP/DB state before attack")
    return failures


def evaluate_gate_invariants(
    ora: Dict[str, Any],
    nonces: Dict[str, str],
    public_data: Dict[str, Any],
    before_data: Dict[str, Any],
    attack_data: Dict[str, Any],
    after_data: Dict[str, Any],
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Independent deterministic invariant check executed by gate.py itself.
    Returns (verdict, reason, checks_detail).
    """
    e_type = ora["effect_type"]
    o_type = ora["oracle_type"]
    b_obs = before_data.get("before_observation") or {}
    a_obs = after_data.get("after_observation") or {}
    checks: Dict[str, Any] = {"effect_type": e_type, "oracle_type": o_type}

    if a_obs.get("channel_healthy") is False:
        return (
            "INCONCLUSIVE",
            f"Post-attack observation channel unhealthy: {a_obs.get('summary')}",
            checks,
        )

    if not attack_data.get("requests_sent"):
        return (
            "INCONCLUSIVE",
            "exploit.py did not record raw requests_sent in attack_trace",
            checks,
        )

    effect_matched = False

    if e_type == "READ":
        canary = nonces["canary"]
        pub_dump = json.dumps(public_data, ensure_ascii=False)
        extracted = json.dumps(attack_data.get("extracted_data", ""), ensure_ascii=False)
        resp_dump = json.dumps(attack_data.get("requests_sent", []), ensure_ascii=False)
        canary_in_before = canary in json.dumps(b_obs, ensure_ascii=False)
        canary_not_in_public = canary not in pub_dump
        canary_obtained = (canary in extracted) or (canary in resp_dump)
        checks.update({
            "canary_planted_in_before": canary_in_before,
            "canary_absent_from_public_input": canary_not_in_public,
            "canary_obtained_by_attacker": canary_obtained,
        })
        if not canary_in_before or not canary_not_in_public:
            return ("INCONCLUSIVE", "READ canary baseline/isolation invariant broken", checks)
        effect_matched = canary_obtained and (a_obs.get("passed") is True)

    elif e_type == "UPDATE":
        old_v = nonces["old_value"]
        new_v = nonces["new_value"]
        b_id = b_obs.get("target_id")
        a_id = a_obs.get("target_id")
        b_val = b_obs.get("observed_value")
        a_val = a_obs.get("observed_value")
        same_id = bool(b_id) and (b_id == a_id)
        before_matches_old = b_val == old_v
        after_matches_new = a_val == new_v
        checks.update({
            "same_target_id": same_id,
            "target_id": b_id,
            "before_matches_old_nonce": before_matches_old,
            "observed_before": b_val,
            "observed_after": a_val,
            "expected_new_nonce": new_v,
            "after_matches_new_nonce": after_matches_new,
        })
        if not same_id or not before_matches_old:
            return ("INCONCLUSIVE", "UPDATE before-baseline did not bind target_id or old_value nonce", checks)
        effect_matched = after_matches_new and (a_obs.get("passed") is True)

    elif e_type == "CREATE":
        tag = nonces["create_tag"]
        absent_before = b_obs.get("target_exists") is False
        present_after = a_obs.get("target_exists") is True
        tag_in_after = tag in json.dumps(a_obs.get("raw_evidence", ""), ensure_ascii=False)
        checks.update({
            "absent_before_attack": absent_before,
            "present_after_attack": present_after,
            "create_tag_verified_in_scope": tag_in_after,
        })
        if not absent_before:
            return ("INCONCLUSIVE", "CREATE target already existed before attack", checks)
        effect_matched = present_after and tag_in_after and (a_obs.get("passed") is True)

    elif e_type == "DELETE":
        t_id = b_obs.get("target_id")
        s_id = b_obs.get("sentinel_id")
        alive_before = b_obs.get("target_alive") is True
        sentinel_before = b_obs.get("sentinel_alive") is True
        deleted_after = a_obs.get("target_deleted") is True
        sentinel_after = a_obs.get("sentinel_alive") is True
        distinct_ids = bool(t_id) and bool(s_id) and (t_id != s_id)
        checks.update({
            "target_id": t_id,
            "sentinel_id": s_id,
            "distinct_target_and_sentinel": distinct_ids,
            "target_alive_before": alive_before,
            "sentinel_alive_before": sentinel_before,
            "target_deleted_after": deleted_after,
            "sentinel_alive_after": sentinel_after,
        })
        if not (distinct_ids and alive_before and sentinel_before):
            return ("INCONCLUSIVE", "DELETE requires distinct alive target_id and sentinel_id before attack", checks)
        if not sentinel_after:
            return ("INCONCLUSIVE", "DELETE sentinel also disappeared/failed; cannot rule out service outage or filter bug", checks)
        effect_matched = deleted_after and (a_obs.get("passed") is True)

    if o_type == "O2":
        cap_used = bool(attack_data.get("capability_use_requests")) and (after_data.get("capability_use_verified") is True)
        checks["o2_capability_use_verified"] = cap_used
        if effect_matched and not cap_used:
            return (
                "INCONCLUSIVE",
                "O2 requires verified subsequent capability use by beneficiary, not merely role/membership mutation",
                checks,
            )

    if o_type == "O3":
        solo_blocked = after_data.get("solo_baseline_blocked") is True
        checks["o3_solo_baseline_blocked"] = solo_blocked
        if not solo_blocked:
            return (
                "INCONCLUSIVE",
                "O3 requires solo_baseline_blocked=True (proving effect does NOT occur without victim request)",
                checks,
            )
        if not effect_matched and after_data.get("window_missed") is True:
            return (
                "INCONCLUSIVE",
                "O3 concurrency/residual timing window was not hit within attempt_limit; cannot conclude patched",
                checks,
            )

    if effect_matched:
        return ("PROVEN", "All permission boundaries, controls, and nonce-bound post-attack invariants verified", checks)
    return ("NOT_OBSERVED", "Preconditions and positive control held, but unauthorized effect did not occur", checks)


def cmd_validate_contract(run_dir: Path) -> int:
    tp, ora = validate_contract_files(run_dir)
    print(json.dumps({
        "ok": True,
        "cve_id": ora["cve_id"],
        "classification": tp["classification"],
        "oracle_type": ora["oracle_type"],
        "effect_type": ora["effect_type"],
    }, ensure_ascii=False))
    return 0


def cmd_audit_exploit(run_dir: Path) -> int:
    violations = audit_exploit_script(run_dir / "exploit.py")
    if violations:
        print(json.dumps({"ok": False, "violations": violations}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps({"ok": True, "violations": []}, ensure_ascii=False))
    return 0


def cmd_check_before(run_dir: Path) -> int:
    _, ora = validate_contract_files(run_dir)
    prep_script = run_dir / "prep.py"
    verify_script = run_dir / "verify.py"
    if not prep_script.exists() or not verify_script.exists():
        raise FileNotFoundError("Both prep.py and verify.py must exist in run_dir")

    sample_nonces = generate_nonces(seed_tag="devcheck")
    with tempfile.TemporaryDirectory(prefix="bacgenie_before_") as tmp:
        tmp_path = Path(tmp)
        nonce_file = tmp_path / "nonce_bundle.json"
        priv_file = tmp_path / "private_verifier.json"
        pub_file = run_dir / "sample_public_attacker.json"
        before_out = run_dir / "before_check_result.json"
        save_json(nonce_file, sample_nonces)

        prep_exec = run_py(prep_script, [
            "--nonce-in", str(nonce_file),
            "--public-out", str(pub_file),
            "--private-out", str(priv_file),
        ], cwd=run_dir)
        if prep_exec["returncode"] != 0:
            print(json.dumps({"ok": False, "stage": "prep", "exec": prep_exec}, ensure_ascii=False, indent=2))
            return 1

        pub_data = load_json(pub_file)
        priv_data = load_json(priv_file)
        leaks = detect_public_leak(pub_data, priv_data, sample_nonces, ora["effect_type"])
        if leaks:
            print(json.dumps({"ok": False, "stage": "leak_check", "leaks": leaks}, ensure_ascii=False, indent=2))
            return 1

        ver_exec = run_py(verify_script, [
            "--phase", "before",
            "--private-in", str(priv_file),
            "--public-in", str(pub_file),
            "--nonce-in", str(nonce_file),
            "--out", str(before_out),
        ], cwd=run_dir)
        if ver_exec["returncode"] != 0:
            print(json.dumps({"ok": False, "stage": "verify_before", "exec": ver_exec}, ensure_ascii=False, indent=2))
            return 1

        before_data = load_json(before_out)
        failures = check_before_Assertions(before_data, ora)
        if failures:
            print(json.dumps({"ok": False, "stage": "before_assertions", "failures": failures, "before": before_data}, ensure_ascii=False, indent=2))
            return 1

    print(json.dumps({
        "ok": True,
        "message": "Preconditions, permission boundaries, controls, and before-baseline passed. sample_public_attacker.json generated for blind attacker worker.",
        "sample_public_attacker": str(run_dir / "sample_public_attacker.json"),
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_run(run_dir: Path) -> int:
    started_at = utc_now()
    tp, ora = validate_contract_files(run_dir)
    prep_script = run_dir / "prep.py"
    exploit_script = run_dir / "exploit.py"
    verify_script = run_dir / "verify.py"
    for s in (prep_script, exploit_script, verify_script):
        if not s.exists():
            raise FileNotFoundError(f"Required script missing: {s}")

    violations = audit_exploit_script(exploit_script)
    if violations:
        verdict_doc = {
            "cve_id": ora["cve_id"],
            "verdict": "INCONCLUSIVE",
            "reason": "Exploit failed static isolation audit",
            "violations": violations,
            "timestamp": utc_now(),
        }
        save_json(run_dir / "verdict.json", verdict_doc)
        print(json.dumps(verdict_doc, ensure_ascii=False, indent=2))
        return 1

    nonces = generate_nonces()
    bundle: Dict[str, Any] = {
        "cve_id": ora["cve_id"],
        "started_at": started_at,
        "tp": tp,
        "oracle_contract": ora,
        "runtime_nonces": nonces,
        "steps": {},
    }

    with tempfile.TemporaryDirectory(prefix="bacgenie_gate_") as work_tmp:
        wdir = Path(work_tmp)
        nonce_path = wdir / "nonce_bundle.json"
        priv_path = wdir / "private_verifier.json"
        pub_path = wdir / "public_attacker.json"
        before_path = wdir / "before_out.json"
        attack_path = wdir / "attack_out.json"
        after_path = wdir / "after_out.json"

        save_json(nonce_path, nonces)

        # Step 1: Precondition Setup
        prep_exec = run_py(prep_script, [
            "--nonce-in", str(nonce_path),
            "--public-out", str(pub_path),
            "--private-out", str(priv_path),
        ], cwd=run_dir)
        bundle["steps"]["prep"] = prep_exec
        if prep_exec["returncode"] != 0 or not pub_path.exists() or not priv_path.exists():
            return _finalize(run_dir, bundle, "INCONCLUSIVE", "prep.py failed to initialize target state", {})

        pub_data = load_json(pub_path)
        priv_data = load_json(priv_path)
        leaks = detect_public_leak(pub_data, priv_data, nonces, ora["effect_type"])
        if leaks:
            return _finalize(run_dir, bundle, "INCONCLUSIVE", "Information leak from prep.py: " + "; ".join(leaks), {})

        # Step 2: Pre-Attack Permission, Controls & Baseline Observation
        before_exec = run_py(verify_script, [
            "--phase", "before",
            "--private-in", str(priv_path),
            "--public-in", str(pub_path),
            "--nonce-in", str(nonce_path),
            "--out", str(before_path),
        ], cwd=run_dir)
        bundle["steps"]["verify_before_exec"] = before_exec
        if before_exec["returncode"] != 0 or not before_path.exists():
            return _finalize(run_dir, bundle, "INCONCLUSIVE", "verify.py --phase before exited with error", {})

        before_data = load_json(before_path)
        bundle["before_evidence"] = before_data
        before_failures = check_before_Assertions(before_data, ora)
        if before_failures:
            return _finalize(
                run_dir,
                bundle,
                "INCONCLUSIVE",
                "Pre-attack boundary/control check failed: " + "; ".join(before_failures),
                {},
            )

        # Step 3: Air-Gapped Blind Exploit Execution
        priv_bytes = priv_path.read_bytes()
        nonce_bytes = nonce_path.read_bytes()
        before_bytes = before_path.read_bytes()
        pub_bytes = pub_path.read_bytes()
        priv_path.unlink()
        nonce_path.unlink()
        before_path.unlink()
        pub_path.unlink()

        if ora["oracle_type"] != "O3":
            # O1 / O2: Private verifier secrets exist ONLY in gate.py RAM while exploit.py runs.
            with tempfile.TemporaryDirectory(prefix="bacgenie_blind_") as blind_tmp:
                bdir = Path(blind_tmp)
                blind_pub = bdir / "public_attacker.json"
                blind_out = bdir / "attack_trace.json"
                save_json(blind_pub, pub_data)

                exploit_exec = run_py(
                    exploit_script,
                    ["--public-in", str(blind_pub), "--out", str(blind_out)],
                    cwd=bdir,
                    clean_env=True,
                )
                bundle["steps"]["exploit_exec"] = exploit_exec
                if blind_out.exists():
                    shutil.copyfile(blind_out, attack_path)
        else:
            # O3: Step 3a — Mandatory Solo Attacker Baseline (zero victim traffic; secrets only in RAM)
            with tempfile.TemporaryDirectory(prefix="bacgenie_solo_") as solo_tmp:
                sdir = Path(solo_tmp)
                solo_pub = sdir / "public_attacker.json"
                solo_out = sdir / "solo_trace.json"
                save_json(solo_pub, pub_data)
                solo_exec = run_py(
                    exploit_script,
                    ["--public-in", str(solo_pub), "--out", str(solo_out)],
                    cwd=sdir,
                    clean_env=True,
                )
                bundle["steps"]["o3_solo_baseline_exec"] = solo_exec
                solo_trace = load_json(solo_out) if solo_out.exists() else {}
                bundle["o3_solo_baseline_trace"] = solo_trace
                if nonces["canary"] in json.dumps(solo_trace, ensure_ascii=False):
                    priv_path.write_bytes(priv_bytes)
                    nonce_path.write_bytes(nonce_bytes)
                    before_path.write_bytes(before_bytes)
                    pub_path.write_bytes(pub_bytes)
                    return _finalize(
                        run_dir,
                        bundle,
                        "INCONCLUSIVE",
                        "O3 solo baseline already obtained canary without victim request (misclassified TP1/O1)",
                        {"o3_solo_baseline_blocked": False},
                    )

            # O3: Step 3b — Scheduled Victim Traffic + Blind Attacker Execution
            relation = ora["o3_schedule"]["relation"]
            with tempfile.TemporaryDirectory(prefix="bacgenie_vsim_") as vsim_tmp, \
                 tempfile.TemporaryDirectory(prefix="bacgenie_blind_") as blind_tmp:
                vdir, bdir = Path(vsim_tmp), Path(blind_tmp)
                os.chmod(vdir, 0o700)
                v_priv = vdir / "priv.json"
                v_nonce = vdir / "nonce.json"
                v_priv.write_bytes(priv_bytes)
                v_nonce.write_bytes(nonce_bytes)

                blind_pub = bdir / "public_attacker.json"
                blind_out = bdir / "attack_trace.json"
                save_json(blind_pub, pub_data)

                if relation == "before":
                    v_exec = run_py(verify_script, [
                        "--phase", "victim_traffic",
                        "--private-in", str(v_priv),
                        "--public-in", str(blind_pub),
                        "--nonce-in", str(v_nonce),
                    ], cwd=run_dir, timeout=60)
                    bundle["steps"]["o3_victim_before_exec"] = v_exec
                    exploit_exec = run_py(
                        exploit_script,
                        ["--public-in", str(blind_pub), "--out", str(blind_out)],
                        cwd=bdir,
                        clean_env=True,
                    )
                else:
                    # concurrent / after: run victim_traffic in parallel while blind exploit probes window
                    v_proc = subprocess.Popen(
                        [
                            sys.executable, str(verify_script.resolve()),
                            "--phase", "victim_traffic",
                            "--private-in", str(v_priv),
                            "--public-in", str(blind_pub),
                            "--nonce-in", str(v_nonce),
                        ],
                        cwd=str(run_dir),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    try:
                        exploit_exec = run_py(
                            exploit_script,
                            ["--public-in", str(blind_pub), "--out", str(blind_out)],
                            cwd=bdir,
                            clean_env=True,
                        )
                    finally:
                        try:
                            v_out, v_err = v_proc.communicate(timeout=15)
                        except subprocess.TimeoutExpired:
                            v_proc.kill()
                            v_out, v_err = v_proc.communicate()
                        bundle["steps"]["o3_victim_concurrent_exec"] = {
                            "returncode": v_proc.returncode,
                            "stdout": (v_out or "")[-8000:],
                            "stderr": (v_err or "")[-8000:],
                        }

                bundle["steps"]["exploit_exec"] = exploit_exec
                if blind_out.exists():
                    shutil.copyfile(blind_out, attack_path)

        # Restore private context after exploit.py has terminated
        priv_path.write_bytes(priv_bytes)
        nonce_path.write_bytes(nonce_bytes)
        before_path.write_bytes(before_bytes)
        pub_path.write_bytes(pub_bytes)

        if exploit_exec["returncode"] != 0 or not attack_path.exists():
            return _finalize(run_dir, bundle, "INCONCLUSIVE", "exploit.py failed or produced no attack_trace.json", {})

        attack_data = load_json(attack_path)
        bundle["public_attacker_input"] = pub_data
        bundle["attack_evidence"] = attack_data

        # Step 4: Independent Post-Attack Observation
        after_exec = run_py(verify_script, [
            "--phase", "after",
            "--private-in", str(priv_path),
            "--public-in", str(pub_path),
            "--nonce-in", str(nonce_path),
            "--before-in", str(before_path),
            "--attack-in", str(attack_path),
            "--out", str(after_path),
        ], cwd=run_dir)
        bundle["steps"]["verify_after_exec"] = after_exec
        if after_exec["returncode"] != 0 or not after_path.exists():
            return _finalize(run_dir, bundle, "INCONCLUSIVE", "verify.py --phase after exited with error", {})

        after_data = load_json(after_path)
        bundle["after_evidence"] = after_data

        # Optional environment reset hook (non-fatal) if verify.py supports --phase cleanup
        if ora.get("cleanup_after_gate", False):
            cleanup_exec = run_py(verify_script, [
                "--phase", "cleanup",
                "--private-in", str(priv_path),
                "--public-in", str(pub_path),
            ], cwd=run_dir, timeout=60)
            bundle["steps"]["cleanup_exec"] = cleanup_exec

        verdict, reason, checks = evaluate_gate_invariants(
            ora, nonces, pub_data, before_data, attack_data, after_data
        )
        return _finalize(run_dir, bundle, verdict, reason, checks)


def _finalize(run_dir: Path, bundle: Dict[str, Any], verdict: str, reason: str, checks: Dict[str, Any]) -> int:
    finished_at = utc_now()
    bundle["finished_at"] = finished_at
    bundle["gate_invariant_checks"] = checks
    bundle["verdict"] = verdict
    bundle["reason"] = reason
    save_json(run_dir / "evidence_bundle.json", bundle)

    verdict_doc = {
        "cve_id": bundle["cve_id"],
        "oracle_type": bundle["oracle_contract"]["oracle_type"],
        "effect_type": bundle["oracle_contract"]["effect_type"],
        "classification": bundle["tp"]["classification"],
        "run_id": bundle["runtime_nonces"]["run_id"],
        "verdict": verdict,
        "reason": reason,
        "gate_invariant_checks": checks,
        "started_at": bundle["started_at"],
        "finished_at": finished_at,
    }
    save_json(run_dir / "verdict.json", verdict_doc)
    print(json.dumps(verdict_doc, ensure_ascii=False, indent=2))
    return 0 if verdict in ("PROVEN", "NOT_OBSERVED") else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-contract", "audit-exploit", "check-before", "run"):
        p = sub.add_parser(name)
        p.add_argument("run_dir", type=Path, help="Path to runs/<CVE-ID> directory")

    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    try:
        if args.command == "validate-contract":
            return cmd_validate_contract(run_dir)
        if args.command == "audit-exploit":
            return cmd_audit_exploit(run_dir)
        if args.command == "check-before":
            return cmd_check_before(run_dir)
        if args.command == "run":
            return cmd_run(run_dir)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
