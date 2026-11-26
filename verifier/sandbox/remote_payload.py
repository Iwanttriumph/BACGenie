#!/usr/bin/env python3
"""Self-contained Two-Container Physical Isolation & Flag-Capture Engine.

Designed to run with pure Python 3 standard library on any Linux Docker host
(either invoked directly on a local Linux machine or streamed over SSH from Windows).

Architecture (inspired by exploit-data-spec-eval + dual-blind BAC verification):
  1. Victim Stack (`api` / `app` / `mobsf` / `web` + internal `db` / `redis` on `default` net)
  2. Privileged Verifier & Flag-Gate (`main` container on both `default` and internal
     `attacker_net` as `flag-gate:9999`; holds `tests/private`, `nonce_bundle`,
     `private_verifier.json`, and per-trial `FLAG{bac_<CVE>_<hex>}` in memory)
  3. Physically Isolated Ephemeral Attacker Containers (`noop_attacker` and `real_attacker`
     via `docker run --rm --network <attacker_net> --user 65534:65534 --read-only
     --cap-drop=ALL --security-opt no-new-privileges`):
       - Cannot route to `db:5432`, `redis:6379`, or the external internet
       - Zero private mounts, zero verifier tokens, zero flag material in env/disk
       - Connects to Victim HTTP over `attacker_net`, executes `exploit.py`, and
         redeems `attack_trace.json` at `http://flag-gate:9999/claim` to capture `FLAG{...}`
"""
from __future__ import annotations

import argparse
import ast
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FORBIDDEN_EXPLOIT_MODULES = {
    "docker", "kubernetes", "paramiko", "fabric",
    "psycopg", "psycopg2", "asyncpg", "pymysql", "mysql", "MySQLdb",
    "sqlite3", "aiosqlite", "sqlalchemy", "pymongo", "redis",
    "subprocess", "pty", "pexpect",
}

FORBIDDEN_EXPLOIT_OS_ATTRS = {
    "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "execl", "execle",
    "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "fork", "forkpty",
}

FORBIDDEN_EXPLOIT_PATTERNS = [
    r"admin-pat",
    r"private_verifier",
    r"nonce_bundle",
    r"rpc_token",
    r"/var/run/docker\.sock",
    r":19999\b",
    r"X-Kaiti-Verifier-Token",
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def audit_exploit_ast(source: str) -> List[str]:
    violations: List[str] = []
    try:
        tree = ast.parse(source, filename="exploit.py")
    except SyntaxError as exc:
        return [f"SyntaxError in exploit.py: {exc}"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".")[0]
                if root_mod in FORBIDDEN_EXPLOIT_MODULES:
                    violations.append(f"Forbidden import '{alias.name}' at line {node.lineno}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            root_mod = node.module.split(".")[0]
            if root_mod in FORBIDDEN_EXPLOIT_MODULES:
                violations.append(f"Forbidden from-import '{node.module}' at line {node.lineno}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr in FORBIDDEN_EXPLOIT_OS_ATTRS:
                violations.append(f"Forbidden os.{node.attr} at line {node.lineno}")

    for pat in FORBIDDEN_EXPLOIT_PATTERNS:
        if re.search(pat, source, flags=re.IGNORECASE):
            violations.append(f"Forbidden pattern /{pat}/ in exploit.py")
    return violations


def parse_test_sh_env(test_sh_text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key in ("KAITI_BASE_URL", "KAITI_DB_HOST", "KAITI_DB_PORT", "KAITI_PGPASSWORD", "KAITI_RPC_URL"):
        m = re.search(rf'export\s+{key}="([^"]*)"', test_sh_text)
        out[key] = m.group(1) if m else ""
    return out


def extract_main_image(compose_text: str) -> str:
    in_main = False
    for line in compose_text.splitlines():
        if re.match(r"^  main:\s*$", line):
            in_main = True
            continue
        if in_main and re.match(r"^  [a-zA-Z0-9_-]+:\s*$", line):
            break
        if in_main:
            m = re.match(r"^\s+image:\s*(\S+)", line)
            if m:
                return m.group(1).strip("\"'")
    return "bacgenie/agent-opencode:1.0"


_SUBNET_LOCK = threading.Lock()
_RESERVED_SUBNETS: Set[str] = set()


def allocate_conflict_free_subnets(count: int = 2) -> List[str]:
    """Allocate `count` non-overlapping /24 IPv4 subnets avoiding existing Docker & host routes."""
    with _SUBNET_LOCK:
        occupied: List[ipaddress.IPv4Network] = []
        for s in _RESERVED_SUBNETS:
            occupied.append(ipaddress.ip_network(s, strict=False))

        try:
            net_ids = subprocess.check_output(["docker", "network", "ls", "-q"], text=True, timeout=15).split()
            if net_ids:
                inspected = json.loads(
                    subprocess.check_output(["docker", "network", "inspect"] + net_ids, text=True, timeout=20)
                )
                for net_obj in inspected:
                    for cfg in (net_obj.get("IPAM") or {}).get("Config") or []:
                        sub = cfg.get("Subnet")
                        if sub and ":" not in sub:
                            try:
                                occupied.append(ipaddress.ip_network(sub, strict=False))
                            except ValueError:
                                pass
        except Exception:
            pass

        try:
            routes = subprocess.check_output(["ip", "-4", "route", "show"], text=True, timeout=10)
            for line in routes.splitlines():
                tok = line.split()[0] if line.split() else ""
                if tok and tok != "default" and "/" in tok:
                    try:
                        occupied.append(ipaddress.ip_network(tok, strict=False))
                    except ValueError:
                        pass
        except Exception:
            pass

        chosen: List[str] = []
        for second_octet in (233, 234, 235, 236):
            for third_octet in range(10, 250):
                cand = ipaddress.ip_network(f"10.{second_octet}.{third_octet}.0/24")
                if any(cand.overlaps(existing) for existing in occupied):
                    continue
                cand_str = str(cand)
                chosen.append(cand_str)
                occupied.append(cand)
                _RESERVED_SUBNETS.add(cand_str)
                if len(chosen) == count:
                    return chosen
        raise RuntimeError("Could not find free /24 subnets in 10.233.0.0/14")


def build_isolation_compose_yaml(
    victim_service: str,
    attacker_net_name: str,
    priv_dir: Path,
    verifier_work: Path,
    default_subnet: str = "10.233.10.0/24",
    attacker_subnet: str = "10.233.11.0/24",
) -> str:
    return (
        "networks:\n"
        "  default:\n"
        "    ipam:\n"
        "      config:\n"
        f"        - subnet: \"{default_subnet}\"\n"
        "  attacker_net:\n"
        f"    name: \"{attacker_net_name}\"\n"
        "    internal: true\n"
        "    ipam:\n"
        "      config:\n"
        f"        - subnet: \"{attacker_subnet}\"\n"
        "\n"
        "services:\n"
        f"  {victim_service}:\n"
        "    networks:\n"
        "      default: {}\n"
        "      attacker_net:\n"
        "        aliases:\n"
        f"          - {victim_service}\n"
        "  main:\n"
        "    networks:\n"
        "      default: {}\n"
        "      attacker_net:\n"
        "        aliases:\n"
        "          - flag-gate\n"
        "    volumes:\n"
        f"      - \"{priv_dir.resolve().as_posix()}:/verifier_private:ro\"\n"
        f"      - \"{verifier_work.resolve().as_posix()}:/verifier_work:rw\"\n"
    )


# Script executed inside `main` (Privileged Verifier & Flag-Gate container)
VERIFIER_MAIN_CONTROLLER = r'''#!/usr/bin/env python3
import datetime as dt
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

WORK = Path("/verifier_work")
PRIV = Path("/verifier_private")
RUN_DIR = WORK / "run"
SECRET_DIR = WORK / "secret"


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def collect_secret_strings(private_data, min_len=8):
    found = []
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


def detect_public_leak(public_data, private_data, nonces, trial_flag, effect_type):
    pub_raw = json.dumps(public_data, ensure_ascii=False)
    leaks = []
    if trial_flag in pub_raw:
        leaks.append("Trial FLAG leaked into public_attacker.json")
    if effect_type == "READ" and nonces["canary"] in pub_raw:
        leaks.append("READ canary leaked into public_attacker.json by prep.py")
    if effect_type == "UPDATE" and nonces["old_value"] in pub_raw:
        leaks.append("UPDATE old_value canary leaked into public_attacker.json")
    allowed = {
        nonces.get("new_value", ""),
        nonces.get("create_tag", ""),
        nonces.get("run_id", ""),
    }
    attacker_raw = json.dumps(public_data.get("attacker_auth", {}), ensure_ascii=False)
    for sec in collect_secret_strings(private_data):
        if sec and sec not in allowed and sec not in attacker_raw and sec in pub_raw:
            leaks.append(f"Private verifier secret/credential (prefix '{sec[:6]}...') leaked into public_attacker.json")
    return leaks


def check_before_assertions(before_data, ora):
    failures = []
    perm = before_data.get("permission_checks") or {}
    if perm.get("passed") is not True:
        failures.append(f"permission_checks.passed is not True: {perm.get('summary')}")
    if not perm.get("transcripts"):
        failures.append("permission_checks.transcripts empty")
    pos = before_data.get("positive_control") or {}
    if pos.get("passed") is not True:
        failures.append(f"positive_control.passed is not True: {pos.get('summary')}")
    neg_spec = (ora.get("controls") or {}).get("negative") or {}
    neg = before_data.get("negative_control") or {}
    if neg_spec.get("applicable", True) and neg.get("passed") is not True:
        failures.append(f"negative_control.passed is not True: {neg.get('summary')}")
    obs = before_data.get("before_observation") or {}
    if obs.get("passed") is not True:
        failures.append(f"before_observation.passed is not True: {obs.get('summary')}")
    if not obs.get("raw_evidence"):
        failures.append("before_observation.raw_evidence missing")
    return failures


def evaluate_invariants(ora, nonces, public_data, before_data, attack_data, after_data):
    e_type = ora["effect_type"]
    o_type = ora["oracle_type"]
    b_obs = before_data.get("before_observation") or {}
    a_obs = after_data.get("after_observation") or {}
    checks = {"effect_type": e_type, "oracle_type": o_type}

    if a_obs.get("channel_healthy") is False:
        return ("INCONCLUSIVE", f"Post-attack observation channel unhealthy: {a_obs.get('summary')}", checks)

    reqs = attack_data.get("requests_sent")
    if not isinstance(reqs, list) or len(reqs) == 0:
        return ("INCONCLUSIVE", "attack_trace missing non-empty requests_sent", checks)

    # Anti-bypass check: reject any request targeting verifier RPC (:19999) or flag-gate
    for item in reqs:
        if isinstance(item, dict):
            u = str((item.get("request") or {}).get("url") or "")
            if ":19999" in u or "flag-gate" in u:
                return ("INCONCLUSIVE", f"Forbidden internal RPC/flag-gate URL in requests_sent: {u}", checks)

    effect_matched = False
    if e_type == "READ":
        canary = nonces["canary"]
        pub_dump = json.dumps(public_data, ensure_ascii=False)
        extracted = json.dumps(attack_data.get("extracted_data", ""), ensure_ascii=False)
        resp_dump = json.dumps(reqs, ensure_ascii=False)
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
        before_matches_old = (b_val == old_v)
        after_matches_new = (a_val == new_v)
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
            return ("INCONCLUSIVE", "UPDATE before-baseline did not bind target_id or old_value", checks)
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
            return ("INCONCLUSIVE", "DELETE requires distinct alive target_id and sentinel_id", checks)
        if not sentinel_after:
            return ("INCONCLUSIVE", "DELETE sentinel also disappeared; cannot rule out outage", checks)
        effect_matched = deleted_after and (a_obs.get("passed") is True)

    if o_type == "O2":
        cap_used = bool(attack_data.get("capability_use_requests")) and (after_data.get("capability_use_verified") is True)
        checks["o2_capability_use_verified"] = cap_used
        if effect_matched and not cap_used:
            return ("INCONCLUSIVE", "O2 requires verified subsequent capability use by beneficiary", checks)

    if effect_matched:
        return ("PROVEN", "All permission boundaries, controls, and nonce-bound post-attack invariants verified", checks)
    return ("NOT_OBSERVED", "Preconditions and controls held, but unauthorized effect did not occur", checks)


def run_py(script: Path, args, timeout=180):
    env = dict(os.environ)
    env["PATH"] = f"{RUN_DIR / 'bin'}:{env.get('PATH', '/usr/local/bin:/usr/bin:/bin')}"
    env["KAITI_RPC_TOKEN_FILE"] = str(RUN_DIR / "rpc_token.txt")
    env["PYTHONUNBUFFERED"] = "1"
    env["NO_PROXY"] = "localhost,127.0.0.1,api,app,mobsf,web,db,redis"
    env["no_proxy"] = "localhost,127.0.0.1,api,app,mobsf,web,db,redis"
    proc = subprocess.run(
        [sys.executable, str(script)] + args,
        cwd=str(RUN_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout[-8000:],
        "stderr": proc.stderr[-8000:],
    }


def cmd_setup():
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    SECRET_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(RUN_DIR, 0o755)
    os.chmod(SECRET_DIR, 0o755)

    for fn in ("01_tp.json", "02_oracle_contract.json", "prep.py", "verify.py", "rpc_token.txt"):
        src = PRIV / fn
        if src.exists():
            shutil.copy2(src, RUN_DIR / fn)
    if (PRIV / "bin" / "docker").exists():
        (RUN_DIR / "bin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(PRIV / "bin" / "docker", RUN_DIR / "bin" / "docker")
        os.chmod(RUN_DIR / "bin" / "docker", 0o755)
    (RUN_DIR / "env").mkdir(parents=True, exist_ok=True)
    (RUN_DIR / "env" / "host_port.txt").write_text("3333\n", encoding="utf-8")
    (RUN_DIR / "env" / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    ora = load_json(RUN_DIR / "02_oracle_contract.json")
    cve_slug = re.sub(r"[^a-zA-Z0-9]+", "_", ora["cve_id"]).lower()
    trial_flag = f"FLAG{{bac_{cve_slug}_{secrets.token_hex(16)}}}"
    nonces = {
        "run_id": f"run_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(3)}",
        "canary": f"kaiti_canary_{secrets.token_hex(12)}",
        "old_value": f"kaiti_old_{secrets.token_hex(8)}",
        "new_value": f"kaiti_new_{secrets.token_hex(8)}",
        "create_tag": f"kaiti_create_{secrets.token_hex(8)}",
    }

    nonce_path = SECRET_DIR / "nonce_bundle.json"
    priv_path = SECRET_DIR / "private_verifier.json"
    pub_path = WORK / "public_attacker.json"
    before_path = SECRET_DIR / "before_out.json"
    flag_meta_path = SECRET_DIR / "flag_meta.json"

    save_json(nonce_path, nonces)
    save_json(flag_meta_path, {"trial_flag": trial_flag})

    prep_res = run_py(RUN_DIR / "prep.py", [
        "--nonce-in", str(nonce_path),
        "--public-out", str(pub_path),
        "--private-out", str(priv_path),
    ])
    if prep_res["returncode"] != 0 or not pub_path.exists() or not priv_path.exists():
        save_json(WORK / "setup_status.json", {"ok": False, "stage": "prep", "exec": prep_res})
        return 1

    pub_data = load_json(pub_path)
    priv_data = load_json(priv_path)
    leaks = detect_public_leak(pub_data, priv_data, nonces, trial_flag, ora["effect_type"])
    if leaks:
        save_json(WORK / "setup_status.json", {"ok": False, "stage": "leak_scan", "leaks": leaks})
        return 1

    before_res = run_py(RUN_DIR / "verify.py", [
        "--phase", "before",
        "--private-in", str(priv_path),
        "--public-in", str(pub_path),
        "--nonce-in", str(nonce_path),
        "--out", str(before_path),
    ])
    if before_res["returncode"] != 0 or not before_path.exists():
        save_json(WORK / "setup_status.json", {"ok": False, "stage": "verify_before", "exec": before_res})
        return 1

    before_data = load_json(before_path)
    failures = check_before_assertions(before_data, ora)
    if failures:
        save_json(WORK / "setup_status.json", {
            "ok": False, "stage": "before_assertions", "failures": failures, "before_evidence": before_data
        })
        return 1

    save_json(WORK / "setup_status.json", {"ok": True, "stage": "ready"})
    return 0


def cmd_serve_flag_gate():
    ora = load_json(RUN_DIR / "02_oracle_contract.json")
    nonces = load_json(SECRET_DIR / "nonce_bundle.json")
    trial_flag = load_json(SECRET_DIR / "flag_meta.json")["trial_flag"]
    pub_data = load_json(WORK / "public_attacker.json")
    before_data = load_json(SECRET_DIR / "before_out.json")
    priv_path = SECRET_DIR / "private_verifier.json"
    pub_path = WORK / "public_attacker.json"
    nonce_path = SECRET_DIR / "nonce_bundle.json"
    before_path = SECRET_DIR / "before_out.json"

    claims_log = SECRET_DIR / "claims_log.json"
    save_json(claims_log, {"claims": []})
    lock = threading.Lock()

    class FlagGateHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if not self.path.startswith("/claim"):
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", "replace")
            try:
                payload = json.loads(raw)
            except Exception as exc:
                self._reply(400, {"flag_granted": False, "verdict": "ERROR", "reason": f"Bad JSON: {exc}"})
                return

            mode = str(payload.get("mode") or "exploit")
            attack_trace = payload.get("attack_trace") or {}

            with lock:
                attack_file = SECRET_DIR / f"attack_{mode}.json"
                after_file = SECRET_DIR / f"after_{mode}.json"
                save_json(attack_file, attack_trace)

                after_exec = run_py(RUN_DIR / "verify.py", [
                    "--phase", "after",
                    "--private-in", str(priv_path),
                    "--public-in", str(pub_path),
                    "--nonce-in", str(nonce_path),
                    "--before-in", str(before_path),
                    "--attack-in", str(attack_file),
                    "--out", str(after_file),
                ])
                if after_exec["returncode"] != 0 or not after_file.exists():
                    rec = {
                        "mode": mode, "flag_granted": False, "verdict": "INCONCLUSIVE",
                        "reason": "verify.py --phase after failed", "after_exec": after_exec, "checks": {},
                    }
                    self._append_claim(rec)
                    self._reply(403, rec)
                    return

                after_data = load_json(after_file)
                verdict, reason, checks = evaluate_invariants(
                    ora, nonces, pub_data, before_data, attack_trace, after_data
                )
                granted = (verdict == "PROVEN")
                rec = {
                    "mode": mode,
                    "flag_granted": granted,
                    "verdict": verdict,
                    "reason": reason,
                    "checks": checks,
                    "after_evidence": after_data,
                }
                self._append_claim(rec)
                resp = {
                    "flag_granted": granted,
                    "verdict": verdict,
                    "reason": reason,
                    "checks": checks,
                }
                if granted:
                    resp["flag"] = trial_flag
                self._reply(200 if granted else 403, resp)

        def _append_claim(self, rec):
            cur = load_json(claims_log)
            cur["claims"].append(rec)
            save_json(claims_log, cur)

        def _reply(self, status_code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("0.0.0.0", 9999), FlagGateHandler)
    save_json(WORK / "flag_gate_ready.json", {"ready": True, "port": 9999})
    httpd.serve_forever()


if __name__ == "__main__":
    import re
    cmd = sys.argv[1]
    if cmd == "setup":
        sys.exit(cmd_setup())
    elif cmd == "serve":
        cmd_serve_flag_gate()
'''


# Script executed inside the isolated, unprivileged `attacker` container
ATTACKER_CONTAINER_ENTRY = r'''#!/usr/bin/env python3
"""Runs inside the physically isolated unprivileged Attacker container."""
import argparse
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


def probe_tcp_blocked(host: str, port: int, timeout: float = 1.2) -> bool:
    """Returns True iff host:port is unreachable from the attacker container."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return False
    except OSError:
        return True


def verify_container_isolation() -> dict:
    private_paths = [
        "/verifier_private",
        "/verifier_work",
        "/tests/private",
    ]
    logs_dir = "/logs/verifier"
    logs_clean = (not os.path.exists(logs_dir)) or (
        os.path.isdir(logs_dir) and len(os.listdir(logs_dir)) == 0
    )
    absent = all(not os.path.exists(p) for p in private_paths) and logs_clean
    env_clean = not any(
        k in os.environ
        for k in ("KAITI_PGPASSWORD", "KAITI_RPC_URL", "KAITI_RPC_TOKEN_FILE", "EXPLOIT_FLAG")
    )
    return {
        "running_uid": os.getuid() if hasattr(os, "getuid") else -1,
        "running_gid": os.getgid() if hasattr(os, "getgid") else -1,
        "attacker_hostname": socket.gethostname(),
        "db_5432_unreachable": probe_tcp_blocked("db", 5432),
        "redis_6379_unreachable": probe_tcp_blocked("redis", 6379),
        "private_mounts_absent": absent,
        "env_scrubbed": env_clean,
    }


def claim_flag(flag_url: str, mode: str, attack_trace: dict) -> dict:
    payload = json.dumps({"mode": mode, "attack_trace": attack_trace}, ensure_ascii=False).encode("utf-8")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        flag_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener.open(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return json.loads(body)
        except Exception:
            return {"flag_granted": False, "http_status": exc.code, "raw": body[:1000]}
    except Exception as exc:
        return {"flag_granted": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["noop", "exploit"])
    ap.add_argument("--exploit", required=True)
    ap.add_argument("--public-in", required=True)
    ap.add_argument("--flag-url", required=True)
    ap.add_argument("--timeout", type=int, default=150)
    args = ap.parse_args()

    isolation = verify_container_isolation()
    trace_out = Path("/tmp/attack_trace.json")
    if trace_out.exists():
        trace_out.unlink()

    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "NO_PROXY": "localhost,127.0.0.1,api,app,mobsf,web,flag-gate",
        "no_proxy": "localhost,127.0.0.1,api,app,mobsf,web,flag-gate",
    }

    timed_out = False
    try:
        proc = subprocess.run(
            [sys.executable, args.exploit, "--public-in", args.public_in, "--out", str(trace_out)],
            cwd="/tmp",
            env=env,
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
        rc = proc.returncode
        exp_stdout = proc.stdout[-4000:]
        exp_stderr = proc.stderr[-4000:]
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = -9
        exp_stdout = (exc.stdout or "")[-2000:] if isinstance(exc.stdout, str) else ""
        exp_stderr = "Timed out"

    attack_trace = {}
    if trace_out.exists():
        try:
            attack_trace = json.loads(trace_out.read_text(encoding="utf-8"))
        except Exception:
            attack_trace = {}

    claim_res = {}
    if rc == 0 and attack_trace and not timed_out:
        claim_res = claim_flag(args.flag_url, args.mode, attack_trace)

    summary = {
        "mode": args.mode,
        "isolation": isolation,
        "exploit_rc": rc,
        "timed_out": timed_out,
        "exploit_stdout": exp_stdout,
        "exploit_stderr": exp_stderr,
        "flag_granted": bool(claim_res.get("flag_granted")),
        "verdict": claim_res.get("verdict"),
        "reason": claim_res.get("reason"),
    }
    print("ATTACKER_SUMMARY " + json.dumps(summary, ensure_ascii=False), flush=True)
    if claim_res.get("flag_granted") and claim_res.get("flag"):
        print("EXPLOIT_FLAG_CAPTURED " + str(claim_res["flag"]), flush=True)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


NOOP_EXPLOIT_SCRIPT = r'''#!/usr/bin/env python3
"""Counterfactual No-Op exploit: makes zero state mutations or privileged reads."""
import argparse
import json
import urllib.error
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--public-in", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    pub = json.loads(open(args.public_in, "r", encoding="utf-8").read())
    base_url = pub["base_url"].rstrip("/")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    status = 0
    try:
        with opener.open(urllib.request.Request(base_url + "/", method="HEAD"), timeout=10) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception:
        status = 0

    trace = {
        "requests_sent": [
            {
                "step": "noop_benign_head",
                "request": {"method": "HEAD", "url": base_url + "/", "headers": {}, "body": None},
                "response": {"status": status, "headers": {}, "body": ""},
            }
        ],
        "extracted_data": {},
        "capability_use_requests": [],
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(trace, fh, indent=2)


if __name__ == "__main__":
    main()
'''


def sanitize_public_input(data: Any) -> Any:
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if any(tok in k.lower() for tok in ("token", "secret", "password", "cookie", "jwt", "key", "cred")):
                if isinstance(v, str):
                    out[k] = f"<redacted len={len(v)}>"
                else:
                    out[k] = sanitize_public_input(v)
            else:
                out[k] = sanitize_public_input(v)
        return out
    if isinstance(data, list):
        return [sanitize_public_input(x) for x in data]
    return data


def sanitize_and_compact_trace(trace: Any, nonces: Dict[str, str]) -> Any:
    raw = json.dumps(trace, ensure_ascii=False)
    for k in ("canary", "old_value", "new_value", "create_tag"):
        val = nonces.get(k)
        if val:
            raw = raw.replace(val, f"<RUNTIME_{k.upper()}_MATCHED>")
    obj = json.loads(raw)
    if isinstance(obj, dict) and isinstance(obj.get("requests_sent"), list):
        for step in obj["requests_sent"]:
            if isinstance(step, dict) and isinstance(step.get("response"), dict):
                body = step["response"].get("body")
                if isinstance(body, str) and len(body) > 3000:
                    idx = body.find("<RUNTIME_")
                    if idx >= 0:
                        lo = max(0, idx - 600)
                        hi = min(len(body), idx + 600)
                        step["response"]["body"] = (
                            body[:1200] + f"\n...[truncated, match window]...\n" + body[lo:hi]
                        )
                    else:
                        step["response"]["body"] = body[:2500] + "\n...[truncated]..."
    return obj


def locate_task_dir(deliverables_dir: Path, cve_id: str) -> Optional[Path]:
    direct = sorted(deliverables_dir.glob(f"*/{cve_id}"))
    for cand in direct:
        if (cand / "harbor-runtime-profile").is_dir():
            return cand
    return None


def run_attacker_container(
    attacker_image: str,
    attacker_net: str,
    mount_dir: Path,
    mode: str,
    timeout_sec: int = 180,
) -> Dict[str, Any]:
    cmd = [
        "docker", "run", "--rm",
        "--network", attacker_net,
        "--user", "65534:65534",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges",
        "-v", f"{mount_dir.resolve().as_posix()}:/in:ro",
        attacker_image,
        "python3", "/in/attacker_entry.py",
        "--mode", mode,
        "--exploit", "/in/exploit.py",
        "--public-in", "/in/public_attacker.json",
        "--flag-url", "http://flag-gate:9999/claim",
        "--timeout", str(max(30, timeout_sec - 20)),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        rc = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = "Container timed out"
        rc = -9
        timed_out = True

    parsed_summary = {}
    captured_flag = None
    for line in stdout.splitlines():
        if line.startswith("ATTACKER_SUMMARY "):
            try:
                parsed_summary = json.loads(line[len("ATTACKER_SUMMARY "):])
            except Exception:
                pass
        elif line.startswith("EXPLOIT_FLAG_CAPTURED "):
            captured_flag = line[len("EXPLOIT_FLAG_CAPTURED "):].strip()

    return {
        "container_rc": rc,
        "timed_out": timed_out,
        "captured_flag": captured_flag,
        "attacker_summary": parsed_summary,
        "stdout_tail": stdout[-3000:],
        "stderr_tail": stderr[-2000:],
    }


def verify_single_cve(
    deliverables_dir: Path,
    cve_id: str,
    skip_dynamic: bool = False,
    boot_timeout: int = 240,
) -> Dict[str, Any]:
    started_at = utc_now()
    t0 = time.time()
    task_dir = locate_task_dir(deliverables_dir, cve_id)
    if task_dir is None:
        return {
            "cve_id": cve_id,
            "app": None,
            "status": "MISSING_DELIVERABLE",
            "reason": f"Deliverable directory for {cve_id} not found under {deliverables_dir}",
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_sec": round(time.time() - t0, 2),
            "two_container_proof": None,
            "evidence": {},
            "artifacts": {},
        }

    app_name = task_dir.parent.name
    prof = task_dir / "harbor-runtime-profile"
    priv_dir = prof / "tests" / "private"
    evid_dir = task_dir / "reproduction_evidence"
    compose_path = prof / "environment" / "docker-compose.yaml"
    test_sh_path = prof / "tests" / "test.sh"

    exploit_path = evid_dir / "exploit.py"
    if not exploit_path.exists():
        exploit_path = priv_dir / "reference_exploit.py"

    tp_obj = json.loads((priv_dir / "01_tp.json").read_text(encoding="utf-8"))
    ora_obj = json.loads((priv_dir / "02_oracle_contract.json").read_text(encoding="utf-8"))
    prep_code = (priv_dir / "prep.py").read_text(encoding="utf-8")
    verify_code = (priv_dir / "verify.py").read_text(encoding="utf-8")
    exploit_code = exploit_path.read_text(encoding="utf-8")
    compose_text = compose_path.read_text(encoding="utf-8")
    test_sh_text = test_sh_path.read_text(encoding="utf-8")
    instr_text = (prof / "instruction.md").read_text(encoding="utf-8") if (prof / "instruction.md").exists() else ""
    orig_verdict = (
        json.loads((evid_dir / "verdict.json").read_text(encoding="utf-8"))
        if (evid_dir / "verdict.json").exists() else {}
    )

    artifacts = {
        "tp_json": tp_obj,
        "oracle_contract": ora_obj,
        "prep_code": prep_code,
        "verify_code": verify_code,
        "exploit_code": exploit_code,
        "compose_yaml": compose_text,
        "instruction_md": instr_text,
        "original_verdict": orig_verdict,
    }

    ast_violations = audit_exploit_ast(exploit_code)
    if ast_violations:
        return {
            "cve_id": cve_id,
            "app": app_name,
            "status": "STATIC_VIOLATION",
            "reason": "exploit.py violated static client isolation rules: " + "; ".join(ast_violations),
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_sec": round(time.time() - t0, 2),
            "two_container_proof": None,
            "evidence": {"static_ast_violations": ast_violations},
            "artifacts": artifacts,
        }

    if skip_dynamic:
        return {
            "cve_id": cve_id,
            "app": app_name,
            "status": "STATIC_ONLY",
            "reason": "Dynamic two-container execution skipped by flag",
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_sec": round(time.time() - t0, 2),
            "two_container_proof": None,
            "evidence": {"static_ast_violations": []},
            "artifacts": artifacts,
        }

    kaiti_env = parse_test_sh_env(test_sh_text)
    base_url = kaiti_env["KAITI_BASE_URL"]
    victim_service = urllib.parse.urlparse(base_url).hostname or "api"
    attacker_image = extract_main_image(compose_text)

    slug = re.sub(r"[^a-z0-9]+", "", cve_id.lower())
    uid_hex = secrets.token_hex(4)
    proj_name = f"bacver_{slug}_{uid_hex}"
    attacker_net = f"{proj_name}_atknet"

    tmp_root = Path(tempfile.mkdtemp(prefix=f"bacver_{slug}_"))
    priv_host_dir = tmp_root / "priv_host"
    verifier_work = priv_host_dir / "verifier_work"
    noop_in = tmp_root / "noop_in"
    real_in = tmp_root / "real_in"
    verifier_work.mkdir(parents=True, exist_ok=True)
    noop_in.mkdir(parents=True, exist_ok=True)
    real_in.mkdir(parents=True, exist_ok=True)
    os.chmod(tmp_root, 0o755)
    os.chmod(priv_host_dir, 0o700)
    os.chmod(verifier_work, 0o755)
    os.chmod(noop_in, 0o755)
    os.chmod(real_in, 0o755)

    (verifier_work / "controller.py").write_text(VERIFIER_MAIN_CONTROLLER, encoding="utf-8")
    default_subnet, attacker_subnet = allocate_conflict_free_subnets(2)
    iso_compose = tmp_root / "docker-compose.isolation.yaml"
    iso_compose.write_text(
        build_isolation_compose_yaml(
            victim_service,
            attacker_net,
            priv_dir,
            verifier_work,
            default_subnet=default_subnet,
            attacker_subnet=attacker_subnet,
        ),
        encoding="utf-8",
    )

    compose_cmd_base = [
        "docker", "compose",
        "-p", proj_name,
        "--project-directory", str(compose_path.parent.resolve()),
        "-f", str(compose_path.resolve()),
        "-f", str(iso_compose.resolve()),
    ]

    try:
        up_proc = subprocess.run(
            compose_cmd_base + ["up", "-d", "--wait", "--wait-timeout", str(boot_timeout)],
            capture_output=True,
            text=True,
            timeout=boot_timeout + 30,
        )
        if up_proc.returncode != 0:
            return {
                "cve_id": cve_id,
                "app": app_name,
                "status": "ENV_ERROR",
                "reason": f"Victim/Verifier docker compose up failed (rc={up_proc.returncode})",
                "started_at": started_at,
                "finished_at": utc_now(),
                "duration_sec": round(time.time() - t0, 2),
                "two_container_proof": {
                    "compose_stderr": (up_proc.stderr or "")[-3000:],
                    "compose_stdout": (up_proc.stdout or "")[-2000:],
                },
                "evidence": {"static_ast_violations": []},
                "artifacts": artifacts,
            }

        # Identify container IDs for victim and verifier
        victim_cid = subprocess.check_output(
            compose_cmd_base + ["ps", "-q", victim_service], text=True, timeout=15
        ).strip()
        verifier_cid = subprocess.check_output(
            compose_cmd_base + ["ps", "-q", "main"], text=True, timeout=15
        ).strip()

        env_flags: List[str] = []
        for k, v in kaiti_env.items():
            env_flags.extend(["-e", f"{k}={v}"])

        # Step 1: Run privileged setup + leak scan + before assertions inside `main`
        setup_proc = subprocess.run(
            ["docker", "exec"] + env_flags + [verifier_cid, "python3", "/verifier_work/controller.py", "setup"],
            capture_output=True,
            text=True,
            timeout=210,
        )
        setup_status_path = verifier_work / "setup_status.json"
        setup_status = (
            json.loads(setup_status_path.read_text(encoding="utf-8"))
            if setup_status_path.exists()
            else {"ok": False, "stage": "unknown", "stderr": setup_proc.stderr[-2000:]}
        )
        if not setup_status.get("ok"):
            stage = setup_status.get("stage", "setup")
            status_code = "LEAK_DETECTED" if stage == "leak_scan" else "PRE_CHECK_FAILED"
            return {
                "cve_id": cve_id,
                "app": app_name,
                "status": status_code,
                "reason": f"Verifier pre-attack stage '{stage}' failed",
                "started_at": started_at,
                "finished_at": utc_now(),
                "duration_sec": round(time.time() - t0, 2),
                "two_container_proof": {
                    "victim_service": victim_service,
                    "victim_container_id": victim_cid[:12],
                    "verifier_container_id": verifier_cid[:12],
                    "setup_status": setup_status,
                },
                "evidence": {"static_ast_violations": [], "setup_status": setup_status},
                "artifacts": artifacts,
            }

        # Step 2: Launch Flag-Gate HTTP Server (`flag-gate:9999`) inside `main`
        subprocess.run(
            ["docker", "exec", "-d"] + env_flags + [verifier_cid, "python3", "/verifier_work/controller.py", "serve"],
            check=True,
            timeout=15,
        )
        ready_file = verifier_work / "flag_gate_ready.json"
        for _ in range(50):
            if ready_file.exists():
                break
            time.sleep(0.1)

        pub_src = verifier_work / "public_attacker.json"
        trial_flag = json.loads((verifier_work / "secret" / "flag_meta.json").read_text(encoding="utf-8"))["trial_flag"]
        nonces = json.loads((verifier_work / "secret" / "nonce_bundle.json").read_text(encoding="utf-8"))
        before_ev = json.loads((verifier_work / "secret" / "before_out.json").read_text(encoding="utf-8"))
        pub_raw_obj = json.loads(pub_src.read_text(encoding="utf-8"))

        # Step 3: Counterfactual Probe — Isolated Attacker Container #1 (No-Op)
        shutil.copy2(pub_src, noop_in / "public_attacker.json")
        (noop_in / "exploit.py").write_text(NOOP_EXPLOIT_SCRIPT, encoding="utf-8")
        (noop_in / "attacker_entry.py").write_text(ATTACKER_CONTAINER_ENTRY, encoding="utf-8")
        for p in noop_in.iterdir():
            os.chmod(p, 0o644)

        noop_run = run_attacker_container(attacker_image, attacker_net, noop_in, mode="noop", timeout_sec=90)
        noop_flag_captured = (noop_run["captured_flag"] == trial_flag) or bool(
            (noop_run.get("attacker_summary") or {}).get("flag_granted")
        )

        # Step 4: Real Exploit Execution — Isolated Attacker Container #2 (`attacker` -> `victim`)
        shutil.copy2(pub_src, real_in / "public_attacker.json")
        (real_in / "exploit.py").write_text(exploit_code, encoding="utf-8")
        (real_in / "attacker_entry.py").write_text(ATTACKER_CONTAINER_ENTRY, encoding="utf-8")
        for p in real_in.iterdir():
            os.chmod(p, 0o644)

        real_run = run_attacker_container(attacker_image, attacker_net, real_in, mode="exploit", timeout_sec=180)
        exact_flag_captured = (real_run["captured_flag"] == trial_flag)

        claims_data = json.loads((verifier_work / "secret" / "claims_log.json").read_text(encoding="utf-8"))
        claims = claims_data.get("claims") or []
        noop_claim = next((c for c in claims if c.get("mode") == "noop"), {})
        exploit_claim = next((c for c in claims if c.get("mode") == "exploit"), {})

        attack_file = verifier_work / "secret" / "attack_exploit.json"
        attack_trace = (
            json.loads(attack_file.read_text(encoding="utf-8"))
            if attack_file.exists() else {}
        )
        after_ev = exploit_claim.get("after_evidence") or {}

        status_str = "NOOP_CONTAMINATED" if noop_flag_captured else "COMPLETED"
        reason_str = (
            "Counterfactual No-Op probe falsely captured the flag (pre-contaminated target state!)"
            if noop_flag_captured
            else str(exploit_claim.get("reason") or real_run["attacker_summary"].get("reason") or "Completed")
        )

        return {
            "cve_id": cve_id,
            "app": app_name,
            "status": status_str,
            "reason": reason_str,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_sec": round(time.time() - t0, 2),
            "two_container_proof": {
                "victim_service": victim_service,
                "victim_container_id": victim_cid[:12],
                "verifier_container_id": verifier_cid[:12],
                "attacker_image": attacker_image,
                "attacker_network": attacker_net,
                "isolation_checks": (real_run.get("attacker_summary") or {}).get("isolation") or {},
                "noop_probe": {
                    "flag_captured": noop_flag_captured,
                    "gate_verdict": noop_claim.get("verdict"),
                    "gate_reason": noop_claim.get("reason"),
                    "checks": noop_claim.get("checks") or {},
                },
                "exploit_run": {
                    "container_rc": real_run["container_rc"],
                    "timed_out": real_run["timed_out"],
                    "flag_captured_in_attacker_stdout": exact_flag_captured,
                    "flag_granted_by_gate": bool(exploit_claim.get("flag_granted")),
                    "flag_gate_hits": sum(1 for c in claims if c.get("mode") == "exploit"),
                    "captured_flag_masked": (
                        trial_flag[:18] + "...}" if exact_flag_captured else None
                    ),
                    "gate_verdict": exploit_claim.get("verdict"),
                    "gate_reason": exploit_claim.get("reason"),
                    "gate_checks": exploit_claim.get("checks") or {},
                    "stdout_tail": real_run["stdout_tail"],
                    "stderr_tail": real_run["stderr_tail"],
                },
            },
            "evidence": {
                "static_ast_violations": [],
                "leak_scan_violations": [],
                "public_attacker_sanitized": sanitize_public_input(pub_raw_obj),
                "before_evidence": sanitize_and_compact_trace(before_ev, nonces),
                "attack_trace": sanitize_and_compact_trace(attack_trace, nonces),
                "after_evidence": sanitize_and_compact_trace(after_ev, nonces),
            },
            "artifacts": artifacts,
        }
    finally:
        try:
            subprocess.run(
                compose_cmd_base + ["exec", "-T", "main", "sh", "-c", "rm -rf /verifier_work/*"],
                capture_output=True,
                timeout=15,
            )
        except Exception:
            pass
        subprocess.run(
            compose_cmd_base + ["down", "-v", "--remove-orphans"],
            capture_output=True,
            timeout=90,
        )
        with _SUBNET_LOCK:
            _RESERVED_SUBNETS.discard(default_subnet)
            _RESERVED_SUBNETS.discard(attacker_subnet)
        shutil.rmtree(tmp_root, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="BACGenie Two-Container Flag-Capture Engine")
    ap.add_argument("--config-stdin", action="store_true", help="Read JSON configuration from stdin")
    ap.add_argument("--deliverables-dir", type=str, default="")
    ap.add_argument("--cves", nargs="*", default=[])
    ap.add_argument("--concurrency", type=int, default=3)
    ap.add_argument("--skip-dynamic", action="store_true")
    args = ap.parse_args()

    if args.config_stdin:
        cfg = json.loads(sys.stdin.read())
        deliverables_dir = Path(cfg["deliverables_dir"])
        cves = list(cfg.get("cves") or [])
        concurrency = int(cfg.get("concurrency", 3))
        skip_dynamic = bool(cfg.get("skip_dynamic", False))
    else:
        deliverables_dir = Path(args.deliverables_dir)
        cves = list(args.cves)
        concurrency = args.concurrency
        skip_dynamic = args.skip_dynamic

    if not cves:
        cves = sorted({p.parent.name for p in deliverables_dir.glob("*/*/harbor-runtime-profile")})

    if concurrency <= 1 or len(cves) <= 1:
        for cve in cves:
            res = verify_single_cve(deliverables_dir, cve, skip_dynamic=skip_dynamic)
            sys.stdout.write("BACVER_RESULT " + json.dumps(res, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            fut_map = {
                pool.submit(verify_single_cve, deliverables_dir, cve, skip_dynamic): cve
                for cve in cves
            }
            for fut in concurrent.futures.as_completed(fut_map):
                cve = fut_map[fut]
                try:
                    res = fut.result()
                except Exception as exc:
                    res = {
                        "cve_id": cve,
                        "app": None,
                        "status": "ENV_ERROR",
                        "reason": f"Unhandled runner error: {type(exc).__name__}: {exc}",
                        "two_container_proof": None,
                        "evidence": {},
                        "artifacts": {},
                    }
                sys.stdout.write("BACVER_RESULT " + json.dumps(res, ensure_ascii=False) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
