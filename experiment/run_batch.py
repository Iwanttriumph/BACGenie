#!/usr/bin/env python3
"""
Kaiti v2 batch experiment runner (overnight supervisor).

For each CVE:
  - isolated OpenCode runtime (own XDG_* dirs and DB)
  - one kaiti-planner session with DeepSeek V4.1 Flash
  - wall-clock timeout, log capture
  - after exit, collect verdict.json + token usage from the isolated DB

Usage:
  python3 experiment/run_batch.py --round 1 --jobs 5 --timeout 2700
  python3 experiment/run_batch.py --cves CVE-2024-10273 --jobs 1 --timeout 1800
"""
import argparse
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT.parent
BENCH = ROOT / "experiment" / "benchmark_23.json"
RUNTIME_ROOT = ROOT / "experiment" / "runtime"
LOG_ROOT = ROOT / "experiment" / "logs"
RESULT_ROOT = ROOT / "experiment" / "results"
SOURCE_ROOT = BASE / "bench_cache" / "sources"
CONFIG_SRC = BASE / ".opencode-runtime" / "config" / "opencode"

MODEL = "yeowl/deepseek-v4.1-flash"

# DeepSeek V4.1 Flash reference price (USD per 1M tokens), documented in eval.xlsx.
# Chosen to match the CVEGenie benchmark's own accounting: CVE-2024-10273's
# $2.43 == 7.59M prompt * 0.30 + 0.125M completion * 1.20.
PRICE_INPUT = 0.30
PRICE_OUTPUT = 1.20
PRICE_CACHE_READ = 0.006


def load_bench():
    return json.loads(BENCH.read_text(encoding="utf-8"))


def source_dir(entry):
    project = entry["project"]
    ver = entry["version"]
    if project == "Lunary":
        return SOURCE_ROOT / f"Lunary_{ver}"
    if project == "MobSF":
        return SOURCE_ROOT / f"MobSF_{ver}"
    if project == "Nextcloud Server":
        return SOURCE_ROOT / f"Nextcloud_{ver}"
    if project == "Mastodon":
        return SOURCE_ROOT / f"Mastodon_{ver}"
    if project == "ZITADEL":
        return SOURCE_ROOT / f"ZITADEL_{ver}"
    if project == "Autolab":
        return SOURCE_ROOT / f"Autolab_{ver}"
    return None


def prepare_runtime(cve):
    rt = RUNTIME_ROOT / cve
    (rt / "config" / "opencode").mkdir(parents=True, exist_ok=True)
    (rt / "data").mkdir(parents=True, exist_ok=True)
    (rt / "state").mkdir(parents=True, exist_ok=True)
    (rt / "cache").mkdir(parents=True, exist_ok=True)
    cfg = rt / "config" / "opencode" / "opencode.json"
    if not cfg.exists():
        shutil.copyfile(CONFIG_SRC / "opencode.json", cfg)
        os.chmod(cfg, 0o600)
        pkg = CONFIG_SRC / "package.json"
        if pkg.exists():
            shutil.copyfile(pkg, rt / "config" / "opencode" / "package.json")
        nm = rt / "config" / "opencode" / "node_modules"
        if not nm.exists():
            os.symlink(Path.home() / ".config/opencode/node_modules", nm)
    return rt


def ports_for(index):
    app = 21000 + index
    db = 23000 + index
    return app, db


def build_prompt(entry, index, timeout_min):
    cve = entry["cve"]
    src = source_dir(entry)
    app_port, db_port = ports_for(index)
    comp = "kaiti_" + cve.lower().replace("-", "_")
    input_json = ROOT / "results - v2" / cve / f"{cve}.json"
    lines = [
        f"目标漏洞：{cve}（{entry['project']} {entry['version']}，CWE: {', '.join(entry['cwe'])}）。",
        "请按 Kaiti 主审架构师规范完成全流程：源码锚定与 Oracle 契约、4090-1 隔离靶场与 Solution 2 前置状态、Clean-Room 盲态攻击脚本、双盲动态信标终审，并签发 reproduction_report.md。",
        "",
        "【本次实验硬约束】",
        "1) 禁止 websearch / webfetch（已禁用，调用会失败）；所有材料均已本地化。",
        f"2) CVE 公告与官方补丁 diff：{input_json}（含 description / cwes / patches.content）。",
    ]
    if src and src.exists():
        lines.append(f"3) 目标版本源码缓存：{src}（直接复用，勿联网下载）。")
    else:
        lines.append("3) 目标版本源码未预缓存，请优先用本地 bench_cache，其次用 https://ghfast.top/ 前缀克隆 GitHub。")
    env_file = ROOT / "runs" / cve / "env" / "docker-compose.yml"
    if env_file.exists() and entry["project"] != "Lunary":
        infra = ROOT / "runs" / cve / "INFRA.md"
        lines.append(
            f"5) 已预置并实测启动的靶场：`{env_file}`，说明见 `{infra}`。"
            f"请直接 `cd runs/{cve}/env && COMPOSE_PROJECT_NAME={comp} docker compose up -d` 使用；"
            "**禁止 docker compose build、禁止重新安装依赖、禁止修改容器基础镜像**。"
        )
    if entry["project"] == "Lunary":
        lines.append(
            f"4) 本地 bare git 仓库 {SOURCE_ROOT / '_lunary_bare.git'}，可用 "
            f"`git --git-dir=<bare> diff {entry['version']} <fixed-tag>` 核对官方修复。"
        )
        lines.append(
            f"5) 已预置并实测通过的靶场：`runs/{cve}/env/docker-compose.yml` 与 `runs/{cve}/INFRA.md`。"
            f"请直接 `cd runs/{cve}/env && COMPOSE_PROJECT_NAME={comp} docker compose up -d --wait` 使用；"
            "**禁止 docker compose build、禁止 npm install、禁止修改 Dockerfile**。该环境挂载 tmpfs 中已装好的 node_modules，启动约 10-20 秒。"
        )
        lines.append(
            f"6) 若 `runs/{cve}/01_tp.json`、`02_oracle_contract.json`、`prep.py`、`verify.py` 已存在且 check-before 通过，必须复用，不要重写。"
        )
    lines += [
        f"7) 端口分配（仅绑 127.0.0.1）：应用 {app_port}，数据库 {db_port}。COMPOSE_PROJECT_NAME={comp}，容器/镜像名必须带 `kaiti` 前缀且唯一，严禁触碰非 kaiti 容器与端口。",
        f"8) 总预算 {timeout_min} 分钟；若 runs/{cve}/01_tp.json 与 02_oracle_contract.json 已存在且 validate-contract 通过，请复核后直接复用，不要推倒重来。",
        "9) 全程不要询问用户；遇到阻塞自主决策并在 00_ledger.md 记录。",
        f"10) 收尾必须落盘：runs/{cve}/verdict.json、runs/{cve}/evidence_bundle.json、runs/{cve}/reproduction_report.md。报告要让非安全工程师也能看懂：用六段式、原文报文、前后 Diff 和一张通俗的“攻击前/攻击后”对照表说明复现完全成功。",
        "11) 若 3 次修复仍无法通过，如实给出 INCONCLUSIVE 并写清阻塞点，绝不伪造证据。",
    ]
    return "\n".join(lines)


def collect_metrics(rt, cve):
    db = rt / "data" / "opencode" / "opencode.db"
    out = {
        "session_id": None,
        "tokens_input": 0,
        "tokens_output": 0,
        "tokens_reasoning": 0,
        "tokens_cache_read": 0,
        "tokens_cache_write": 0,
        "cost_usd": 0.0,
        "sessions": 0,
    }
    if not db.exists():
        return out
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        root = con.execute(
            "select id from session_v2 where title = ? order by time_created desc limit 1",
            (f"Kaiti-{cve}",),
        ).fetchone()
        if not root:
            root = con.execute(
                "select id from session_v2 where title like ? order by time_created desc limit 1",
                (f"%{cve}%",),
            ).fetchone()
        if root:
            root_id = root["id"]
            out["session_id"] = root_id
            ids = {root_id}
            changed = True
            while changed:
                changed = False
                q = ",".join("?" for _ in ids)
                for row in con.execute(
                    f"select id from session_v2 where parent_id in ({q})", tuple(ids)
                ):
                    if row["id"] not in ids:
                        ids.add(row["id"])
                        changed = True
            q = ",".join("?" for _ in ids)
            agg = con.execute(
                f"""select count(*) n,
                           coalesce(sum(tokens_input),0) ti,
                           coalesce(sum(tokens_output),0) to_,
                           coalesce(sum(tokens_reasoning),0) tr,
                           coalesce(sum(tokens_cache_read),0) tcr,
                           coalesce(sum(tokens_cache_write),0) tcw
                    from session_v2 where id in ({q})""",
                tuple(ids),
            ).fetchone()
            out.update(
                sessions=agg["n"],
                tokens_input=agg["ti"],
                tokens_output=agg["to_"],
                tokens_reasoning=agg["tr"],
                tokens_cache_read=agg["tcr"],
                tokens_cache_write=agg["tcw"],
            )
            out["cost_usd"] = round(
                (
                    out["tokens_input"] * PRICE_INPUT
                    + out["tokens_output"] * PRICE_OUTPUT
                    + out["tokens_cache_read"] * PRICE_CACHE_READ
                )
                / 1_000_000,
                4,
            )
    except Exception as exc:  # metrics must never break the experiment
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def stop_containers(entry):
    """Fast, exception-proof cleanup: remove only this compose project's containers."""
    cve = entry["cve"]
    comp = "kaiti_" + cve.lower().replace("-", "_")
    try:
        subprocess.run(
            [
                "bash",
                "-lc",
                f'ids=$(docker ps -aq --filter label=com.docker.compose.project={comp}); '
                f'[ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=40,
        )
    except Exception:
        pass


def read_result(entry, rnd, started, finished, code, log_path, timed_out, rt):
    cve = entry["cve"]
    run_dir = ROOT / "runs" / cve
    verdict = None
    checks = None
    reason = None
    report = (run_dir / "reproduction_report.md").exists()
    if (run_dir / "verdict.json").exists():
        try:
            v = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
            verdict = v.get("verdict")
            reason = v.get("reason")
            checks = v.get("gate_invariant_checks")
        except Exception as exc:
            reason = f"verdict parse error: {exc}"
    return {
        "cve": cve,
        "project": entry["project"],
        "version": entry["version"],
        "cwe": entry["cwe"],
        "round": rnd,
        "started_at": started,
        "finished_at": finished,
        "duration_s": round(finished - started, 1),
        "exit_code": code,
        "timed_out": timed_out,
        "verdict": verdict,
        "reason": reason,
        "gate_checks": checks,
        "report": report,
        "log": str(log_path),
        "metrics": collect_metrics(rt, cve),
    }


def run_one(entry, index, rnd, timeout_s, timeout_min):
    cve = entry["cve"]
    rt = prepare_runtime(cve)
    # Every round starts from a clean isolated target environment.
    try:
        stop_containers(entry)
    except Exception:
        pass
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    log_path = LOG_ROOT / f"{cve}.r{rnd}.log"
    (ROOT / "runs" / cve).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(
        XDG_CONFIG_HOME=str(rt / "config"),
        XDG_DATA_HOME=str(rt / "data"),
        XDG_STATE_HOME=str(rt / "state"),
        XDG_CACHE_HOME=str(rt / "cache"),
        OPENCODE_DISABLE_AUTOUPDATE="true",
        OPENCODE_DISABLE_MODELS_FETCH="true",
        TMPDIR=str(rt / "tmp"),
    )
    (rt / "tmp").mkdir(exist_ok=True)
    prompt = build_prompt(entry, index, timeout_min)
    cmd = [
        os.environ.get("OPENCODE_BIN", str(Path.home() / ".opencode/bin/opencode")),
        "run",
        "--standalone",
        "--auto",
        "--title",
        f"Kaiti-{cve}",
        "--agent",
        "kaiti-planner",
        "-m",
        MODEL,
        prompt,
    ]
    started = time.time()
    timed_out = False
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                code = proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = proc.wait()
    finished = time.time()
    try:
        stop_containers(entry)
    except Exception:
        pass
    result = read_result(entry, rnd, started, finished, code, log_path, timed_out, rt)
    out_dir = RESULT_ROOT / f"round{rnd}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{cve}.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=2700, help="seconds per CVE")
    ap.add_argument("--cves", nargs="*", default=None)
    ap.add_argument("--only-project", default=None)
    ap.add_argument("--max", type=int, default=None, help="limit number of CVEs")
    ap.add_argument("--resume", action="store_true", help="skip CVEs already PROVEN in this round")
    ap.add_argument("--verify", action="store_true", help="package proven runs into Harbor bundle and invoke Automated Verifier")
    args = ap.parse_args()

    bench = load_bench()
    if args.cves:
        bench = [e for e in bench if e["cve"] in set(args.cves)]
    if args.only_project:
        bench = [e for e in bench if e["project"].lower() == args.only_project.lower()]
    if args.max:
        bench = bench[: args.max]
    # keep Lunary first, then cached projects, then heavy projects
    order = {"Lunary": 0, "MobSF": 1, "Nextcloud Server": 2, "ZITADEL": 3, "Autolab": 4, "Mastodon": 5}
    bench.sort(key=lambda e: order.get(e["project"], 9))
    index_by_cve = {e["cve"]: i for i, e in enumerate(load_bench())}

    if args.resume:
        skip = set()
        rd = RESULT_ROOT / f"round{args.round}"
        if rd.exists():
            for p in rd.glob("*.json"):
                try:
                    if json.loads(p.read_text(encoding="utf-8")).get("verdict") == "PROVEN":
                        skip.add(p.stem)
                except Exception:
                    pass
        bench = [e for e in bench if e["cve"] not in skip]

    timeout_min = args.timeout // 60
    print(f"[batch] {len(bench)} CVEs, jobs={args.jobs}, timeout={timeout_min}min, round={args.round}", flush=True)
    import threading

    lock = threading.Lock()
    results = []
    queue = list(bench)

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                entry = queue.pop(0)
            cve = entry["cve"]
            print(f"[start] {cve} ({entry['project']} {entry['version']})", flush=True)
            try:
                r = run_one(entry, index_by_cve[cve], args.round, args.timeout, timeout_min)
            except Exception as exc:
                print(f"[error] {cve}: {type(exc).__name__}: {exc}", flush=True)
                continue
            with lock:
                results.append(r)
            print(
                f"[done] {cve} verdict={r['verdict']} dur={r['duration_s']}s "
                f"tok_in={r['metrics']['tokens_input']} tok_out={r['metrics']['tokens_output']} "
                f"cost=${r['metrics']['cost_usd']}",
                flush=True,
            )

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, args.jobs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    summary = {
        "round": args.round,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total": len(results),
        "proven": sum(1 for r in results if r["verdict"] == "PROVEN"),
        "results": sorted(results, key=lambda r: r["cve"]),
    }
    (RESULT_ROOT / f"round{args.round}.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, ensure_ascii=False), flush=True)

    if args.verify:
        target_cves = [r["cve"] for r in results]
        bundle_cmd = [
            sys.executable,
            str(ROOT / "experiment" / "build_harbor_bundle.py"),
            "--skip-image-export",
            "--verify",
        ]
        if target_cves:
            bundle_cmd.extend(["--cves"] + target_cves)
        subprocess.run(bundle_cmd, cwd=str(ROOT), check=True)


if __name__ == "__main__":
    main()
