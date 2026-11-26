#!/usr/bin/env python3
"""Collect verdicts + token/cost metrics for runs that were orphaned or not
recorded by the batch orchestrator. Merges into experiment/results/roundN/."""
import argparse
import json
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXP = ROOT / "experiment"
BENCH = json.loads((EXP / "benchmark_23.json").read_text(encoding="utf-8"))
PRICE_INPUT, PRICE_OUTPUT, PRICE_CACHE = 0.30, 1.20, 0.006


def metrics(rt, cve):
    db = rt / "data/opencode/opencode.db"
    out = {"session_id": None, "tokens_input": 0, "tokens_output": 0,
           "tokens_reasoning": 0, "tokens_cache_read": 0, "tokens_cache_write": 0,
           "cost_usd": 0.0, "sessions": 0, "duration_s": None, "started": None, "finished": None}
    if not db.exists():
        return out
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        root = con.execute(
            "select * from session_v2 where title = ? order by time_created desc limit 1",
            (f"Kaiti-{cve}",),
        ).fetchone()
        if not root:
            return out
        out["session_id"] = root["id"]
        out["started"] = root["time_created"]
        ids = {root["id"]}
        changed = True
        while changed:
            changed = False
            q = ",".join("?" for _ in ids)
            for row in con.execute(f"select id from session_v2 where parent_id in ({q})", tuple(ids)):
                if row["id"] not in ids:
                    ids.add(row["id"])
                    changed = True
        q = ",".join("?" for _ in ids)
        agg = con.execute(
            f"""select count(*) n, coalesce(sum(tokens_input),0) ti, coalesce(sum(tokens_output),0) to_,
                       coalesce(sum(tokens_reasoning),0) tr, coalesce(sum(tokens_cache_read),0) tcr,
                       coalesce(sum(tokens_cache_write),0) tcw, max(time_updated) last
                from session_v2 where id in ({q})""",
            tuple(ids),
        ).fetchone()
        out.update(
            sessions=agg["n"], tokens_input=agg["ti"], tokens_output=agg["to_"],
            tokens_reasoning=agg["tr"], tokens_cache_read=agg["tcr"], tokens_cache_write=agg["tcw"],
            finished=agg["last"],
        )
        span = con.execute(
            f"select min(time_created) a, max(time_updated) b from session_v2 where id in ({q})",
            tuple(ids),
        ).fetchone()
        if span and span["a"] and span["b"]:
            out["started"] = span["a"]
            out["finished"] = span["b"]
            out["duration_s"] = round((span["b"] - span["a"]) / 1000.0, 1)
        out["cost_usd"] = round(
            (out["tokens_input"] * PRICE_INPUT + out["tokens_output"] * PRICE_OUTPUT
             + out["tokens_cache_read"] * PRICE_CACHE) / 1_000_000, 4)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def verdict(cve):
    p = ROOT / "runs" / cve / "verdict.json"
    if not p.exists():
        return None, None, None
    try:
        v = json.loads(p.read_text(encoding="utf-8"))
        return v.get("verdict"), v.get("reason"), v.get("gate_invariant_checks")
    except Exception:
        return None, None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, default=1)
    args = ap.parse_args()
    outdir = EXP / "results" / f"round{args.round}"
    outdir.mkdir(parents=True, exist_ok=True)
    for e in BENCH:
        cve = e["cve"]
        p = outdir / f"{cve}.json"
        old = {}
        if p.exists():
            try:
                old = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                old = {}
        v, reason, checks = verdict(cve)
        m = metrics(EXP / "runtime" / cve, cve)
        data = old or {}
        had_proven = data.get("verdict") == "PROVEN"
        data.update({
            "cve": cve, "project": e["project"], "version": e["version"], "cwe": e["cwe"],
            "round": args.round,
            "verdict": v, "reason": reason, "gate_checks": checks,
            "report": (ROOT / "runs" / cve / "reproduction_report.md").exists(),
            "log": str(EXP / "logs" / f"{cve}.r{args.round}.log"),
            "metrics": m,
        })
        if m.get("duration_s"):
            data["duration_s"] = m["duration_s"]
        if m.get("started"):
            data["started_at"] = m["started"]
        if m.get("finished"):
            data["finished_at"] = m["finished"]
        data.setdefault("exit_code", None)
        data.setdefault("timed_out", False)
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    proven = 0
    for p in outdir.glob("*.json"):
        try:
            if json.loads(p.read_text(encoding="utf-8")).get("verdict") == "PROVEN":
                proven += 1
        except Exception:
            pass
    print(f"round{args.round}: {len(list(outdir.glob('*.json')))} results, {proven} PROVEN")


if __name__ == "__main__":
    main()
