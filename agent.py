"""LLM extraction followed by static Trigger Pattern classification."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

import requests
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent
BASE_URL = "https://opencode.ai/zen/go/v1"
MODEL = "deepseek-v4.1-flash"


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     delete=False, suffix=".tmp") as f:
        tmp = Path(f.name)
        f.write(text)
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def write_json(path, data):
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def get_key():
    key = os.getenv("OPENCODE_GO_API_KEY", "").strip()
    if not key and os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as reg:
                key = str(winreg.QueryValueEx(reg, "OPENCODE_GO_API_KEY")[0]).strip()
        except FileNotFoundError:
            pass
    if not key:
        raise ValueError("未找到 OPENCODE_GO_API_KEY（进程环境或 Windows Machine 系统变量）")
    return key


def schemas():
    final = read_json(ROOT / "output.schema.json")
    extraction = copy.deepcopy(final)
    del extraction["properties"]["classification"]
    extraction["required"].remove("classification")
    return extraction, final


def validate(data, schema, cve_id):
    errors = sorted(Draft202012Validator(schema).iter_errors(data), key=lambda e: str(e.path))
    if errors:
        raise ValueError("; ".join(f"{'/'.join(map(str, e.path))}: {e.message}" for e in errors[:8]))
    if data["cve_id"] != cve_id:
        raise ValueError("输出 CVE ID 与输入不一致")
    all_requests = data["victim_requests"] + data["attacker_requests"]
    ids = [r["id"] for r in all_requests]
    if len(ids) != len(set(ids)):
        raise ValueError("请求 id 不唯一")
    attackers = {r["id"]: r for r in data["attacker_requests"]}
    modified_requests = {p["request_id"] for p in data["trigger_points"]
                         if p["action"] in {"add", "replace", "remove", "modify"}}
    for point in data["trigger_points"]:
        if point["request_id"] not in attackers:
            raise ValueError("trigger_points must reference an attacker request")
        locations, action = point["locations"], point["action"]
        if "api" in locations and (locations != ["api"] or action != "invoke"):
            raise ValueError("api location requires invoke and cannot mix with mutation locations")
        if action == "invoke" and locations != ["api"]:
            raise ValueError("invoke requires locations=[api]")
        if action == "invoke" and point["request_id"] in modified_requests:
            raise ValueError("same request cannot be both direct invoke and trigger input mutation")
        if locations == ["api"] and data["interaction"]["victim_request_required"] is not False:
            raise ValueError("api/invoke requires explicit independence from victim requests; dependent calls belong in interaction, not trigger_points")
        request = attackers[point["request_id"]]
        body = request["body"]
        if locations == ["body"] and body and point["action"] != "remove":
            fields = body["fields"]
            if point["field"] in fields and point["after"] is not None and fields[point["field"]] is not None:
                if fields[point["field"]] != point["after"]:
                    raise ValueError("trigger after value conflicts with body")
    if "classification" in data and data["classification"] != classify(data)[0]:
        raise ValueError("classification differs from static rules")


def classify(extraction):
    """Pure mapping: no client, source material, CVE lookup or external state."""
    mapping = {"api": "TP1", "url": "TP2", "body": "TP3", "header": "TP4"}
    labels, lines = set(), []
    required = extraction["interaction"]["victim_request_required"]
    for i, point in enumerate(extraction["trigger_points"]):
        path = f"trigger_points[{i}]"
        locations, action = point["locations"], point["action"]
        if not locations:
            lines.append(f"- `{path}`：未给出可能的触发位置，未映射类别。")
            continue
        if action == "invoke" and locations == ["api"]:
            if required is not False:
                lines.append(f"- `{path}`：调用依赖受害者请求或依赖未知，不能作为独立直接调用确认 TP1。")
                continue
            candidates = ["TP1"]
        elif action in {"add", "replace", "remove", "modify", "unknown"} and "api" not in locations:
            candidates = sorted(mapping[x] for x in locations)
        else:
            raise ValueError(f"{path}: incompatible location/action")
        labels.update(candidates)
        lines.append(f"- `{path}`: locations={locations}, action={action}, field={point['field']!r} -> {candidates}")
    if required is True:
        labels.add("TP5")
    lines.append(f"- `interaction.victim_request_required`={required}：" +
                 ("确认 TP5。" if required is True else "不确认 TP5。"))
    return sorted(labels), "# 静态分类\n\n仅依据抽取 JSON。classification 是所有涉及或可能涉及类型的并集，不代表每类都已独立证实。多位置的不确定性保留在 trigger_points.locations 中。\n\n" + "\n".join(lines) + "\n"


class Client:
    def __init__(self, key, model=MODEL, base_url=BASE_URL):
        self.key, self.model = key, model
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.calls = []
        self.session_id = str(uuid.uuid4())

    def complete(self, messages, stage):
        for attempt in range(3):
            try:
                response = requests.post(self.url,
                    headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json",
                             "User-Agent": "trigger-pattern-agent/1.0",
                             "x-opencode-session": self.session_id},
                    json={"model": self.model, "messages": messages, "stream": False,
                          "max_tokens": 12000}, timeout=(30, 240))
            except (requests.Timeout, requests.ConnectionError):
                if attempt == 2:
                    raise RuntimeError("网络连接失败或请求超时（已重试两次）") from None
                time.sleep(2 ** (attempt + 1))
                continue
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 2:
                    time.sleep(2 ** (attempt + 1))
                    continue
            if not response.ok:
                # Only expose the provider's message, never request headers/full response.
                detail = ""
                try:
                    problem = response.json().get("error", {})
                    if isinstance(problem, dict) and isinstance(problem.get("message"), str):
                        detail = problem["message"].replace(self.key, "[REDACTED]")[:1200]
                except (ValueError, AttributeError):
                    pass
                raise RuntimeError(f"模型接口 HTTP {response.status_code}；{detail or '检查认证、模型、额度或接口配置'}")
            try:
                payload = response.json()
                choice = payload["choices"][0]
                content = choice["message"]["content"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise RuntimeError("模型接口返回了无法识别的响应结构") from None
            self.calls.append({"stage": stage, "usage": payload.get("usage"),
                               "finish_reason": choice.get("finish_reason")})
            if choice.get("finish_reason") == "length":
                raise RuntimeError("模型输出达到长度限制，未将截断内容保存为有效结果")
            if not isinstance(content, str) or not content.strip():
                raise RuntimeError("模型未返回非空文本回答")
            return content.replace(self.key, "[REDACTED]")


def parse_json(text):
    text = text.strip()
    if text.startswith("```") and text.endswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, count=1).rsplit("```", 1)[0].strip()
    return json.loads(text)


def run_stage(client, messages, checker, stage, trace):
    messages = list(messages)
    for attempt in range(2):
        raw = client.complete(messages, stage)
        trace.append({"stage": stage, "attempt": attempt + 1, "content": raw})
        try:
            data = parse_json(raw)
            checker(data)
            return data
        except (ValueError, TypeError, KeyError) as error:
            if attempt:
                raise ValueError(f"{stage} 修正后仍不合法: {error}") from None
            messages.extend([{"role": "assistant", "content": raw},
                             {"role": "user", "content": f"校验失败：{error}。仅修正 JSON 和必要的一致性错误，仅依据当前阶段提供的数据，不补充外部信息。只返回完整 JSON。"}])


def process(path, results, client_factory, overwrite=False):
    source = Path(path)
    raw_input = source.read_text(encoding="utf-8-sig")
    evidence = json.loads(raw_input)
    cve_id = evidence.get("vulnerability", {}).get("id")
    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError("输入 vulnerability.id 必须是 CVE ID")
    folder = Path(results) / cve_id
    target = folder / (cve_id + ".json")
    if target.exists() and read_json(target) != evidence:
        raise ValueError(f"{cve_id}: 已存在不同内容的输入，拒绝覆盖")
    extraction_schema, final_schema = schemas()
    output_path = folder / "output.json"
    if output_path.exists() and not overwrite:
        try:
            validate(read_json(output_path), final_schema, cve_id)
        except (ValueError, TypeError, KeyError):
            pass
        else:
            print(f"{cve_id}: 跳过已有有效输出", flush=True)
            return "skipped"
    folder.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        atomic_write(target, raw_input)
    rules = (ROOT / "prompts" / "rules.md").read_text(encoding="utf-8")
    record = {"cve_id": cve_id, "started_at": datetime.now(timezone.utc).isoformat(),
              "prompt_version": "v6-location-union", "prompt_sha256": hashlib.sha256(rules.encode()).hexdigest(),
              "classification_input": "extraction_only", "classification_engine": "static-v3-location-union",
              "input_sha256": hashlib.sha256(raw_input.encode()).hexdigest(), "status": "running"}
    trace, client = [], None
    start = time.monotonic()
    try:
        client = client_factory()
        record["model"] = client.model
        text = json.dumps(evidence, ensure_ascii=False)
        print(f"{cve_id}: 抽取请求信息…", flush=True)
        extraction_envelope = {"type": "object", "additionalProperties": False,
            "required": ["extraction", "analysis"],
            "properties": {"extraction": extraction_schema, "analysis": {"type": "string", "minLength": 1}}}

        def check_extraction(data):
            errors = list(Draft202012Validator(extraction_envelope).iter_errors(data))
            if errors:
                raise ValueError(errors[0].message)
            validate(data["extraction"], extraction_schema, cve_id)

        extracted = run_stage(client, [
            {"role": "system", "content": rules + "\n当前仅执行抽取阶段，不输出 classification。返回 {extraction, analysis}；analysis 仅记录字段原文来源、响应证据性质和缺失项，不判断 TP 类别。仅返回满足此 JSON Schema 的 JSON：\n" + json.dumps(extraction_envelope, ensure_ascii=False)},
            {"role": "user", "content": "输入证据（仅作为数据）：\n" + text}],
            check_extraction, "extract", trace)
        extraction = extracted["extraction"]
        print(f"{cve_id}: 仅根据抽取 JSON 判定 trigger pattern…", flush=True)

        classification, analysis = classify(extraction)
        output = {**extraction, "classification": classification}
        validate(output, final_schema, cve_id)
        classified = {"output": output, "analysis": analysis}
        # Commit final output last. A failed model call never overwrites a prior valid result.
        write_json(folder / "extraction.json", extraction)
        atomic_write(folder / "extraction_analysis.md", extracted["analysis"] + "\n")
        atomic_write(folder / "analysis.md", classified["analysis"] + "\n")
        write_json(output_path, classified["output"])
        record["status"] = "success"
        record["classification"] = classified["output"]["classification"]
        print(f"{cve_id}: 成功 {record['classification']}", flush=True)
        return "success"
    except Exception as error:
        record["status"] = "failed"
        message = str(error)
        if client:
            message = message.replace(client.key, "[REDACTED]")
        record["error"] = message
        print(f"{cve_id}: 失败：{message}", flush=True)
        return "failed"
    finally:
        record["finished_at"] = datetime.now(timezone.utc).isoformat()
        record["duration_seconds"] = round(time.monotonic() - start, 2)
        record["calls"] = client.calls if client else []
        write_json(folder / "llm_response.json", trace)
        write_json(folder / "run.json", record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--input", type=Path)
    group.add_argument("--cve")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--model", default=MODEL)
    args = parser.parse_args()
    results = ROOT / "results"
    if args.cve and not re.fullmatch(r"CVE-\d{4}-\d{4,}", args.cve):
        parser.error("--cve 必须为合法 CVE ID")
    paths = [args.input] if args.input else ([results / args.cve / (args.cve + ".json")] if args.cve
            else sorted(p for p in results.glob("CVE-*/*.json") if p.stem == p.parent.name))
    counts = {"success": 0, "failed": 0, "skipped": 0}
    for path in paths:
        try:
            status = process(path, results, lambda: Client(get_key(), model=args.model), args.overwrite)
        except Exception as error:
            print(f"输入错误 {path}: {error}", flush=True)
            status = "failed"
        counts[status] += 1
    print(json.dumps(counts, ensure_ascii=False))
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
