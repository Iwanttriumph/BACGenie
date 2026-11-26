"""Two-stage, single-template Oracle design.

Selection is a separate model stage that records candidate evidence and a
single chosen template.  Instantiation receives only the selected template
schema and produces one Oracle with explicit Subject-Access-Object bindings.
This module never executes target requests.
"""

import copy
import hashlib
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from src.config import RESOURCES
from src.toolbox.file_ops import atomic_write, read_json, write_json
from src.toolbox.llm_client import run_stage
from src.toolbox.source import (
    CLASSIFICATION_VERSION,
    ORACLE_POLICY_VERSION,
    RETRIEVAL_VERSION,
    VERSION,
    load_input,
)
from src.toolbox.validation import (
    oracle_status,
    schemas,
    validate,
    validate_oracle,
    validate_selection,
)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _selection_gaps(selection):
    gaps = list(selection.get("gaps", []))
    for candidate in selection["candidates"]:
        if candidate["template"] == selection.get("selected_template"):
            gaps.extend(candidate.get("gaps", []))
    return list(dict.fromkeys(gaps))


def _check_envelope(data, keys):
    if not isinstance(data, dict):
        raise ValueError("$: expected a JSON object")
    for key in keys:
        if key not in data:
            raise ValueError(f"$.{key}: required")
    extra = sorted(set(data) - set(keys))
    if extra:
        raise ValueError(f"$: unexpected keys {extra}")
    if not isinstance(data["analysis"], str) or not data["analysis"].strip():
        raise ValueError("$.analysis: non-empty string required")


def _preserve_oracle(folder):
    output = folder / "oracle.json"
    if not output.exists():
        return
    try:
        data = read_json(output)
        if not data.get("oracles"):
            return
        shutil.copy2(output, folder / "oracle.previous.json")
        analysis = folder / "oracle_analysis.md"
        if analysis.exists():
            shutil.copy2(analysis, folder / "oracle.previous.analysis.md")
    except (OSError, ValueError, TypeError):
        pass


def _write_no_oracle(folder, cve, selection):
    _preserve_oracle(folder)
    write_json(folder / "oracle.json", {"cve_id": cve, "oracles": []})
    atomic_write(
        folder / "oracle_analysis.md",
        f"本次未生成 Oracle：模板选择状态为 {selection['status']}。"
        "选择依据、候选证据和缺口见 oracle_selection_analysis.md。\n",
    )


def _selected_schema(schema, selected):
    selected_schema = copy.deepcopy(schema)
    selected_schema["$defs"]["Oracle"]["properties"]["template"] = {
        "$ref": f"#/$defs/{selected}Template"
    }
    return selected_schema


def _normalize_oracle(data):
    """Move a verifier accidentally nested in template back to the Oracle."""
    if not isinstance(data, dict):
        return
    oracle = data.get("oracle")
    if not isinstance(oracle, dict):
        return
    for item in oracle.get("oracles", []):
        if not isinstance(item, dict):
            continue
        template = item.get("template")
        if isinstance(template, dict) and "verifier" in template and "verifier" not in item:
            item["verifier"] = template.pop("verifier")


def _repair(error, raw):
    return (
        f"校验失败（JSON 路径和约束）：{error}。"
        "只修正该 JSON 路径对应的字段或结构，不删除字段、不补造证据。"
        "返回完整 JSON。"
    )


def _run_selection(
    client, repository, cve, evidence, tp, analysis, source_evidence, prompt, schema, trace
):
    print(f"{cve}: selecting Oracle template...", flush=True)
    instruction = (
        "Return JSON {selection, analysis}. Selection JSON Schema:\n"
        + json.dumps(schema, ensure_ascii=False)
    )
    messages = repository.collect(
        client,
        [
            {"role": "system", "content": prompt + "\n" + instruction},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "evidence": evidence,
                        "tp": tp,
                        "extraction_analysis": analysis,
                        "source_evidence": source_evidence,
                    },
                    ensure_ascii=False,
                ),
            },
        ],
        "oracle_select",
        trace,
    )

    def check(data):
        _check_envelope(data, ["selection", "analysis"])
        validate_selection(data["selection"], cve)

    selected = run_stage(
        client, messages, check, "oracle_select", trace, max_repairs=2, repair=_repair
    )
    selection = copy.deepcopy(selected["selection"])
    selection["cve_id"] = cve
    selection["policy_version"] = ORACLE_POLICY_VERSION
    selection["selection_prompt_sha256"] = digest(prompt)
    selection["selection_schema_sha256"] = digest(json.dumps(schema, sort_keys=True))
    validate_selection(selection, cve)
    return selection, selected["analysis"]


def _run_instantiation(
    client,
    repository,
    cve,
    evidence,
    tp,
    analysis,
    selection,
    source_evidence,
    selection_reads,
    prompt,
    schema,
    trace,
):
    print(f"{cve}: instantiating {selection['selected_template']}...", flush=True)
    selected_schema = _selected_schema(schema, selection["selected_template"])
    instruction = (
        "Return JSON {oracle, analysis}. Oracle JSON Schema "
        "(selected template only):\n" + json.dumps(selected_schema, ensure_ascii=False)
    )
    messages = repository.collect(
        client,
        [
            {"role": "system", "content": prompt + "\n" + instruction},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "evidence": evidence,
                        "tp": tp,
                        "extraction_analysis": analysis,
                        "selection": selection,
                        "source_evidence": source_evidence,
                        "selection_source_evidence": selection_reads,
                    },
                    ensure_ascii=False,
                ),
            },
        ],
        "oracle",
        trace,
    )

    def check(data):
        _check_envelope(data, ["oracle", "analysis"])
        _normalize_oracle(data)
        validate_oracle(data["oracle"], tp, selection)

    answer = run_stage(
        client, messages, check, "oracle", trace, max_repairs=2, repair=_repair
    )
    validate_oracle(answer["oracle"], tp, selection)
    return answer["oracle"], answer["analysis"], oracle_status(selection, answer["oracle"])


def process_oracle(path, results, client_factory, overwrite=False):
    raw, original, evidence, repository = load_input(path)
    cve = evidence["vulnerability"]["id"]
    folder = Path(results) / cve
    folder.mkdir(parents=True, exist_ok=True)
    record = {
        "cve_id": cve,
        "status": "running",
        "stage": "preparing",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    trace, client, selection = [], None, None
    start = time.monotonic()
    try:
        stored_input = folder / (cve + ".json")
        if not stored_input.exists() or read_json(stored_input) != original:
            raise ValueError(
                "Stored input mismatch; rerun TP with the selected input directory first"
            )
        tp = read_json(folder / "output.json")
        tp_schema = schemas()[1]
        validate(tp, tp_schema, cve)
        tp_run = read_json(folder / "run.json")
        tp_prompt_sha = digest(
            (RESOURCES / "prompts/trigger.md").read_text(encoding="utf-8")
        )
        tp_schema_sha = digest(json.dumps(tp_schema, sort_keys=True))
        if (
            tp_run.get("source_sha256") != repository.fingerprint
            or tp_run.get("pipeline_version") != VERSION
            or tp_run.get("classification_version") != CLASSIFICATION_VERSION
            or tp_run.get("retrieval_version") != RETRIEVAL_VERSION
            or tp_run.get("status") != "success"
            or tp_run.get("input_sha256") != digest(raw)
            or tp_run.get("prompt_sha256") != tp_prompt_sha
            or tp_run.get("schema_sha256") != tp_schema_sha
        ):
            raise ValueError(
                "TP source/input changed or last TP run failed; "
                "rerun --stage tp --overwrite first"
            )
        analysis = (folder / "extraction_analysis.md").read_text(encoding="utf-8")
        source_evidence = (
            read_json(folder / "source_evidence.json")
            if (folder / "source_evidence.json").exists()
            else []
        )
        select_prompt = (RESOURCES / "prompts/oracle_select.md").read_text(encoding="utf-8")
        instantiate_prompt = (
            RESOURCES / "prompts/oracle_instantiate.md"
        ).read_text(encoding="utf-8")
        selection_schema = read_json(
            RESOURCES / "schemas/oracle_selection.schema.json"
        )
        oracle_schema = read_json(RESOURCES / "schemas/oracle.schema.json")
        deps = {
            "source_sha256": repository.fingerprint,
            "pipeline_version": VERSION,
            "classification_version": CLASSIFICATION_VERSION,
            "retrieval_version": RETRIEVAL_VERSION,
            "oracle_policy_version": ORACLE_POLICY_VERSION,
            "input_sha256": digest(raw),
            "tp_sha256": digest(json.dumps(tp, sort_keys=True)),
            "analysis_sha256": digest(analysis),
            "source_evidence_sha256": digest(
                json.dumps(source_evidence, sort_keys=True)
            ),
            "selection_prompt_sha256": digest(select_prompt),
            "selection_schema_sha256": digest(
                json.dumps(selection_schema, sort_keys=True)
            ),
            "instantiate_prompt_sha256": digest(instantiate_prompt),
            "instantiate_schema_sha256": digest(
                json.dumps(oracle_schema, sort_keys=True)
            ),
        }
        selection_path = folder / "oracle_selection.json"
        if selection_path.exists():
            try:
                candidate = read_json(selection_path)
                if (
                    candidate.get("selection_prompt_sha256")
                    != deps["selection_prompt_sha256"]
                    or candidate.get("selection_schema_sha256")
                    != deps["selection_schema_sha256"]
                ):
                    raise ValueError("selection prompt/schema changed")
                validate_selection(candidate, cve)
                selection = candidate
                deps["selection_sha256"] = digest(
                    json.dumps(candidate, sort_keys=True)
                )
            except (ValueError, OSError, TypeError):
                selection = None
        record.update(deps)
        output = folder / "oracle.json"
        if output.exists() and not overwrite and selection:
            try:
                old = read_json(folder / "oracle_run.json")
                validate_oracle(read_json(output), tp, selection)
                if old.get("status") in ("ready", "incomplete") and all(
                    old.get(key) == value for key, value in deps.items()
                ):
                    return "skipped"
            except (ValueError, KeyError, OSError, TypeError):
                pass

        client = client_factory()
        record["model"] = client.model
        selection_cached = bool(selection)
        if selection:
            record["stage"] = "select"
            record["selection_status"] = selection["status"]
            record["selected_template"] = selection["selected_template"]
            record["gaps"] = _selection_gaps(selection)
            record["selection_sha256"] = digest(
                json.dumps(selection, sort_keys=True)
            )
            prior_path = folder / "oracle_source_evidence.json"
            prior = read_json(prior_path) if prior_path.exists() else {}
            selection_reads = prior.get("oracle_reads", []) if isinstance(prior, dict) else []
            if selection["status"] != "selected":
                _write_no_oracle(folder, cve, selection)
                record["status"] = "incomplete"
                print(f"{cve}: template selection {selection['status']}", flush=True)
                return "incomplete"
            print(f"{cve}: reusing template selection {selection['selected_template']}", flush=True)
        else:
            selection, selection_analysis = _run_selection(
                client,
                repository,
                cve,
                evidence,
                tp,
                analysis,
                source_evidence,
                select_prompt,
                selection_schema,
                trace,
            )
            write_json(selection_path, selection)
            atomic_write(
                folder / "oracle_selection_analysis.md",
                selection_analysis + "\n",
            )
            record["selection_status"] = selection["status"]
            record["selected_template"] = selection["selected_template"]
            record["gaps"] = _selection_gaps(selection)
            record["selection_sha256"] = digest(
                json.dumps(selection, sort_keys=True)
            )
            record["stage"] = "select"
            write_json(
                folder / "oracle_source_evidence.json",
                {"tp_reads": source_evidence, "oracle_reads": repository.audit},
            )
            if selection["status"] != "selected":
                _write_no_oracle(folder, cve, selection)
                record["status"] = "incomplete"
                print(f"{cve}: template selection {selection['status']}", flush=True)
                return "incomplete"
            selection_reads = list(repository.audit)

        record["stage"] = "instantiate"
        oracle, oracle_analysis, status = _run_instantiation(
            client,
            repository,
            cve,
            evidence,
            tp,
            analysis,
            selection,
            source_evidence,
            selection_reads,
            instantiate_prompt,
            oracle_schema,
            trace,
        )
        _preserve_oracle(folder)
        write_json(output, oracle)
        atomic_write(folder / "oracle_analysis.md", oracle_analysis + "\n")
        oracle_reads = (
            list(selection_reads) + list(repository.audit)
            if selection_cached
            else list(repository.audit)
        )
        write_json(
            folder / "oracle_source_evidence.json",
            {"tp_reads": source_evidence, "oracle_reads": oracle_reads},
        )
        record["status"] = status
        record["stage"] = "instantiate"
        print(f"{cve}: Oracle {status}", flush=True)
        return status
    except Exception as error:
        record["status"] = "failed"
        if record.get("stage") == "preparing":
            record["stage"] = "select"
        record["error"] = (
            str(error).replace(client.key, "[REDACTED]") if client else str(error)
        )
        print(f'{cve}: Oracle failed: {record["error"]}', flush=True)
        return "failed"
    finally:
        if record["status"] != "running":
            record["finished_at"] = datetime.now(timezone.utc).isoformat()
            record["duration_seconds"] = round(time.monotonic() - start, 2)
            record["source_rounds"] = repository.rounds
            record["source_chars"] = repository.used
            record["calls"] = client.calls if client else []
            write_json(folder / "oracle_llm_response.json", trace)
            write_json(folder / "oracle_run.json", record)
