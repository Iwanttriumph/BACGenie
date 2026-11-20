"""Generate reviewable Oracle designs; never execute target operations."""
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator
from src.config import RESOURCES
from src.toolbox.file_ops import read_json, write_json, atomic_write
from src.toolbox.llm_client import run_stage
from src.toolbox.validation import schemas, validate, validate_oracle


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def process_oracle(path, results, client_factory, overwrite=False):
    raw = Path(path).read_text(encoding='utf-8-sig')
    evidence = json.loads(raw)
    cve = evidence['vulnerability']['id']
    if not isinstance(cve, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
        raise ValueError('Invalid vulnerability.id')
    folder = Path(results) / cve
    folder.mkdir(parents=True, exist_ok=True)
    record = {'cve_id': cve, 'status': 'running', 'started_at': datetime.now(timezone.utc).isoformat()}
    trace, client = [], None
    start = time.monotonic()
    try:
        stored_input = folder / (cve + '.json')
        if not stored_input.exists() or read_json(stored_input) != evidence:
            raise ValueError('Stored input mismatch; rerun TP with the selected input directory first')
        tp = read_json(folder / 'output.json')
        validate(tp, schemas()[1], cve)
        tp_run = read_json(folder / 'run.json')
        if tp_run.get('status') != 'success' or tp_run.get('input_sha256') != digest(raw):
            raise ValueError('TP input mismatch or failed run; rerun --stage tp --overwrite first')
        analysis = (folder / 'extraction_analysis.md').read_text(encoding='utf-8')
        rules = (RESOURCES / 'prompts/oracle.md').read_text(encoding='utf-8')
        schema = read_json(RESOURCES / 'schemas/oracle.schema.json')
        deps = {'input_sha256': digest(raw), 'tp_sha256': digest(json.dumps(tp, sort_keys=True)),
                'analysis_sha256': digest(analysis), 'prompt_sha256': digest(rules),
                'schema_sha256': digest(json.dumps(schema, sort_keys=True))}
        record.update(deps)
        output = folder / 'oracle.json'
        if output.exists() and not overwrite:
            try:
                old = read_json(folder / 'oracle_run.json')
                validate_oracle(read_json(output), tp)
                if old.get('status') == 'success' and all(old.get(k) == v for k, v in deps.items()):
                    return 'skipped'
            except (ValueError, KeyError, OSError, TypeError):
                pass
        envelope = {'type': 'object', 'required': ['oracle', 'analysis'], 'additionalProperties': False,
                    'properties': {'oracle': schema, 'analysis': {'type': 'string', 'minLength': 1}}}
        def check(data):
            errors = list(Draft202012Validator(envelope).iter_errors(data))
            if errors:
                raise ValueError(errors[0].message)
            validate_oracle(data['oracle'], tp)
        client = client_factory()
        record['model'] = client.model
        print(f'{cve}: designing Oracle...', flush=True)
        answer = run_stage(client, [
            {'role': 'system', 'content': rules + '\nJSON Schema:\n' + json.dumps(envelope)},
            {'role': 'user', 'content': json.dumps({'evidence': evidence, 'tp': tp, 'extraction_analysis': analysis}, ensure_ascii=False)}
        ], check, 'oracle', trace)
        atomic_write(folder / 'oracle_analysis.md', answer['analysis'] + '\n')
        write_json(output, answer['oracle'])
        record['status'] = 'success'
        return 'success'
    except Exception as error:
        record['status'] = 'failed'
        record['error'] = str(error).replace(client.key, '[REDACTED]') if client else str(error)
        print(f'{cve}: {record["error"]}', flush=True)
        return 'failed'
    finally:
        # A cache hit must preserve the successful dependency record.
        if record['status'] != 'running':
            record['finished_at'] = datetime.now(timezone.utc).isoformat()
            record['duration_seconds'] = round(time.monotonic() - start, 2)
            record['calls'] = client.calls if client else []
            write_json(folder / 'oracle_llm_response.json', trace)
            write_json(folder / 'oracle_run.json', record)
