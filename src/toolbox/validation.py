import copy
from jsonschema import Draft202012Validator
from src.config import RESOURCES
from .file_ops import read_json
from .classification import classify

def validate_oracle(data, tp):
    schema = read_json(RESOURCES / 'schemas/oracle.schema.json')
    errors = list(Draft202012Validator(schema).iter_errors(data))
    if errors:
        raise ValueError(errors[0].message)
    if data['cve_id'] != tp['cve_id']:
        raise ValueError('Oracle CVE mismatch')
    def unique(items):
        ids = [x['id'] for x in items]
        if len(ids) != len(set(ids)):
            raise ValueError('Duplicate ID')
    unique(data['oracles'])
    goals = set()
    for index, o in enumerate(data['oracles'], 1):
        if o['id'] != f'o{index}':
            raise ValueError('Oracle IDs must be o1, o2, ... in output order')
        t = o['template']; v = o['verifier']
        unique(v['observations'])
        for observation in v['observations']:
            if observation['api'] is not None and observation['api']['actor'] != observation['actor']:
                raise ValueError('Observation API actor must match observation actor')
        if not t['attack_request']:
            raise ValueError('Direct attack_request required')
        if t['type'] == 'O2' and (not t.get('capability_change') or 'capability_use_requests' not in t):
            raise ValueError('O2 requires capability change and use design')
        if t['type'] == 'O3' and (not t.get('victim_requests') or not t.get('schedule') or len(t['subjects']) < 2):
            raise ValueError('O3 requires victim requests and schedule')
        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in ('actor', 'subject') and child not in t['subjects']:
                        raise ValueError('Undeclared subject')
                    walk(child)
            elif isinstance(value, list):
                for child in value: walk(child)
        walk(t); walk(v)
        goal = (t['goal'], v['success_condition'])
        if goal in goals:
            raise ValueError('Duplicate Oracle goal/effect')
        goals.add(goal)

def schemas():
    final = read_json(RESOURCES / "schemas" / "trigger.schema.json")
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


