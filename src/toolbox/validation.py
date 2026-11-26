import copy

from jsonschema import Draft202012Validator

from src.config import RESOURCES
from .file_ops import read_json
from .classification import classify


def _json_path(error):
    path = "$"
    for part in error.absolute_path:
        path += f"[{part}]" if isinstance(part, int) else f".{part}"
    return path


def _schema_check(data, schema):
    errors = sorted(
        Draft202012Validator(schema).iter_errors(data),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        raise ValueError(f"{_json_path(error)}: {error.message}")


def _selection_candidate(selection, template):
    for candidate in selection["candidates"]:
        if candidate["template"] == template:
            return candidate
    raise ValueError(f"$.candidates: missing {template}")


def validate_selection(data, cve_id):
    schema = read_json(RESOURCES / "schemas" / "oracle_selection.schema.json")
    _schema_check(data, schema)
    if data["cve_id"] != cve_id:
        raise ValueError("$.cve_id: Oracle selection CVE mismatch")
    candidates = data["candidates"]
    templates = [candidate["template"] for candidate in candidates]
    if sorted(templates) != ["O1", "O2", "O3"]:
        raise ValueError("$.candidates: exactly O1, O2 and O3 are required")
    if data["status"] == "selected":
        if data["selected_template"] is None:
            raise ValueError("$.selected_template: selected status requires a template")
        selected = _selection_candidate(data, data["selected_template"])
        if not selected["applicable"]:
            raise ValueError("$.selected_template: selected template is marked inapplicable")
        if selected["rejected_reason"] is not None:
            raise ValueError("$.selected_template: selected template must not have a rejection reason")
        for candidate in candidates:
            if candidate["template"] != data["selected_template"] and not candidate["rejected_reason"]:
                raise ValueError(
                    f"$.candidates: {candidate['template']} must record why it was rejected"
                )
    elif data["status"] == "ambiguous":
        if data["selected_template"] is not None:
            raise ValueError("$.selected_template: ambiguous status cannot select a template")
        if sum(1 for candidate in candidates if candidate["applicable"]) < 2:
            raise ValueError("$.candidates: ambiguous status needs at least two applicable templates")
    else:
        if data["selected_template"] is not None:
            raise ValueError("$.selected_template: incomplete status cannot select a template")
        if not data["gaps"]:
            raise ValueError("$.gaps: incomplete status requires at least one gap")


def validate_oracle(data, tp, selection):
    schema = read_json(RESOURCES / "schemas/oracle.schema.json")
    _schema_check(data, schema)
    if data["cve_id"] != tp["cve_id"]:
        raise ValueError("$.cve_id: Oracle CVE mismatch")
    if selection["cve_id"] != tp["cve_id"]:
        raise ValueError("$.cve_id: selection CVE mismatch")
    if selection["status"] != "selected":
        if data["oracles"]:
            raise ValueError("$.oracles: no Oracle may be generated when template selection is not selected")
        return
    if len(data["oracles"]) != 1:
        raise ValueError("$.oracles: exactly one Oracle is required when a template is selected")
    oracle = data["oracles"][0]
    if oracle["id"] != "o1":
        raise ValueError("$.oracles[0].id: Oracle ID must be o1")
    template = oracle["template"]
    selected = selection["selected_template"]
    if template["type"] != selected:
        raise ValueError("$.oracles[0].template.type: does not match selected template")
    subjects = template["subjects"]
    if selected == "O2" and "beneficiary" not in subjects:
        raise ValueError("$.oracles[0].template.subjects.beneficiary: O2 requires a beneficiary subject")
    if selected == "O3":
        if len(subjects) < 2:
            raise ValueError("$.oracles[0].template.subjects: O3 requires attacker and victim subjects")
        request_ids = {request["id"] for request in template["victim_requests"]}
        if not request_ids:
            raise ValueError("$.oracles[0].template.victim_requests: O3 requires victim requests")

    access_checks = template["access_checks"]
    access_ids = [check["id"] for check in access_checks]
    if len(access_ids) != len(set(access_ids)):
        raise ValueError("$.oracles[0].template.access_checks: duplicate access check ID")
    request_ids = set()
    seen_request_ids = []
    for key in ("attack_request", "capability_use_requests", "victim_requests"):
        for request in template.get(key, []):
            seen_request_ids.append(request["id"])
            request_ids.add(request["id"])
    if len(seen_request_ids) != len(set(seen_request_ids)):
        raise ValueError("$.oracles[0].template: duplicate request ID")
    for index, check in enumerate(access_checks):
        path = f"$.oracles[0].template.access_checks[{index}]"
        if check["subject"] not in subjects:
            raise ValueError(f"{path}.subject: undeclared subject")
        request_id = check["access"]["request_id"]
        if request_id is not None and request_id not in request_ids:
            raise ValueError(f"{path}.access.request_id: unknown request")
    phases = {check["phase"] for check in access_checks}
    if selected == "O1" and not phases.intersection({"operation", "attack"}):
        raise ValueError("$.oracles[0].template.access_checks: O1 needs an operation or attack check")
    if selected == "O1" and not any(
        check["phase"] in {"operation", "attack"} and check["expected_decision"] == "deny"
        for check in access_checks
    ):
        raise ValueError("$.oracles[0].template.access_checks: O1 attack check must expect deny")
    if selected == "O2":
        if "acquisition" not in phases or "use" not in phases:
            raise ValueError(
                "$.oracles[0].template.access_checks: O2 needs both acquisition and use checks"
            )
        if not any(
            check["phase"] in {"acquisition", "use"} and check["expected_decision"] == "deny"
            for check in access_checks
        ):
            raise ValueError("$.oracles[0].template.access_checks: O2 attack checks must expect deny")
        use_ids = {request["id"] for request in template["capability_use_requests"]}
        if not any(
            check["phase"] == "use" and check["access"]["request_id"] in use_ids
            for check in access_checks
        ):
            raise ValueError(
                "$.oracles[0].template.access_checks: O2 use check must reference a capability_use_request"
            )
    if selected == "O3":
        if not phases.intersection({"baseline"}):
            raise ValueError("$.oracles[0].template.access_checks: O3 needs a baseline check")
        if not phases.intersection({"effect", "attack"}):
            raise ValueError("$.oracles[0].template.access_checks: O3 needs an effect or attack check")
        if not any(
            check["phase"] in {"effect", "attack"} and check["expected_decision"] == "deny"
            for check in access_checks
        ):
            raise ValueError("$.oracles[0].template.access_checks: O3 effect check must expect deny")

    verifier = oracle["verifier"]
    expected_verifier = {"O2": "PRIVILEGE_USE", "O3": "STATE_ISOLATION"}.get(selected)
    if expected_verifier:
        if verifier["type"] != expected_verifier:
            raise ValueError(
                f"$.oracles[0].verifier.type: {selected} requires {expected_verifier}"
            )
    elif verifier["type"] not in {"READ", "CREATE", "UPDATE", "DELETE"}:
        raise ValueError("$.oracles[0].verifier.type: O1 requires READ, CREATE, UPDATE or DELETE")

    observation_ids = [observation["id"] for observation in verifier["observations"]]
    if len(observation_ids) != len(set(observation_ids)):
        raise ValueError("$.oracles[0].verifier.observations: duplicate observation ID")
    for index, observation in enumerate(verifier["observations"]):
        path = f"$.oracles[0].verifier.observations[{index}]"
        if observation["access_check"] not in access_ids:
            raise ValueError(f"{path}.access_check: unknown access check")
        if observation["actor"] not in subjects:
            raise ValueError(f"{path}.actor: undeclared subject")
        if observation["api"] is not None and observation["api"]["actor"] != observation["actor"]:
            raise ValueError(f"{path}.api.actor: must match observation actor")
        if not observation["target"]:
            raise ValueError(f"{path}.target: target binding is required")

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "actor" and child not in subjects:
                    raise ValueError("$.oracles[0].template: undeclared actor")
                if key == "subject" and child not in subjects:
                    raise ValueError("$.oracles[0].template: undeclared subject")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(template)
    walk(verifier)


def oracle_status(selection, data):
    if selection["status"] != "selected" or not data["oracles"]:
        return "incomplete"
    gaps = list(selection.get("gaps", []))
    try:
        gaps.extend(_selection_candidate(selection, selection["selected_template"])["gaps"])
    except ValueError:
        return "incomplete"
    template = data["oracles"][0]["template"]
    if any(check["policy_basis"] is None for check in template["access_checks"]):
        gaps.append("access check policy_basis is unknown")
    verifier = data["oracles"][0]["verifier"]
    if any(
        observation["api"] is None and observation["query"] is None
        for observation in verifier["observations"]
    ):
        gaps.append("observation channel is unknown")
    if verifier["unresolved_conditions"]:
        gaps.append("verifier has unresolved conditions")
    return "incomplete" if gaps else "ready"


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
