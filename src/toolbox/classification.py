"""Static trigger-pattern classification.

The model never supplies classification.  This module maps the extracted
trigger locations to candidate labels and keeps only the highest-priority
candidate.  The selected label is a classification result, not proof that the
highest-priority location was confirmed.
"""

from .source import CLASSIFICATION_VERSION

PRIORITY = {"TP1": 1, "TP2": 2, "TP3": 3, "TP4": 4, "TP5": 5}
LOCATION_LABEL = {"url": "TP2", "body": "TP3", "header": "TP4"}
MUTATIONS = {"add", "replace", "remove", "modify", "unknown"}


def _ordered(labels):
    return sorted(labels, key=lambda label: (PRIORITY[label], label))


def _select(labels):
    """Return the single highest-priority label, or an empty list."""
    return [_ordered(labels)[-1]] if labels else []


def classify(extraction):
    """Pure mapping: no client, source material, CVE lookup or external state."""
    required = extraction["interaction"]["victim_request_required"]
    candidates, lines = set(), []
    for index, point in enumerate(extraction["trigger_points"]):
        path = f"trigger_points[{index}]"
        locations, action = point["locations"], point["action"]
        point_candidates = set()
        if not locations:
            lines.append(f"- `{path}`：未给出可能的触发位置，未映射类别。")
            continue
        if "api" in locations:
            if locations != ["api"] or action != "invoke":
                raise ValueError(f"{path}: incompatible location/action")
            if required is None:
                lines.append(
                    f"- `{path}`：locations=api, action=invoke，但交互依赖未知，"
                    "不能生成独立直接调用候选 TP1。"
                )
                continue
            point_candidates.add("TP1")
            if required is True:
                lines.append(
                    f"- `{path}`：api/invoke 仅作为候选 TP1 记录；"
                    "交互依赖为 true，按优先级由 TP5 覆盖。"
                )
        elif action in MUTATIONS:
            point_candidates.update(LOCATION_LABEL[location] for location in locations)
        else:
            raise ValueError(f"{path}: incompatible location/action")
        candidates.update(point_candidates)
        selected = _select(point_candidates)
        covered = point_candidates - set(selected)
        detail = (
            f"候选 {_ordered(point_candidates)}，按优先级保留 {selected}"
            + (f"，覆盖 {_ordered(covered)}" if covered else "")
        )
        lines.append(
            f"- `{path}`: locations={locations}, action={action}, "
            f"field={point['field']!r} -> {detail}。"
        )
    if required is True:
        candidates.add("TP5")
        lines.append("- `interaction.victim_request_required`=true：加入 TP5 候选。")
    else:
        lines.append(
            "- `interaction.victim_request_required`="
            f"{required}：不加入 TP5 候选。"
        )
    selected = _select(candidates)
    covered = candidates - set(selected)
    lines.append(
        "- 固定优先级 TP5 > TP4(header) > TP3(body) > TP2(URL) > TP1："
        f"候选 {_ordered(candidates)}，保留 {selected}"
        + (f"，覆盖 {_ordered(covered)}" if covered else "")
        + "。"
    )
    return selected, (
        "# 静态分类\n\n"
        "仅依据抽取 JSON。classification 只保留最高优先级的候选类别，"
        "不代表该位置已经证实；多位置的不确定性保留在 trigger_points.locations 中。"
        f"分类版本：{CLASSIFICATION_VERSION}。\n\n" + "\n".join(lines) + "\n"
    )
