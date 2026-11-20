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


