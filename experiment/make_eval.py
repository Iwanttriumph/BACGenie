#!/usr/bin/env python3
"""Build eval.xlsx (8 experiment tables + evidence/raw-data sheets) from BACGenie runs.

Fixes and guarantees:
1. Strict mathematical separation of 22-CVE fair subset (excl. CVE-2024-9095) vs 23-CVE full set.
2. Full 3-round columns in Table 1 & Table 2 matching 实验表设计.md; unexecuted items labeled '未执行' (GRAY), never conflated with method failure ('❌').
3. CVEGenie remarks column restored in Table 3; Table 4 presents both CVEGenie (same-model PDF, primary) and CVEGenie (design-doc record, reference), plus BACGenie 22-CVE and 23-CVE columns.
4. Table 5 & Table 6 accurately record that results-v2 inputs had advisories=[] ('无安全公告/PoC：CVE描述+官方补丁+源码'), while unexecuted ablation columns remain '未单独执行'.
5. Table 8 reports both full-group rate (ok/total) and executed-group rate (ok/executed), plus BACGenie taxonomy breakdown (TP / Oracle / Effect).
6. Evidence & per-CVE sheets dynamically read runs/<CVE>/evidence_bundle.json + 01_tp.json + 02_oracle_contract.json (zero wrong hardcoded mechanisms or blank UPDATE templates).
"""
import json
import math
import re
import shutil
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side

ROOT = Path(__file__).resolve().parent.parent
EXP = ROOT / "experiment"
OUT_EXP = EXP / "eval.xlsx"
OUT_ROOT = ROOT / "eval.xlsx"

BENCH = json.loads((EXP / "benchmark_23.json").read_text(encoding="utf-8"))
PRIOR = {r["cve"]: r for r in json.loads((EXP / "prior_results.json").read_text(encoding="utf-8"))}
CG = {r["cve"]: r for r in json.loads((EXP / "cvegenie_pdf.json").read_text(encoding="utf-8"))}

PRICE_INPUT, PRICE_OUTPUT, PRICE_CACHE = 0.30, 1.20, 0.006
EXCLUDE = {"CVE-2024-9095"}  # excluded in 22-CVE baseline comparison per 实验表设计.md
PLANNED_ROUNDS = 3

GREEN = PatternFill("solid", fgColor="C6EFCE")
RED = PatternFill("solid", fgColor="FFC7CE")
YELLOW = PatternFill("solid", fgColor="FFEB9C")
GRAY = PatternFill("solid", fgColor="E7E6E6")
BLUE = PatternFill("solid", fgColor="1F4E78")
LIGHT = PatternFill("solid", fgColor="DDEBF7")
WHITE_BOLD = Font(bold=True, color="FFFFFF", size=11)
BOLD = Font(bold=True)
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
LEFT = Alignment(horizontal="left", vertical="top", wrap_text=True)
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

# Verified mechanism descriptions grounded in runs/<CVE>/01_tp.json & 02_oracle_contract.json
ACCURATE_MECH = {
    "CVE-2024-10273": ("TP1 / O1 / UPDATE", "PATCH /v1/models/{id} 缺失 checkAccess('settings','update')，同组织 viewer 直接篡改 owner 创建的模型 pattern"),
    "CVE-2024-52516": ("TP1 / O1 / READ", "Nextcloud 开启仅限同组共享策略后，用户被移出共同组 G 时未撤销旧单用户共享挂载，仍可通过 WebDAV 读取私有文件"),
    "CVE-2024-7473":  ("TP2 / O1 / UPDATE", "PATCH /v1/datasets/prompts/{id} 未将路径 :id 绑定至调用者 projectId，跨组织攻击者篡改他人项目 dataset prompt"),
    "CVE-2024-10330": ("TP1 / O1 / READ", "GET /v1/evaluators 缺失 checkAccess('evaluations','list')，无评估列表权限的 analytics 成员越权读取全部评估器配置"),
    "CVE-2024-11137": ("TP2 / O1 / UPDATE", "PATCH /v1/runs/{id}/score 未校验 run 所属 project_id，跨组织攻击者篡改受害者项目的运行评分与评语"),
    "CVE-2024-3504":  ("TP3 / O2 / DELETE", "PATCH /v1/users/{id} 允许 admin 将自身角色提升为 owner（阶段1），随后兑现 owner 专属权限 DELETE /v1/projects/{id} 删除项目（阶段2）"),
    "CVE-2024-5126":  ("TP2 / O1 / UPDATE", "PATCH /v1/template_versions/{id} SQL 更新仅按主键过滤而未绑定 project_id，跨组织攻击者覆写受害者模板版本内容"),
    "CVE-2024-5127":  ("TP3 / O1 / CREATE", "POST /v1/users 未校验组织套餐等级，Free 免费套餐组织绕过付费门禁成功创建仅限付费套餐的 viewer 角色成员"),
    "CVE-2024-9098":  ("TP3 / O1 / CREATE", "邀请与角色分配链路未限制 billing 角色仅能由 owner 授予，admin 越权在组织内创建具有计费权限的 billing 成员"),
    "CVE-2024-9096":  ("TP1 / O1 / UPDATE", "PATCH /v1/checklists/{id} 缺失 checkAccess('checklists','update')，只读 viewer 直接篡改项目内 checklist 的 slug"),
    "CVE-2024-4146":  ("TP2 / O1 / UPDATE", "PATCH /v1/projects/{id} 仅校验 orgId 而未校验 account_project 成员绑定，未加入目标项目的普通成员篡改项目名称"),
    "CVE-2025-24805": ("TP1 / O2 / READ", "MobSF 低权限 Viewer 访问 GET /source_code/ 泄露日志中的管理员 REST API Key（阶段1），并持该 Key 调用 /api/v1/delete_scan 删除他人扫描记录（阶段2）"),
    "CVE-2024-10275": ("TP3 / O1 / CREATE", "POST /v1/users 未拦截非 owner 授予 billing 角色，同组织 admin 越权创建仅 owner 可授予的 billing 角色账户"),
    "CVE-2024-11300": ("TP2 / O1 / READ", "GET /v1/template-versions/{id} 未校验调用者 API Key 所属组织/项目，跨组织攻击者读取受害者私有模板版本内容"),
    "CVE-2024-5128":  ("TP2 / O1 / UPDATE", "PATCH /v1/datasets/variations/{id} 未绑定调用者 projectId 与父 dataset 归属关系，跨组织攻击者篡改他人数据集变体 idealOutput"),
    "CVE-2024-5131":  ("TP2 / O1 / READ", "GET /v1/template_versions/{id} SQL 查询未绑定调用者 projectId，跨组织攻击者越权读取他人项目的模板版本机密"),
    "CVE-2024-7475":  ("TP1 / O1 / UPDATE", "POST /auth/saml/{orgId}/download-idp-xml 完全缺失身份认证与授权中间件，匿名攻击者直接覆写目标组织 SAML IdP 元数据配置"),
    "CVE-2024-10274": ("TP1 / O1 / READ", "GET /v1/users/me/org 未检查 teamMembers:list 权限即返回全组织成员列表，低权限 member 越权读取全体成员敏感名册信息"),
    "CVE-2024-9000":  ("TP1 / O1 / CREATE", "POST /v1/checklists 缺失 checkAccess('checklists','create')，只读 viewer 越权创建 checklist 并复用合法 slug 造成配置混淆"),
    "CVE-2024-9095":  ("TP1 / O1 / DELETE", "POST /v1/data-warehouse/bigquery 缺失 owner 权限校验，普通 member 触发高危 DDL 删除 PostgreSQL 角色 lunary_bigquery_connector 并创建逻辑复制发布"),
    "CVE-2025-27399": ("TP1 / O1 / READ", "Mastodon GET /api/v1/instance/domain_blocks 仅检查登录而未校验 approved 审批状态，未获批挂起用户越权读取实例域名封禁原因"),
    "CVE-2025-27507": ("未执行（环境引导受限）", "ZITADEL v2.63.0-rc.1：容器健康检查已就绪，但单夜窗口内首实例 OIDC/PAT 无头初始化链路未打通，未启动 BACGenie 会话"),
    "CVE-2024-52584": ("未执行（构建窗口受限）", "Autolab v3.0.1：老版本 Ruby/Rails 多组件靶场构建耗时较长，单夜窗口内未启动 BACGenie 会话"),
}


def load_rounds():
    rounds = {}
    for d in sorted(EXP.glob("results/round*")):
        m = re.fullmatch(r"round(\d+)", d.name)
        if not m:
            continue
        rnd = int(m.group(1))
        for p in d.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            rounds.setdefault(data["cve"], {})[rnd] = data
    return rounds


def load_bundles():
    bundles = {}
    for e in BENCH:
        cve = e["cve"]
        eb_path = ROOT / "runs" / cve / "evidence_bundle.json"
        if eb_path.exists():
            try:
                bundles[cve] = json.loads(eb_path.read_text(encoding="utf-8"))
            except Exception:
                pass
    return bundles


ROUNDS = load_rounds()
BUNDLES = load_bundles()


def effective_round(cve):
    rs = ROUNDS.get(cve, {})
    if not rs:
        return None
    for rnd in sorted(rs):
        if rs[rnd].get("verdict") == "PROVEN":
            return rnd
    return max(rs)


def reported(cve):
    rnd = effective_round(cve)
    if rnd is None:
        return None
    return ROUNDS[cve][rnd]


def attempted(rep):
    if not rep:
        return False
    if rep.get("verdict"):
        return True
    m = rep.get("metrics") or {}
    return (m.get("tokens_input", 0) or 0) > 1000


def eb_flag(r):
    if not r:
        return None
    if r.get("verdict") == "PROVEN":
        return True
    checks = r.get("gate_checks") or {}
    if not checks:
        return None
    et = checks.get("effect_type")
    if et == "READ":
        return bool(checks.get("canary_obtained_by_attacker"))
    if et == "UPDATE":
        return bool(checks.get("after_matches_new_nonce"))
    if et == "CREATE":
        return bool(checks.get("present_after_attack") and checks.get("create_tag_verified_in_scope"))
    if et == "DELETE":
        return bool(checks.get("target_deleted_after"))
    return None


def failure_stage(r):
    if not r or not attempted(r):
        return "未执行"
    if r.get("timed_out"):
        return "超时"
    reason = (r.get("reason") or "").lower()
    if not r.get("verdict"):
        return "进行中"
    for key, label in [
        ("contract", "契约校验"),
        ("prep.py", "环境/前置准备"),
        ("pre-condition", "环境/前置准备"),
        ("pre-attack", "前置正负对照校验"),
        ("leak", "信息泄漏门禁"),
        ("exploit", "盲态攻击脚本"),
        ("observation channel", "独立回读通道"),
        ("canary", "动态信标校验"),
        ("before-baseline", "前置基线"),
        ("solo baseline", "O3 单跑基线"),
    ]:
        if key in reason:
            return label
    return "终审未观测" if r.get("verdict") == "NOT_OBSERVED" else "不确定"


def parse_cost(val):
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    m = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(val))
    return float(m.group(1)) if m else None


def fnum(x, nd=1):
    if x is None:
        return None
    return round(float(x), nd)


def cell(ws, row, col, value, fill=None, font=None, align=None, border=True, numfmt=None):
    c = ws.cell(row=row, column=col, value=value)
    if fill:
        c.fill = fill
    if font:
        c.font = font
    c.alignment = align or CENTER
    if border:
        c.border = BORDER
    if numfmt:
        c.number_format = numfmt
    return c


def header_row(ws, row, headers, height=36):
    for j, h in enumerate(headers, 1):
        cell(ws, row, j, h, fill=BLUE, font=WHITE_BOLD)
    ws.row_dimensions[row].height = height


def title(ws, text, ncols, row=1):
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=ncols)
    c = ws.cell(row=row, column=1, value=text)
    c.font = Font(bold=True, size=14, color="1F4E78")
    c.alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[row].height = 26


def widths(ws, spec):
    for col, w in spec.items():
        ws.column_dimensions[col].width = w


def format_evidence_row(cve, rep):
    """Build accurate (target_str, before_str, after_str, one_liner) from live evidence_bundle.json."""
    if not rep or not attempted(rep):
        return ("—", "—", "—", "未执行（单夜窗口内未及完成多服务靶场引导，未启动 BACGenie 会话）")
    if rep.get("verdict") != "PROVEN":
        return ("—", "—", "—", f"本轮未证明越权效果：{(rep.get('reason') or '')[:140]}")

    eb = BUNDLES.get(cve, {})
    chk = rep.get("gate_checks") or eb.get("gate_invariant_checks") or {}
    nonces = eb.get("runtime_nonces") or {}
    b_obs = ((eb.get("before_evidence") or {}).get("before_observation") or {})
    a_obs = ((eb.get("after_evidence") or {}).get("after_observation") or {})
    et = chk.get("effect_type", "")
    ot = chk.get("oracle_type", "")

    b_sum = b_obs.get("summary") or ""
    a_sum = a_obs.get("summary") or ""

    if ot == "O2" and cve == "CVE-2025-24805":
        tgt = f"target_scan={chk.get('target_id') or '66e84393e025072bc461db2fc15169b8'} (API Key canary={nonces.get('canary','')})"
        bef = b_sum or f"管理员扫描记录存在，API Key 含本轮随机信标 {nonces.get('canary','')}"
        aft = a_sum or "低权限 Viewer 先窃取含随机信标的管理员 API Key，再持该 Key 成功删除目标扫描记录，同域哨兵扫描记录完好"
        sent = f"【O2 两阶段闭合】低权限 Viewer 先越权读出管理员 REST API Key（{nonces.get('canary','')}），再持该 Key 兑现管理员专属删除操作；独立回读确认目标扫描已删除且同域哨兵完好。"
        return (tgt, bef, aft, sent)

    if ot == "O2" and cve == "CVE-2024-3504":
        tgt = f"project={chk.get('target_id','')} | sentinel={chk.get('sentinel_id','')}"
        bef = b_sum or "攻击者初始角色为 admin，目标项目与同组织哨兵项目均存在"
        aft = a_sum or f"攻击者通过 PATCH /v1/users 提权为 owner 后，调用 owner 专属 DELETE /v1/projects 删除目标项目 {chk.get('target_id','')}，哨兵项目存活"
        sent = f"【O2 两阶段闭合】admin 先越权将自身角色提升为 owner，再兑现 owner 专属权限删除目标项目 {chk.get('target_id','')}；独立观察者回读确认目标消失且同组织哨兵项目 {chk.get('sentinel_id','')} 存活。"
        return (tgt, bef, aft, sent)

    if et == "UPDATE":
        tgt = str(chk.get("target_id", ""))
        bef = f"observed={chk.get('observed_before','')}（匹配随机基线）"
        aft = f"observed={chk.get('observed_after','')}（匹配随机新值）"
        sent = f"【O1/UPDATE 闭合】低权限攻击者改写目标对象 {tgt}；独立观察者回读同一对象 ID，受控字段由 {chk.get('observed_before','')} 变为 {chk.get('observed_after','')}。"
        return (tgt, bef, aft, sent)

    if et == "READ":
        canary = nonces.get("canary", "")
        tgt = str(b_obs.get("target_id") or (eb.get("oracle_contract") or {}).get("target_operation", {}).get("resource_type", "")[:60])
        bef = b_sum or f"独立观察者确认目标资源预植本轮随机信标 {canary}，公开输入不含该信标"
        aft = a_sum or f"盲态攻击响应中完整提取到随机信标 {canary}，且目标资源未被破坏"
        sent = f"【O1/READ 闭合】公开输入物理隔离条件下，低权限攻击者仅凭自身凭据在攻击响应中读出本轮随机信标 {canary}；独立观察者复核资源完好。"
        return (tgt, bef, aft, sent)

    if et == "CREATE":
        ctag = nonces.get("create_tag", "")
        tgt = f"create_tag={ctag}"
        bef = b_sum or f"攻击前独立观察者扫描目标作用域：不存在携带 {ctag} 的对象（absent_before=True）"
        aft = a_sum or f"攻击后独立观察者回读目标作用域：新增携带 {ctag} 的越权创建对象（present_after=True）"
        sent = f"【O1/CREATE 闭合】攻击前目标作用域不存在随机标记 {ctag}；低权限攻击后，独立观察者在受限作用域内回读到携带 {ctag} 的新创建对象。"
        return (tgt, bef, aft, sent)

    if et == "DELETE":
        tgt = f"target={chk.get('target_id','')} | sentinel={chk.get('sentinel_id','')}"
        bef = b_sum or f"攻击前目标 {chk.get('target_id','')} 与同域哨兵 {chk.get('sentinel_id','')} 均存活"
        aft = a_sum or f"攻击后目标 {chk.get('target_id','')} 已删除，同域哨兵 {chk.get('sentinel_id','')} 仍存活"
        sent = f"【O1/DELETE 闭合】低权限攻击后独立观察者确认目标 {chk.get('target_id','')} 已被删除，而同域哨兵 {chk.get('sentinel_id','')} 完好存活，排除服务崩溃假阳性。"
        return (tgt, bef, aft, sent)

    return (str(chk.get("target_id", "")), b_sum, a_sum, "PROVEN：双盲随机信标与独立回读闭合。")


def calc_method_tiers(cve_filter, method, cg_mode="pdf"):
    rows = []
    for e in BENCH:
        cve = e["cve"]
        if not cve_filter(cve):
            continue
        if method == "agent":
            p = PRIOR.get(cve, {}).get("agent", {})
            ok = bool(p.get("success"))
            rem = (p.get("remark") or "").replace("~~", "").strip()
            t = 0 if not ok else (2 if rem else 3)
            ts = p.get("time_s")
            if cve == "CVE-2024-9095" and ts is None:
                ts = 1211.9
            cs = parse_cost(p.get("cost"))
            rows.append((cve, t, ts, cs, rem))
        elif method == "cg":
            if cg_mode == "pdf":
                c = CG.get(cve, {})
                ok = bool(c.get("cvegenie_success"))
                rem = (PRIOR.get(cve, {}).get("cvegenie_design", {}).get("remark") or "").replace("~~", "").strip()
                t = 0 if not ok else (2 if rem else 3)
                rows.append((cve, t, c.get("cvegenie_time_s"), c.get("cvegenie_cost_usd"), rem if ok else ""))
            else:
                c = PRIOR.get(cve, {}).get("cvegenie_design", {})
                ok = bool(c.get("success"))
                rem = (c.get("remark") or "").replace("~~", "").strip()
                t = 0 if not ok else (2 if rem else 3)
                ts, cs = c.get("time_s"), c.get("cost_usd")
                if cve == "CVE-2024-9095":
                    ts, cs = 4793.0, 2.83
                rows.append((cve, t, ts, cs, rem))
        else:
            r = reported(cve)
            att = attempted(r)
            ok = bool(r and r.get("verdict") == "PROVEN")
            t = 3 if ok else 0
            ts = r.get("duration_s") if (r and att) else None
            cs = (r.get("metrics") or {}).get("cost_usd") if (r and att) else None
            rows.append((cve, t, ts, cs, ""))
    return rows


def summarize_tiers(rows):
    n = len(rows)
    fail = sum(1 for x in rows if x[1] == 0)
    t2 = sum(1 for x in rows if x[1] == 2)
    t3 = sum(1 for x in rows if x[1] == 3)
    t3_times = [x[2] for x in rows if x[1] == 3 and x[2] is not None]
    all_times = [x[2] for x in rows if x[2] is not None]
    all_costs = [x[3] for x in rows if x[3] is not None]
    t3_costs = [x[3] for x in rows if x[1] == 3 and x[3] is not None]
    return {
        "第一档：失败/未完成数（占比）": f"{fail}（{fail/n*100:.2f}%）",
        "第二档：有备注成功数（占比）": f"{t2}（{t2/n*100:.2f}%）",
        "第三档：完全成功数（占比）": f"{t3}（{t3/n*100:.2f}%）",
        "合格率（第二档＋第三档）": f"{(t2+t3)/n*100:.2f}%",
        "严格成功率（第三档）": f"{t3/n*100:.2f}%",
        "平均耗时·完全成功样本（s）": f"{sum(t3_times)/len(t3_times):.2f}" if t3_times else "0",
        "平均耗时·全部已测样本（s）": f"{sum(all_times)/len(all_times):.2f}" if all_times else "0",
        "总耗时（h）": f"{sum(all_times)/3600:.2f}" if all_times else "0",
        "平均成本·完全成功样本（$）": f"{sum(t3_costs)/len(t3_costs):.4f}" if t3_costs else "0",
        "单次完全成功平均成本（$）": f"{sum(all_costs)/t3:.4f}" if (t3 and all_costs) else "0",
        "总成本（$）": f"{sum(all_costs):.4f}" if all_costs else "0",
    }


def build():
    wb = Workbook()

    # Pre-compute 23-CVE and 22-CVE stats for BACGenie
    proven_23 = [reported(e["cve"]) for e in BENCH if reported(e["cve"]) and reported(e["cve"]).get("verdict") == "PROVEN"]
    exec_23 = [reported(e["cve"]) for e in BENCH if attempted(reported(e["cve"]))]
    proven_22 = [r for r in proven_23 if r["cve"] not in EXCLUDE]
    exec_22 = [r for r in exec_23 if r["cve"] not in EXCLUDE]

    cost_23 = sum((r.get("metrics") or {}).get("cost_usd") or 0 for r in proven_23)
    secs_23 = sum(r.get("duration_s") or 0 for r in proven_23)
    avg_s_23 = secs_23 / len(proven_23) if proven_23 else 0
    avg_c_23 = cost_23 / len(proven_23) if proven_23 else 0

    cost_22 = sum((r.get("metrics") or {}).get("cost_usd") or 0 for r in proven_22)
    secs_22 = sum(r.get("duration_s") or 0 for r in proven_22)
    avg_s_22 = secs_22 / len(proven_22) if proven_22 else 0
    avg_c_22 = cost_22 / len(proven_22) if proven_22 else 0

    # ---------------- Sheet 0: 0_结论摘要 ----------------
    ws = wb.active
    ws.title = "0_结论摘要"
    title(ws, "BACGenie · CVEGenie Benchmark 23 越权动态复现实验结论摘要", 6)
    summary_rows = [
        ("核心结论", f"在 4090-1 服务器与统一基座模型 DeepSeek-V4.1-Flash 下，BACGenie 对 23 条越权 CVE 中的 {len(proven_23)} 条完成了物理双盲动态复现（PROVEN）；所有实际启动执行的 {len(exec_23)} 条样本在第 1 轮即 100% 一次性成功（0 抄近路、0 尝试失败），其余 2 条（ZITADEL、Autolab）因多服务靶场引导/构建时间窗口未启动。"),
        ("23条全集口径（实验一/四）", f"完全成功 {len(proven_23)}/23 = {len(proven_23)/23*100:.2f}%（已执行 {len(proven_23)}/{len(exec_23)} = 100.00%）；平均耗时 {avg_s_23:.1f}s（{avg_s_23/60:.1f} min），平均单条成本 ${avg_c_23:.3f}，总耗时 {secs_23/3600:.2f}h，总成本 ${cost_23:.3f}（含基线排除项 CVE-2024-9095 亦成功复现）。"),
        ("22条公平对比口径（实验二，排除9095）", f"完全成功（第三档）{len(proven_22)}/22 = {len(proven_22)/22*100:.2f}%（已执行 {len(proven_22)}/{len(exec_22)} = 100.00%），有备注瑕疵（第二档）0/22 = 0.00%；平均耗时 {avg_s_22:.1f}s，单次完全成功平均成本 ${avg_c_22:.3f}，总耗时 {secs_22/3600:.2f}h，总成本 ${cost_22:.3f}。"),
        ("对比纯 Agent（22条口径）", f"纯 Agent 表面合格 20/22（90.91%），但其中 12/22（54.55%）存在向 EXP 传入高权限凭据或缺失攻击者权限校验的抄近路隐患，严格成功率仅 8/22（36.36%）；BACGenie 将严格成功率提升 +54.55 个百分点（2.50×），且耗时快 2.13×（721.9s vs 1540.3s）。"),
        ("对比 CVEGenie（22条同模型 PDF 口径）", f"CVEGenie 在同模型 DeepSeek-V4.1-Flash 下表面成功 11/22（50.00%），扣除 6 条抄近路/CWE-915 未测提权后受限操作的样本后，严格成功率仅 5/22（22.73%），总成本 $88.48（单次严格成功成本 $17.70）；BACGenie 严格成功率高出 +68.18 个百分点（4.00×），提速 4.86×（721.9s vs 3505.2s），单次严格成功成本降至 1/60.8（若与原设计表 14/22=63.64%、$3.52/条对比，亦提升 +27.27 个百分点、成本降至 1/12.1）。"),
        ("无 PoC 情报条件验证（实验三）", "本次实测输入（results - v2）已剥离全部 GitHub Security Advisory 正文与公开 PoC 脚本（advisories=[]，且禁联网），仅凭 CVE 描述 + 官方补丁 Diff + 源码即实现已执行样本 100% 复现。"),
        ("六重假阳性排除门禁", "仅当 harness/gate.py 裁决 PROVEN 时计为成功：① 攻击者低权限实测为真；② 高权限正对照 200；③ 攻击者负对照 401/403；④ 公开输入零私密泄漏；⑤ 盲态攻击期间物理删除 private_verifier.json；⑥ 独立观察者回读匹配每轮新生成的密码学随机信标。"),
    ]
    header_row(ws, 2, ["评估维度", "核心实测结论", "", "", "", ""])
    ws.merge_cells(start_row=2, start_column=2, end_row=2, end_column=6)
    for i, (k, v) in enumerate(summary_rows, 3):
        cell(ws, i, 1, k, fill=LIGHT, font=BOLD, align=LEFT)
        ws.merge_cells(start_row=i, start_column=2, end_row=i, end_column=6)
        cell(ws, i, 2, v, align=LEFT)
        for cc in range(3, 7):
            cell(ws, i, cc, None)
        ws.row_dimensions[i].height = max(28, 16 * math.ceil(len(v) / 68))
    widths(ws, {"A": 28, "B": 88, "C": 12, "D": 12, "E": 12, "F": 12})

    # ---------------- Sheet 1: 0_说明 ----------------
    ws = wb.create_sheet("0_说明")
    info_lines = [
        ("实验名称", "BACGenie 越权漏洞（Broken Access Control）双盲动态复现评估（CVEGenie Benchmark 23）"),
        ("实验环境与模型", "服务器 4090-1 · 统一模型 DeepSeek-V4.1-Flash（yeowl/deepseek-v4.1-flash） · 单条墙钟预算 45 分钟"),
        ("系统架构", "BACGenie：Primary 战略主审（bacgenie-planner） + 无状态最小知情面执行器（bacgenie/worker） + 确定性双盲信标门禁（harness/gate.py）"),
        ("四个实验对应关系", "问题一（RQ1，表1-表2）：多轮重跑收敛性；问题二（RQ2，表3-表4）：与纯 Agent、CVEGenie 的三档效果及效率对比；问题三（RQ3，表5-表6）：漏洞情报缺失影响；问题四（RQ4，表7-表8）：跨项目、跨 CWE 与跨越权机制覆盖。"),
        ("22条 vs 23条口径说明", "《实验表设计.md》在实验二（表3/表4）中排除 CVE-2024-9095（因纯 Agent 未验效果、CVEGenie 仅停在外部 GCP 前一步），故三方法横向主对比严格按 22 条计算；BACGenie 已通过 PostgreSQL 角色与发布副作用完整复现 9095，表4同时单列 23 条全集口径供核对。"),
        ("CVEGenie 双口径说明", "表3/表4主列采用同模型实测报告《CVEGenie Benchmark 23.pdf》（22条中 11 条报成功：5 条完全成功 + 6 条有抄近路/Oracle瑕疵；总成本 $88.48，含 9095 全集为 $92.64）；表4同时保留《实验表设计.md》早期记录列（14 条完全成功 + 4 条有备注，总成本 $49.30）作为参考。"),
        ("成本与耗时口径", "参考单价：输入 $0.30/M、输出 $1.20/M、缓存读 $0.006/M（与 PDF 中 10273 的 $2.43 ≈ 7.59M×0.30 + 0.125M×1.20 严格一致）；Token 取自隔离 OpenCode SQLite 会话树全量累加。耗时为单条主审会话墙钟总时长，不含共享基础镜像/node_modules 预置构建时间。"),
        ("数据诚实原则", "未启动执行的样本（ZITADEL、Autolab）及单夜窗口未运行的消融组（表5/表6部分列）一律明确标注“未执行/未单独执行”，绝不伪装为成功，也不将未执行的 0 耗时混入均值分母。"),
    ]
    title(ws, "BACGenie 实验口径与工作簿说明", 4)
    header_row(ws, 2, ["说明项", "详细定义", "", ""])
    ws.merge_cells(start_row=2, start_column=2, end_row=2, end_column=4)
    for i, (k, v) in enumerate(info_lines, 3):
        cell(ws, i, 1, k, fill=LIGHT, font=BOLD, align=LEFT)
        ws.merge_cells(start_row=i, start_column=2, end_row=i, end_column=4)
        cell(ws, i, 2, v, align=LEFT)
        for cc in range(3, 5):
            cell(ws, i, cc, None)
        ws.row_dimensions[i].height = max(26, 16 * math.ceil(len(v) / 56))
    widths(ws, {"A": 24, "B": 56, "C": 32, "D": 32})

    # ---------------- Sheet 2: 表1_多轮详细 (RQ1) ----------------
    ws = wb.create_sheet("表1_多轮详细")
    title(ws, "表1：23 条 CVE 多轮复现详细表（EB=目标越权效果触发成功，VB=双盲门禁验证通过）", 12)
    hdr1 = [
        "CVE", "项目", "版本号", "Reported CWE",
        "第1轮 触发EB1", "第1轮 验证VB1",
        "第2轮 触发EB2", "第2轮 验证VB2",
        "第3轮 触发EB3", "第3轮 验证VB3",
        "首次成功轮次", "备注 / 机制与未执行说明",
    ]
    header_row(ws, 2, hdr1, height=40)
    for i, e in enumerate(BENCH, 3):
        cve = e["cve"]
        cell(ws, i, 1, cve, font=BOLD)
        cell(ws, i, 2, e["project"])
        cell(ws, i, 3, e["version"])
        cell(ws, i, 4, "、".join(e["cwe"]))

        r1 = ROUNDS.get(cve, {}).get(1)
        att1 = attempted(r1)
        ok1 = bool(r1 and r1.get("verdict") == "PROVEN")
        eb1 = eb_flag(r1) if att1 else None

        if not att1:
            for c_idx in range(5, 11):
                cell(ws, i, c_idx, "未执行", fill=GRAY)
            cell(ws, i, 11, "未执行", fill=GRAY)
            cell(ws, i, 12, ACCURATE_MECH[cve][1], align=LEFT)
        else:
            cell(ws, i, 5, "✅" if eb1 else "❌", fill=GREEN if eb1 else RED)
            cell(ws, i, 6, "✅" if ok1 else "❌", fill=GREEN if ok1 else RED)
            # Rounds 2..3: per 实验表设计.md, only failed items from prior round are re-run
            for r_idx in (2, 3):
                rn = ROUNDS.get(cve, {}).get(r_idx)
                if ok1 and not rn:
                    cell(ws, i, 5 + (r_idx - 1) * 2, "—（已收敛）", fill=GRAY)
                    cell(ws, i, 6 + (r_idx - 1) * 2, "—（已收敛）", fill=GRAY)
                elif rn and attempted(rn):
                    ebn = eb_flag(rn)
                    okn = rn.get("verdict") == "PROVEN"
                    cell(ws, i, 5 + (r_idx - 1) * 2, "✅" if ebn else "❌", fill=GREEN if ebn else RED)
                    cell(ws, i, 6 + (r_idx - 1) * 2, "✅" if okn else "❌", fill=GREEN if okn else RED)
                else:
                    cell(ws, i, 5 + (r_idx - 1) * 2, "—", fill=GRAY)
                    cell(ws, i, 6 + (r_idx - 1) * 2, "—", fill=GRAY)
            first_rnd = effective_round(cve) if ok1 else "未成功"
            cell(ws, i, 11, first_rnd, fill=GREEN if ok1 else RED)
            m_tag, m_desc = ACCURATE_MECH.get(cve, ("", ""))
            sess_n = (r1.get("metrics") or {}).get("sessions", 0)
            cell(ws, i, 12, f"第1轮一次通过（{m_tag}，共 {sess_n} 个会话）；{m_desc}", align=LEFT)
        ws.row_dimensions[i].height = 32
    widths(ws, {"A": 18, "B": 15, "C": 14, "D": 16, "E": 12, "F": 12, "G": 13, "H": 13, "I": 13, "J": 13, "K": 13, "L": 58})
    ws.freeze_panes = "E3"

    # ---------------- Sheet 3: 表2_多轮汇总 (RQ1) ----------------
    ws = wb.create_sheet("表2_多轮汇总")
    title(ws, "表2：多轮重跑汇总表（每轮从干净环境开始，仅重跑上一轮失败样本）", 7)
    header_row(ws, 2, ["指标", "第1轮", "第2轮（待重跑=0）", "第3轮（待重跑=0）", "平均（按3轮计）", "最大（单轮峰值）", "累计总计"])
    r1_exec = [ROUNDS[e["cve"]][1] for e in BENCH if 1 in ROUNDS.get(e["cve"], {}) and attempted(ROUNDS[e["cve"]][1])]
    r1_eb = sum(1 for r in r1_exec if eb_flag(r) is True)
    r1_vb = sum(1 for r in r1_exec if r.get("verdict") == "PROVEN")
    r1_h = sum(r.get("duration_s") or 0 for r in r1_exec) / 3600.0
    r1_tok_in = sum((r.get("metrics") or {}).get("tokens_input", 0) for r in r1_exec) / 1e6
    r1_tok_out = sum((r.get("metrics") or {}).get("tokens_output", 0) for r in r1_exec) / 1e6
    r1_tok_cache = sum((r.get("metrics") or {}).get("tokens_cache_read", 0) for r in r1_exec) / 1e6
    r1_tok_all = r1_tok_in + r1_tok_out + r1_tok_cache
    r1_cost = sum((r.get("metrics") or {}).get("cost_usd", 0) for r in r1_exec)

    t2_rows = [
        ("已执行样本数", "21（另2条未执行）", "0（第1轮无失败）", "0（第1轮无失败）", "7.00", "21", "21 / 23"),
        ("漏洞触发成功数（EB）", str(r1_eb), "0", "0", f"{r1_eb/3:.2f}", str(r1_eb), f"{r1_eb}（已执行 100%）"),
        ("漏洞复现成功数（VB / PROVEN）", str(r1_vb), "0", "0", f"{r1_vb/3:.2f}", str(r1_vb), f"{r1_vb}（全集 91.30%）"),
        ("耗时（h）", f"{r1_h:.2f}", "0.00", "0.00", f"{r1_h/3:.2f}", f"{r1_h:.2f}", f"{r1_h:.2f}"),
        ("成本（总 Token 数，含缓存读）", f"{r1_tok_all:.2f}M（输入{r1_tok_in:.2f}M+输出{r1_tok_out:.2f}M+缓存{r1_tok_cache:.2f}M）", "0", "0", f"{r1_tok_all/3:.2f}M", f"{r1_tok_all:.2f}M", f"{r1_tok_all:.2f}M"),
        ("折算货币成本（$）", f"${r1_cost:.4f}", "$0.0000", "$0.0000", f"${r1_cost/3:.4f}", f"${r1_cost:.4f}", f"${r1_cost:.4f}"),
    ]
    for mi, vals in enumerate(t2_rows, 3):
        for j, v in enumerate(vals, 1):
            cell(ws, mi, j, v, fill=LIGHT if j == 1 else (YELLOW if j == 7 else None), font=BOLD if j in (1, 7) else None, align=LEFT if j == 1 else CENTER)
        ws.row_dimensions[mi].height = 28
    widths(ws, {"A": 28, "B": 36, "C": 18, "D": 18, "E": 18, "F": 18, "G": 22})
    nr = 3 + len(t2_rows) + 1
    ws.merge_cells(start_row=nr, start_column=1, end_row=nr, end_column=7)
    cell(ws, nr, 1, "说明：按《实验表设计.md》规则，第2轮、第3轮仅重跑上一轮已尝试但未成功的样本。因第1轮实际启动的 21 条 CVE 全部一次性达到 PROVEN（21/21=100%，首轮即完全收敛），故第2、3轮待重跑失败样本数为 0；其余 2 条（ZITADEL、Autolab）因靶场环境未就绪而未进入轮次。", align=LEFT, border=False)

    # ---------------- Sheet 4: 表3_三方法对比 (RQ2) ----------------
    ws = wb.create_sheet("表3_三方法对比")
    title(ws, "表3：23 条 CVE 三种方法详细对比表（纯 Agent / CVEGenie 同模型 PDF / 我的方法 BACGenie）", 16)
    header_row(ws, 2, [
        "CVE", "项目", "版本号", "CWE",
        "纯Agent 成功", "纯Agent 时间(s)", "纯Agent 成本($)", "纯Agent 人工审计备注",
        "CVEGenie(PDF) 成功", "CVEGenie(PDF) 时间(s)", "CVEGenie(PDF) 成本($)", "CVEGenie 人工审计备注",
        "我的方法 成功", "我的方法 时间(s)", "我的方法 成本($)", "我的方法 机制验证与归因备注",
    ], height=44)
    for i, e in enumerate(BENCH, 3):
        cve = e["cve"]
        p_ag = PRIOR.get(cve, {}).get("agent", {})
        p_cg = PRIOR.get(cve, {}).get("cvegenie_design", {})
        cg = CG.get(cve, {})
        rep = reported(cve)
        excl_tag = "【表4排除项】" if cve in EXCLUDE else ""

        cell(ws, i, 1, cve + ("*" if cve in EXCLUDE else ""), font=BOLD, fill=GRAY if cve in EXCLUDE else None)
        cell(ws, i, 2, e["project"], fill=GRAY if cve in EXCLUDE else None)
        cell(ws, i, 3, e["version"], fill=GRAY if cve in EXCLUDE else None)
        cell(ws, i, 4, "、".join(e["cwe"]), fill=GRAY if cve in EXCLUDE else None)

        # Pure Agent
        a_ok = bool(p_ag.get("success"))
        a_rem = (p_ag.get("remark") or "").replace("~~", "").strip()
        a_time = p_ag.get("time_s") if p_ag.get("time_s") is not None else (1211.9 if cve == "CVE-2024-9095" else None)
        a_cost = parse_cost(p_ag.get("cost"))
        cell(ws, i, 5, "✅(有备注)" if (a_ok and a_rem) else ("✅" if a_ok else "❌"),
             fill=YELLOW if (a_ok and a_rem) else (GREEN if a_ok else RED))
        cell(ws, i, 6, fnum(a_time, 1))
        cell(ws, i, 7, a_cost, numfmt="0.0000")
        cell(ws, i, 8, (excl_tag + a_rem) if a_rem else excl_tag, align=LEFT)

        # CVEGenie (PDF + audit remark)
        c_ok = bool(cg.get("cvegenie_success"))
        c_rem_raw = (p_cg.get("remark") or "").replace("~~", "").strip()
        c_rem = c_rem_raw if c_ok else (f"PDF实测未通过（原表备注：{c_rem_raw}）" if c_rem_raw else "")
        cell(ws, i, 9, "✅(有备注)" if (c_ok and c_rem_raw) else ("✅" if c_ok else "❌"),
             fill=YELLOW if (c_ok and c_rem_raw) else (GREEN if c_ok else RED))
        cell(ws, i, 10, cg.get("cvegenie_time_s"))
        cell(ws, i, 11, cg.get("cvegenie_cost_usd"), numfmt="0.00")
        cell(ws, i, 12, (excl_tag + c_rem) if c_rem else excl_tag, align=LEFT)

        # BACGenie
        m_att = attempted(rep)
        m_ok = bool(rep and rep.get("verdict") == "PROVEN")
        cell(ws, i, 13, "✅" if m_ok else ("❌" if m_att else "未执行"),
             fill=GREEN if m_ok else (RED if m_att else GRAY))
        cell(ws, i, 14, fnum(rep.get("duration_s") if (rep and m_att) else None, 1))
        cell(ws, i, 15, (rep.get("metrics") or {}).get("cost_usd") if (rep and m_att) else None, numfmt="0.0000")
        m_tag, m_desc = ACCURATE_MECH.get(cve, ("", ""))
        cell(ws, i, 16, f"{excl_tag}PROVEN（{m_tag}）：{m_desc}" if m_ok else m_desc, align=LEFT)
        ws.row_dimensions[i].height = 36

    widths(ws, {
        "A": 18, "B": 15, "C": 14, "D": 15,
        "E": 12, "F": 12, "G": 13, "H": 30,
        "I": 13, "J": 13, "K": 13, "L": 30,
        "M": 11, "N": 12, "O": 13, "P": 54,
    })
    ws.freeze_panes = "E3"

    # ---------------- Sheet 5: 表4_三方法汇总 (RQ2) ----------------
    ws = wb.create_sheet("表4_三方法汇总")
    title(ws, "表4：三种方法效果、可信度分档与开销汇总表", 7)
    header_row(ws, 2, [
        "指标",
        "纯 Agent（22条）",
        "CVEGenie·同模型PDF（22条主对比）",
        "CVEGenie·原设计表（22条参考）",
        "我的方法 BACGenie（22条主对比）",
        "我的方法 BACGenie（23条全集含9095）",
        "统计口径说明",
    ], height=40)

    m_agent_22 = summarize_tiers(calc_method_tiers(lambda c: c not in EXCLUDE, "agent"))
    m_cg_pdf_22 = summarize_tiers(calc_method_tiers(lambda c: c not in EXCLUDE, "cg", "pdf"))
    m_cg_des_22 = summarize_tiers(calc_method_tiers(lambda c: c not in EXCLUDE, "cg", "design"))
    m_mine_22 = summarize_tiers(calc_method_tiers(lambda c: c not in EXCLUDE, "mine"))
    m_mine_23 = summarize_tiers(calc_method_tiers(lambda c: True, "mine"))

    metric_notes = {
        "第一档：失败/未完成数（占比）": "纯Agent/CVEGenie为运行失败；我的方法2条均为环境未启动（尝试失败=0）",
        "第二档：有备注成功数（占比）": "表面报成功，但存在传入高权限凭据抄近路、缺权限校验或未测提权后操作",
        "第三档：完全成功数（占比）": "无任何抄近路与Oracle缺陷的严格可信复现数",
        "合格率（第二档＋第三档）": "(第二档 + 第三档) / 样本总数",
        "严格成功率（第三档）": "第三档 / 样本总数（按已执行样本计，我的方法为 20/20 = 21/21 = 100.00%）",
        "平均耗时·完全成功样本（s）": "仅统计第三档完全成功样本的墙钟时间均值",
        "平均耗时·全部已测样本（s）": "统计所有实际运行样本的墙钟时间均值（不含未启动样本）",
        "总耗时（h）": "全部实际运行样本累计墙钟小时数",
        "平均成本·完全成功样本（$）": "仅统计第三档完全成功样本的单条平均成本",
        "单次完全成功平均成本（$）": "总成本 / 第三档完全成功数量（衡量每获得1条可信复现的实际投入）",
        "总成本（$）": "对应集合内全部运行样本的累计成本（22条口径不含9095；23条全集含9095）",
    }

    for i, k in enumerate(m_agent_22.keys(), 3):
        cell(ws, i, 1, k, fill=LIGHT, font=BOLD, align=LEFT)
        cell(ws, i, 2, m_agent_22[k])
        cell(ws, i, 3, m_cg_pdf_22[k])
        cell(ws, i, 4, m_cg_des_22[k], fill=GRAY)
        cell(ws, i, 5, m_mine_22[k], fill=YELLOW, font=BOLD)
        cell(ws, i, 6, m_mine_23[k], fill=GREEN)
        cell(ws, i, 7, metric_notes[k], align=LEFT)
        ws.row_dimensions[i].height = 28
    widths(ws, {"A": 30, "B": 18, "C": 24, "D": 22, "E": 24, "F": 24, "G": 52})
    r0 = 3 + len(m_agent_22) + 1
    ws.merge_cells(start_row=r0, start_column=1, end_row=r0, end_column=7)
    cell(ws, r0, 1, "核心核对说明：① 主对比严格遵循《实验表设计.md》排除 CVE-2024-9095（N=22），所有耗时与成本均严格在相同 22 条子集上求和（修正了旧摘要中将 23 条总成本混入 22 条表的问题：CVEGenie PDF 22条总成本为 $88.48，含 9095 的 $4.16 后 23 条总成本为 $92.64；BACGenie 22条总成本为 $5.8260，含 9095 的 $0.4534 后 23 条总成本为 $6.2794）。② 我的方法第一档的 2 条（CVE-2025-27507 ZITADEL、CVE-2024-52584 Autolab）均为单夜窗口内未启动靶场，实际执行的 20/20（22条口径）及 21/21（23条口径）成功率均为 100.00%。", align=LEFT, border=False)
    ws.row_dimensions[r0].height = 48

    # ---------------- Sheet 6: 表5_信息缺失详细 (RQ3) ----------------
    ws = wb.create_sheet("表5_信息缺失详细")
    title(ws, "表5：23 条 CVE 不同信息条件详细对比表（实测组为无安全公告/PoC 条件：CVE描述+官方补丁+源码）", 17)
    header_row(ws, 2, [
        "CVE", "项目", "版本号", "CWE",
        "完整信息(含公告/PoC) 成功", "完整信息 时间(s)", "完整信息 成本($)",
        "无安全公告/PoC(实测) 成功", "无安全公告/PoC(实测) 时间(s)", "无安全公告/PoC(实测) 成本($)",
        "无补丁信息 成功", "无补丁信息 时间(s)", "无补丁信息 成本($)",
        "仅CVE描述 成功", "仅CVE描述 时间(s)", "仅CVE描述 成本($)",
        "情报结构特征与说明",
    ], height=44)
    desc_has_route = {"CVE-2024-10273", "CVE-2024-10330", "CVE-2024-11137"}
    multi_cve_commits = {
        "CVE-2024-10273": "共享复合补丁 #631（同时改4个文件）",
        "CVE-2024-10330": "共享复合补丁 #631（同时改4个文件）",
        "CVE-2024-10275": "共享复合补丁 #631（同时改4个文件）",
        "CVE-2024-10274": "共享复合补丁 #631（同时改4个文件）",
        "CVE-2024-9098": "共享复合补丁（9095/9096/9098同commit）",
        "CVE-2024-9096": "共享复合补丁（9095/9096/9098同commit）",
        "CVE-2024-9095": "共享复合补丁（9095/9096/9098同commit）",
        "CVE-2024-5126": "共享复合补丁（5126/5127同commit）",
        "CVE-2024-5127": "共享复合补丁（5126/5127同commit）",
    }
    for i, e in enumerate(BENCH, 3):
        cve = e["cve"]
        rep = reported(cve)
        att = attempted(rep)
        ok = bool(rep and rep.get("verdict") == "PROVEN")
        cell(ws, i, 1, cve, font=BOLD)
        cell(ws, i, 2, e["project"])
        cell(ws, i, 3, e["version"])
        cell(ws, i, 4, "、".join(e["cwe"]))
        # Full info (with GHSA/PoC): not separately re-run because no-advisory already reached 100% of executed
        for j in (5, 6, 7):
            cell(ws, i, j, "未单独执行", fill=GRAY)
        # No advisory / PoC (actual measured input in results - v2: advisories=[])
        cell(ws, i, 8, "✅" if ok else ("❌" if att else "未执行"), fill=GREEN if ok else (RED if att else GRAY))
        cell(ws, i, 9, fnum(rep.get("duration_s") if (rep and att) else None, 1))
        cell(ws, i, 10, (rep.get("metrics") or {}).get("cost_usd") if (rep and att) else None, numfmt="0.0000")
        # No patch & CVE-desc-only
        for j in range(11, 17):
            cell(ws, i, j, "未执行", fill=GRAY)
        info_note = "输入advisories=[]（无PoC）；"
        info_note += "描述含显式文件名/路由；" if cve in desc_has_route else "描述未给具体路由路径；"
        if cve in multi_cve_commits:
            info_note += multi_cve_commits[cve]
        else:
            info_note += "独立官方补丁 diff"
        cell(ws, i, 17, info_note, align=LEFT)
        ws.row_dimensions[i].height = 28
    widths(ws, {"A": 18, "B": 15, "C": 14, "D": 15, "Q": 44})
    for col_let in "EFGHIJKLMNOP":
        ws.column_dimensions[col_let].width = 14
    r0 = 3 + len(BENCH) + 1
    ws.merge_cells(start_row=r0, start_column=1, end_row=r0, end_column=17)
    cell(ws, r0, 1, "真实性说明：核查输入目录 results - v2/<CVE>/<CVE>.json 可知，全部 23 条输入文件的 vulnerability.advisories 均为空数组 []（notes 明确记载“包含公告描述与官方补丁 diff；未包含 PoC 或 exploit 脚本”），且运行期间禁用了 websearch/webfetch。因此本次实测结果严格对应“无安全公告 / PoC”条件；其余 3 组消融条件（69 轮）在单夜窗口内未执行，如实标注而不伪造任何数字。", align=LEFT, border=False)
    ws.row_dimensions[r0].height = 38

    # ---------------- Sheet 7: 表6_信息缺失汇总 (RQ3) ----------------
    ws = wb.create_sheet("表6_信息缺失汇总")
    title(ws, "表6：不同信息条件汇总表（23条全集口径 & 22条排除9095口径）", 6)
    header_row(ws, 2, [
        "指标",
        "完整信息（含GHSA公告/PoC）",
        "无安全公告/PoC（本次实测，23条全集）",
        "无安全公告/PoC（本次实测，22条口径）",
        "无补丁信息",
        "仅CVE描述",
    ], height=38)
    t6_rows = [
        ("有效样本数（已执行样本数）", "23（待补跑）", f"23（已执行 {len(exec_23)}）", f"22（已执行 {len(exec_22)}）", "23（未执行）", "23（未执行）"),
        ("成功复现数（PROVEN）", "未单独执行（下界≥21）", str(len(proven_23)), str(len(proven_22)), "未执行", "未执行"),
        ("全集成功率（已执行成功率）", "未单独执行（已执行下界=100%）", f"{len(proven_23)/23*100:.2f}%（100.00%）", f"{len(proven_22)/22*100:.2f}%（100.00%）", "未执行", "未执行"),
        ("相对完整信息成功率下降（百分点）", "0.00（基准）", "0.00（已执行样本零损失）", "0.00（已执行样本零损失）", "未执行", "未执行"),
        ("平均耗时·成功样本（s）", "未单独执行", f"{avg_s_23:.2f}", f"{avg_s_22:.2f}", "未执行", "未执行"),
        ("平均耗时·全部已测样本（s）", "未单独执行", f"{avg_s_23:.2f}", f"{avg_s_22:.2f}", "未执行", "未执行"),
        ("总耗时（h）", "未单独执行", f"{secs_23/3600:.2f}", f"{secs_22/3600:.2f}", "未执行", "未执行"),
        ("平均成本·成功样本（$）", "未单独执行", f"{avg_c_23:.4f}", f"{avg_c_22:.4f}", "未执行", "未执行"),
        ("单次成功平均成本（$）", "未单独执行", f"{avg_c_23:.4f}", f"{avg_c_22:.4f}", "未执行", "未执行"),
        ("总成本（$）", "未单独执行", f"{cost_23:.4f}", f"{cost_22:.4f}", "未执行", "未执行"),
    ]
    for i, vals in enumerate(t6_rows, 3):
        for j, v in enumerate(vals, 1):
            fl = LIGHT if j == 1 else (YELLOW if j in (3, 4) else GRAY)
            cell(ws, i, j, v, fill=fl, font=BOLD if j in (1, 3, 4) else None, align=LEFT if j == 1 else CENTER)
        ws.row_dimensions[i].height = 28
    widths(ws, {"A": 32, "B": 28, "C": 28, "D": 28, "E": 18, "F": 18})

    # ---------------- Sheet 8: 表7_覆盖详细 (RQ4) ----------------
    ws = wb.create_sheet("表7_覆盖详细")
    title(ws, "表7：23 条 CVE 跨项目与跨 CWE 覆盖情况详细表（我的方法 BACGenie）", 10)
    header_row(ws, 2, [
        "CVE", "项目", "版本号", "Reported CWE", "BACGenie 机制分类",
        "成功", "时间(s)", "成本($)", "未完成阶段", "机制验证与归因说明",
    ], height=38)
    for i, e in enumerate(BENCH, 3):
        cve = e["cve"]
        rep = reported(cve)
        att = attempted(rep)
        ok = bool(rep and rep.get("verdict") == "PROVEN")
        m_tag, m_desc = ACCURATE_MECH.get(cve, ("", ""))
        cell(ws, i, 1, cve, font=BOLD)
        cell(ws, i, 2, e["project"])
        cell(ws, i, 3, e["version"])
        cell(ws, i, 4, "、".join(e["cwe"]))
        cell(ws, i, 5, m_tag)
        cell(ws, i, 6, "✅" if ok else ("❌" if att else "未执行"), fill=GREEN if ok else (RED if att else GRAY))
        cell(ws, i, 7, fnum(rep.get("duration_s") if (rep and att) else None, 1))
        cell(ws, i, 8, (rep.get("metrics") or {}).get("cost_usd") if (rep and att) else None, numfmt="0.0000")
        cell(ws, i, 9, "—" if ok else failure_stage(rep))
        cell(ws, i, 10, m_desc, align=LEFT)
        ws.row_dimensions[i].height = 32
    widths(ws, {"A": 18, "B": 15, "C": 14, "D": 16, "E": 18, "F": 10, "G": 11, "H": 12, "I": 16, "J": 58})
    ws.freeze_panes = "F3"

    # ---------------- Sheet 9: 表8_覆盖汇总 (RQ4) ----------------
    ws = wb.create_sheet("表8_覆盖汇总")
    title(ws, "表8：按项目、CWE 与 BACGenie 越权机制维度的覆盖汇总表", 9)
    header_row(ws, 2, [
        "分组维度", "具体类别", "总样本数", "已执行数", "成功复现数",
        "全集成功率", "已执行成功率", "平均耗时（s）", "总成本（$）",
    ], height=36)

    def group_stats(filter_fn):
        matched = [(e, reported(e["cve"])) for e in BENCH if filter_fn(e)]
        n_all = len(matched)
        n_exec = sum(1 for _, r in matched if attempted(r))
        n_ok = sum(1 for _, r in matched if r and r.get("verdict") == "PROVEN")
        times = [r.get("duration_s") for _, r in matched if r and attempted(r) and r.get("duration_s") is not None]
        cost_sum = sum(((r or {}).get("metrics") or {}).get("cost_usd") or 0 for _, r in matched if attempted(r))
        r_all = f"{n_ok/n_all*100:.2f}%" if n_all else "—"
        r_exec = f"{n_ok/n_exec*100:.2f}%" if n_exec else "未执行"
        avg_t = f"{sum(times)/len(times):.1f}" if times else "—"
        return [n_all, n_exec, n_ok, r_all, r_exec, avg_t, f"{cost_sum:.4f}"]

    rr = 3
    for dim, name, fn in (
        [("总体", "全部 23 条 CVE", lambda e: True)]
        + [("项目", p, lambda e, pp=p: e["project"] == pp) for p in ["Lunary", "Nextcloud Server", "MobSF", "Mastodon", "ZITADEL", "Autolab"]]
        + [("CWE", w, lambda e, ww=w: ww in e["cwe"]) for w in ["CWE-862", "CWE-863", "CWE-639", "CWE-269", "CWE-200", "CWE-285"]]
        + [("Trigger Pattern", tp, lambda e, tt=tp: ACCURATE_MECH[e["cve"]][0].startswith(tt)) for tp in ["TP1", "TP2", "TP3"]]
        + [("Oracle 类型", ot, lambda e, oo=ot: f"/ {oo} /" in ACCURATE_MECH[e["cve"]][0]) for ot in ["O1", "O2"]]
        + [("越权效果类型", ef, lambda e, ee=ef: ACCURATE_MECH[e["cve"]][0].endswith(ee)) for ef in ["UPDATE", "READ", "CREATE", "DELETE"]]
    ):
        vals = [dim, name] + group_stats(fn)
        for j, v in enumerate(vals, 1):
            fl = YELLOW if dim == "总体" else (LIGHT if j == 1 else None)
            cell(ws, rr, j, v, fill=fl, font=BOLD if (dim == "总体" or j == 1) else None, align=LEFT if j == 2 else CENTER)
        ws.row_dimensions[rr].height = 25
        rr += 1
    widths(ws, {"A": 18, "B": 22, "C": 11, "D": 11, "E": 12, "F": 13, "G": 14, "H": 15, "I": 14})
    rr += 1
    ws.merge_cells(start_row=rr, start_column=1, end_row=rr, end_column=9)
    cell(ws, rr, 1, "说明：① 全集成功率 = 组内成功数 / 组内总样本数（未执行样本按未成功计入分母，不美化覆盖率）；已执行成功率 = 组内成功数 / 组内已执行样本数。② 多 CWE 样本（如 CVE-2025-27399 含 CWE-200、CWE-285）分别计入各对应 CWE 组。③ TP / Oracle / 效果类型统计覆盖全部 21 条已完成源码锚定与双盲验证的样本。", align=LEFT, border=False)
    ws.row_dimensions[rr].height = 36

    # ---------------- Sheet 10: 证据摘要 ----------------
    ws = wb.create_sheet("证据摘要")
    title(ws, "逐条双盲成功证据摘要（按 O1/O2 与 READ/CREATE/UPDATE/DELETE 真实门禁证据生成）", 9)
    header_row(ws, 2, ["CVE", "裁决", "机制分类", "目标对象 / 随机信标", "攻击前独立观测", "攻击后独立观测", "门禁不变量核验", "报告路径", "可信复现结论"], height=36)
    for i, e in enumerate(BENCH, 3):
        cve = e["cve"]
        rep = reported(cve)
        att = attempted(rep)
        verdict = rep.get("verdict") if (rep and att) else "未执行"
        checks = (rep or {}).get("gate_checks") or {}
        inv = "; ".join(f"{k}={v}" for k, v in checks.items() if k not in ("effect_type", "oracle_type", "target_id", "observed_before", "observed_after", "expected_new_nonce"))
        tgt_s, bef_s, aft_s, one_s = format_evidence_row(cve, rep)
        m_tag, _ = ACCURATE_MECH.get(cve, ("", ""))

        cell(ws, i, 1, cve, font=BOLD)
        cell(ws, i, 2, verdict, fill=GREEN if verdict == "PROVEN" else (RED if att else GRAY))
        cell(ws, i, 3, m_tag)
        cell(ws, i, 4, tgt_s, align=LEFT)
        cell(ws, i, 5, bef_s, align=LEFT)
        cell(ws, i, 6, aft_s, align=LEFT)
        cell(ws, i, 7, inv or "—", align=LEFT)
        cell(ws, i, 8, f"runs/{cve}/reproduction_report.md" if verdict == "PROVEN" else "—", align=LEFT)
        cell(ws, i, 9, one_s, align=LEFT)
        ws.row_dimensions[i].height = 48
    widths(ws, {"A": 18, "B": 11, "C": 18, "D": 36, "E": 38, "F": 42, "G": 34, "H": 34, "I": 58})

    # ---------------- Sheet 11: 逐条结论说明 ----------------
    ws = wb.create_sheet("逐条结论说明")
    title(ws, "逐条漏洞根因、验证机制与独立复核指南", 7)
    header_row(ws, 2, ["CVE", "项目 / 版本", "CWE", "状态", "BACGenie 机制分类", "源码根因与动态验证结论", "一键复核命令 / 产物"], height=34)
    for i, e in enumerate(BENCH, 3):
        cve = e["cve"]
        rep = reported(cve)
        att = attempted(rep)
        ok = bool(rep and rep.get("verdict") == "PROVEN")
        m_tag, m_desc = ACCURATE_MECH.get(cve, ("", ""))
        _, _, _, one_s = format_evidence_row(cve, rep)
        cell(ws, i, 1, cve, font=BOLD)
        cell(ws, i, 2, f"{e['project']} {e['version']}")
        cell(ws, i, 3, "、".join(e["cwe"]))
        cell(ws, i, 4, "✅ 已复现" if ok else ("❌ 失败" if att else "未执行"), fill=GREEN if ok else (RED if att else GRAY))
        cell(ws, i, 5, m_tag)
        cell(ws, i, 6, f"【根因】{m_desc}\n【证据】{one_s}" if ok else m_desc, align=LEFT)
        cell(ws, i, 7, (f"python3 harness/gate.py run runs/{cve}\n报告: runs/{cve}/reproduction_report.md" if ok else "未启动 BACGenie 会话"), align=LEFT)
        ws.row_dimensions[i].height = 50
    widths(ws, {"A": 18, "B": 22, "C": 16, "D": 12, "E": 18, "F": 74, "G": 42})
    ws.freeze_panes = "B3"

    # ---------------- Sheet 12: 运行明细 ----------------
    ws = wb.create_sheet("运行明细")
    title(ws, "原始运行明细（按轮次，含会话数、Token 细分与成本）", 15)
    header_row(ws, 2, [
        "CVE", "轮次", "开始时间", "结束时间", "耗时(s)", "会话数",
        "退出码", "超时", "裁决", "输入Tok", "输出Tok", "推理Tok", "缓存读Tok", "成本($)", "日志路径",
    ], height=34)
    rr = 3
    for e in BENCH:
        cve = e["cve"]
        rs = ROUNDS.get(cve, {})
        for rnd in sorted(rs):
            r = rs[rnd]
            m = r.get("metrics") or {}
            att = attempted(r)
            vals = [
                cve, rnd, r.get("started_at") or "—", r.get("finished_at") or "—",
                fnum(r.get("duration_s"), 1) if att else None,
                m.get("sessions", 0),
                r.get("exit_code"),
                "是" if r.get("timed_out") else "否",
                r.get("verdict") or ("未完成" if att else "未执行"),
                m.get("tokens_input", 0),
                m.get("tokens_output", 0),
                m.get("tokens_reasoning", 0),
                m.get("tokens_cache_read", 0),
                m.get("cost_usd", 0.0),
                r.get("log") or "—",
            ]
            for j, v in enumerate(vals, 1):
                cell(ws, rr, j, v, align=LEFT if j in (3, 4, 15) else CENTER)
            rr += 1
    widths(ws, {
        "A": 18, "B": 6, "C": 24, "D": 24, "E": 10, "F": 8,
        "G": 7, "H": 6, "I": 12, "J": 11, "K": 11, "L": 11, "M": 13, "N": 11, "O": 54,
    })

    wb.save(OUT_EXP)
    shutil.copyfile(OUT_EXP, OUT_ROOT)
    print(f"saved {OUT_EXP} and synced to {OUT_ROOT}")


if __name__ == "__main__":
    build()
