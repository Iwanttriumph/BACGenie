---
name: bac-convincing-report
description: 六段式可信越权动态复现报告（reproduction_report.md）撰写规范与假阳性驳回审计清单。在 gate.py 完成终审后，由 Primary Agent 加载以生成面向人类安全专家的完整复现证据报告。
---

# 可信越权动态复现证据报告规范（Audit-Grade Proof Report）

一份令人百分之百信服的越权动态复现报告，绝不能只写“脚本返回 200，复现成功”，而必须让任何挑剔的安全审阅者仅凭报告中的**源码锚点、实测权限矩阵、正负双向对照、盲态触发报文、攻击前后独立观测 Diff**，就能排除一切假阳性可能。

所有报文与数据**必须 100% 忠实摘录自 `runs/<CVE-ID>/evidence_bundle.json` 中 `gate.py` 实测生成的真实运行记录**，严禁手写编造或省略关键字段。

---

## `runs/<CVE-ID>/reproduction_report.md` 标准六段式结构

### 1. 执行摘要与三值裁决卡（Executive Verdict Card）
用一张清晰表格列出：
- **CVE 编号 / 目标组件与实测版本**
- **Trigger Pattern 分类**（`TP1`–`TP5` 及触发位置说明）
- **Oracle 类型与验证器**（`O1 / O2 / O3` × `READ / CREATE / UPDATE / DELETE`）
- **双盲门禁裁决结果**：`PROVEN` / `NOT_OBSERVED` / `INCONCLUSIVE`（附 `run_id` 与一键复核命令 `python3 harness/gate.py run runs/<CVE-ID>`）

### 2. 源码级“应然策略”与漏洞根因定位（Policy & Root-Cause Grounding）
- 引用目标版本真实源码路径、行号与关键代码片段，说明漏洞版本的实际鉴权逻辑错在哪里，并对比官方补丁或业务规则说明**理应执行的访问控制策略（Expected Policy）**。
- 给出**应然 vs. 实然授权矩阵表**：对比主体 `A`（攻击者）与主体 `P`（合法观察者/所有者）在目标操作上的预期结果（Deny vs. Allow）与实测结果。

### 3. 主体身份与有效权限实测证据（Live Subject & Permission Proof）
- 展示 `before_evidence.permission_checks.transcripts` 中的**真实请求与响应原文**（对长 Token 可保留前后缀脱敏显示，保留完整身份 ID 与权限数组）：
  - 证明 `A` 仅持有触发所需低权限（`required_permissions`），**明确不持有目标高阶/跨界权限（`forbidden_permissions`）**；
  - 证明 `P` 是独立于 `A` 与被删目标的合法授权观察主体。

### 4. 控制变量双向对照（Positive & Negative Controls）
- **正对照实测报文**：展示授权操作在隔离测试对象上正常生效的请求与响应，证明目标接口功能完好且未污染待测目标 `R`。
- **负对照实测报文**（适用时）：展示**同一枚 `A` 凭据**访问未受漏洞影响的相邻受限入口被 `401/403` 拒绝（或 `O2` 提权前被拒、`O3` 无受害者请求单跑被拒）的原始报文——用同凭据的 `403 vs. 越权成功` 形成强烈对比！

### 5. 纯盲态攻击触发流量（Clean-Room Blind Attack Trace）
- 说明物理盲态条件：`exploit.py` 在剥离管理员凭据、无容器/数据库访问权限、未知随机信标真值的独立目录运行，列出其实际收到的 `public_attacker_input` 内容。
- 贴出 `attack_evidence.requests_sent` 的完整 HTTP/协议请求与响应，高亮指出 **Trigger Point**（哪个 URL/Body/Header 字段跨越了什么边界；若为 `O2`，分阶段展示“阶段 1 非法获取能力”与“阶段 2 使用新能力执行受限操作”两段流量；若为 `O3`，展示受害者流量与攻击流量的时序配合）。

### 6. 独立观测前后 Diff 与假阳性排除核对表（Before/After Diff & Falsification Audit）
- **前后状态原始证据并排对比（Before vs. After）**：
  - 贴出 `before_evidence.before_observation.raw_evidence` 与 `after_evidence.after_observation.raw_evidence` 的原始回读响应；
  - 精确指出本轮动态随机信标（`canary` / `old_value -> new_value` / `create_tag`）及同域哨兵（`sentinel_id` 依然存活）的实测比对结果。
- **六项假阳性排除核查表（逐项打勾并注明本案例实证依据）**：
  1. [ ] **未误用高权限凭据**：`A` 凭据经实测不含 `forbidden_permissions`，且盲态环境无权接触 `P` 凭据；
  2. [ ] **未偷换目标操作或对象**：前后回读锁定同一 `target_id` 与受限字段（非拿 `CREATE` 冒充 `UPDATE`）；
  3. [ ] **未仅凭状态码判真**：结论建立在动态随机信标提取或独立观察者 `P` 的回读状态变化之上，而非 HTTP 2xx；
  4. [ ] **排除回显与公开数据（针对 READ）**：随机 `canary` 从未出现在 `public_attacker.json` 与攻击请求参数中；
  5. [ ] **排除服务故障与列表过滤（针对 DELETE）**：同作用域哨兵对象 `sentinel_id` 在攻击后经同一 `P` 通道回读依然存活；
  6. [ ] **闭合提权链或跨会话因果链（针对 O2 / O3）**：`O2` 已验证新能力的实际受限操作效果；`O3` 已验证无受害者流量时单跑必败。
