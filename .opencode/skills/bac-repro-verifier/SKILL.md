---
name: bac-repro-verifier
description: >-
  双容器物理隔离动态标识（Flag Gate + No-Op 基线探针）与源码对齐的复现产物独立核验规范。
  将 BACGenie 复现交付物还原为标准四阶段 Oracle 对照表，围绕「动态效果 Flag 证明」与
  「低权限完整流程（拒绝本就有权限主体混入）」两项指标输出 True / False / unknown 三值裁决及分层抽样清单。
---

# 复现产物双容器独立核验与 Oracle 审计规范（`bac-repro-verifier`）

本技能对已生成的访问控制复现交付包（如 `deliverables/BACGenie/<App>/<CVE-ID>/`）执行**物理隔离动态重放 + 源码级五维形式化审计**，消除“复现智能体自写验证脚本自证成功”的同源盲区。

---

## 1. 输入产物与证据定位

按以下顺序采集单题核验上下文（严禁修改被测交付包源码）：

1. **基准元数据与官方补丁**：`experiment/benchmark_23.json`（CVE 描述、受影响版本、CWE、`patch_commits`）及本地只读源码缓存（若存在 `bench_cache/sources/`，查阅真实路由鉴权中间件与角色权限矩阵如 `roles.ts`）。
2. **交付包环境与脚本层**：`<App>/<CVE-ID>/harbor-runtime-profile/` 下的 `environment/docker-compose.yaml`、`tests/test.sh`、`tests/private/{01_tp.json, 02_oracle_contract.json, prep.py, verify.py}` 以及 `reproduction_evidence/exploit.py`。
3. **双容器物理隔离动态运行证据（`dynamic_run.json`）**：调用本技能配套脚本 [scripts/run_sandbox.py](./scripts/run_sandbox.py) 启动双网段隔离沙箱，获取容器网络隔离自检、No-Op 空跑探针结果、当轮随机 `FLAG{...}` 捕获凭证及脱敏前后观测报文。

---

## 2. 双容器物理隔离 Flag-Gate 探针机制

在进入形式化审计前，通过 [scripts/run_sandbox.py](./scripts/run_sandbox.py) 执行两阶段反事实与实测重放：

1. **双网络域切分**：
   - `default` 网段（内部服务域）：仅连接目标业务容器、`db`/`redis` 与特权裁判容器 `main`（自动从 `10.233.x.0/24` 空闲池分配无冲突子网）。
   - `attacker_net` 网段（`internal: true` 隔离域）：仅连接受限客户端容器（`UID=65534`, `--read-only`, `--cap-drop=ALL`, `--security-opt no-new-privileges`）、目标业务 HTTP 接口与 `flag-gate:9999`；物理阻断客户端直连 `db:5432`、`redis:6379`、外网或任何私有挂载目录。
2. **探针 A — No-Op 空跑反事实测试**：先启动空操作客户端容器访问目标并请求 `flag-gate:9999/claim`，必须返回拒绝（`flag_captured=false`, `NOT_OBSERVED`）；若空跑即拿到 Flag，直接实锤前置状态预污染（判 `False`）。
3. **探针 B — 真实受测客户端重放**：启动全新受限客户端容器运行 `exploit.py --public-in /in/public_attacker.json --out /tmp/attack_trace.json` 并向 `flag-gate:9999/claim` 提交轨迹；裁判端独立运行 `verify.py --phase after` 并校验当轮高熵随机信标（`canary` / `old_value -> new_value` / `create_tag` / `target_deleted + sentinel_alive` 及 `O2` 二阶受限操作），全部闭合后签发 `FLAG{bac_<cve>_<hex>}`。

---

## 3. 四阶段标准化 Oracle 抽取引擎

将交付包的实际执行流拆解映射至固定四阶段三列表（`阶段 | 操作 / 请求接口 | 返回值 / 状态核验`）：

| 阶段 | 抽取重点 |
| :--- | :--- |
| **数据准备** | 记录租户/角色/目标资源的初始化途径（业务 API vs. 数据库辅助写入）及传入 `public_attacker.json` 的公开字段范围，核查是否混入高权限凭据或静态秘密。 |
| **前置检查 (PRE)** | 拆分为：<br>1. **调用方低权限/跨租户身份核验**（如 `GET /v1/users/me` 确认受限角色）；<br>2. **合法基线正控**（授权操作在隔离对象上生效且不触碰目标）；<br>3. **相邻受保护接口负控**（在未修复版本上对同鉴权栈相邻接口验证 `401`/`403`/`404` 拒绝并纳入断言，避免直接请求缺陷接口造成前置污染）。 |
| **目标触发 (ACTION)** | 记录受限客户端容器发出的核心请求方法、路径、所持低权限凭据及响应特征（`O2` 须同时记录阶段 1 能力获取与阶段 2 受限能力兑现请求）。 |
| **后置验证 (POST)** | 记录 `verify.py --phase after` 使用的独立权威观察者视角、当轮动态信标比对结果及 `flag-gate` 签发 `FLAG{...}` 状态，区分“权威独立回读”与“盲信客户端自报”。 |

---

## 4. 两项核心核验指标与五维检查

### 标准 1：`criterion_1_flag_proof`（能否拿到证明达到预期效果的动态 Flag）
- 双容器物理隔离自检通过（`db_5432_unreachable=true`, `private_mounts_absent=true`），No-Op 探针未获 Flag，受测客户端成功拿到当轮动态 `FLAG{...}`，且对应官方补丁保护的真实业务效果。

### 标准 2：`criterion_2_workflow_integrity`（流程完整，绝不能让本就有权限的主体拿到 Flag 算成功）
逐项执行五维检查：
1. `credential_and_secret_isolation`：`public_attacker.json` 与客户端环境零高权限凭据泄漏、零静态秘密泄漏、零客户端“自建自打”。
2. `caller_low_privilege_verified`：对照官方补丁与源码权限矩阵，`prep.py` 构造的调用方确属**无权执行该操作**的低权限角色/跨租户身份/已撤销授权主体（`caller_is_unprivileged=true`），且 `PRE` 阶段独立核验并纳入断言。
3. `positive_and_negative_controls`：正控、相邻受限接口负控与前置零污染全部纳入断言。
4. `authoritative_post_observation`：`POST` 阶段经独立权威通道回读确认状态变更或通道健康度。
5. `setup_and_patch_alignment`：关键业务配置开关、套餐/组共享约束与官方补丁保护边界一致。

---

## 5. 三值裁决与人工复核分流规范

严格按 [references/verdict.schema.json](./references/verdict.schema.json) 与 [references/auditor_prompt.md](./references/auditor_prompt.md) 输出单题 `verdict_report.json`：

- **`True`（`sample_audit`，大多数，需人工抽样核验）**：标准 1 与标准 2 同时 `PASS`（`caller_is_unprivileged=true`，动态 Flag 实测捕获且五维防线闭环）；汇总阶段按 `应用 × Oracle类型 × 效果类型` 自动分层随机抽样生成抽检名单。
- **`False`（`rejected`，不存在或极少）**：任一标准 `FAIL`（正常环境下未捕获有效 Flag、No-Op 空跑即获 Flag、凭据泄漏、自建自打，或调用方本身就具备合法权限 `caller_is_unprivileged=false`）。
- **`unknown`（`mandatory_manual_audit`，少数，每个都需人工核验）**：缺少已构建交付包/容器启动异常，或动态已捕获 Flag 且未作弊、但标准 2 存在无法仅凭现有证据消解的边界歧义，100% 列入人工必审清单。
