---
name: bac-trigger-and-oracle
description: 越权漏洞（Broken Access Control）源码级 Trigger Pattern 分类（TP1-TP5）与 Solution 1 Oracle 契约设计（O1/O2/O3 × CRUD + OWASP 正负对照）。在分析 CVE 根因并编写 01_tp.json 与 02_oracle_contract.json 时必须加载。
---

# 越权漏洞 Trigger Pattern 与 Oracle 契约设计规范

本规范将越权漏洞的**触发机制（TP1–TP5）**、**验证契约（Solution 1: O1/O2/O3 × CRUD）**与 **OWASP 授权矩阵对照准则（WSTG-ATHZ-02/04、API3:2023）**统一为可执行、可证伪的源码级契约。

---

## 一、 源码锚定铁律（禁止盲猜，必须查源码）

1. **绝不凭 CVE 摘要或 CWE 标签臆测接口**：必须在目标漏洞版本的真实源码树中检索路由表、Controller/Handler、Proto/OpenAPI 定义、鉴权中间件（Middleware/Decorator/Guard）及默认角色权限表（如 `defaults.yaml`、RBAC migration）。
2. **区分“漏洞实现的错误校验”与“业务应然的授权边界（Expected Policy）”**：
   - 漏洞版本的源码往往写错了权限注解（例如 ZITADEL `CVE-2025-27507` 在漏洞版将实例级 `UpdateLDAPProvider` 标为 `org.idp.write`，而官方补丁更正为 `iam.idp.write`；Venueless `CVE-2026-5599` 在漏洞版查全局 `User.objects.filter`，补丁更正为 `request.world.users`）。
   - 必须结合**安全公告 + 业务作用域语义 + 修复补丁差异**联合确立 `expected_policy` 与 `policy_basis`。
3. **禁止留空观测通道**：只要有源码或运行环境，必须查清真实的**身份/权限查询通道**（API 或只读权限表）与**效果回读通道**（独立 GET API 或精确匹配目标版本 Schema 的只读 SQL 查询，明确软删除如 `deleted=true` 还是物理删除）。

---

## 二、 Trigger Pattern 分类体系（TP1–TP5）

根据攻击者跨越权限边界所需的触发动作分类（可单选，也可多标签组合，但必须在 `combination_mode` 中区分联合条件 `joint_and` 与未定候选 `candidate_or`）：

| 类别 | 定义与常见 CWE | 判定准则与反例边界 |
| :--- | :--- | :--- |
| **`TP1`** | **直接调用受限 API，无需篡改越界参数**<br>(`CWE-862`/`425`/`424`/`602`, `CWE-653`) | 仅当 `victim_request_required=false` 时成立：<br>① 功能级缺鉴权（如低权限 Member 直接 `DELETE /v1/evaluators/:id`）；<br>② 列表接口未按作用域过滤，合法调用自身路径自动混入跨界数据（如 Pretix `GET .../events/{EVENT_A}/checkins/` 自动返回 `EVENT_B` 数据）。 |
| **`TP2`** | **修改 URL 路径或 Query 参数**<br>(`CWE-639`/`566`/`283`, `CWE-915`, `CWE-653`) | 替换 URL 路径主键/UUID（如 `PATCH /v1/runs/{victim_run_id}/score`）或在 Query 中注入受限配置键（如 `GET /cv?upas=1&htp=8081`）。 |
| **`TP3`** | **修改请求体（Body）字段**<br>(`CWE-639`, `CWE-915`/`472`, `CWE-653`) | ① URL 过鉴权、Body 跨界写目标（如 URL `project_id=2` 过检、Body `project_id=1` 落库；或 URL `world_A` 过检、Body `user_id=target_in_world_B` 删除）；<br>② Mass Assignment 在注册/更新表单注入受限属性（如 `role=app-admin`）。 |
| **`TP4`** | **修改/伪造请求头（Header / Cookie）**<br>(`CWE-291`/`290`, `CWE-784`) | 伪造 `X-Forwarded-For: 127.0.0.1` 命中内网白名单（常与 `TP2` `uid=admin` 构成 `joint_and` 联合触发），或伪造未签名 Cookie（如 `Cookie: admin=20`）。注意区分**真实调用者身份（匿名）**与**服务端采信身份（admin）**。 |
| **`TP5`** | **跨主体请求依赖（受害者与攻击者均须发请求）**<br>(`CWE-488`, `CWE-653`) | 受害者请求是触发因果链的必要条件（顺序残留 `before` 或并发窗口 `concurrent`），如工作线程 `ThreadLocal` 身份残留、共享 Datasource OAuth 身份串号。管理员前置建测试数据**不属于** `TP5`。 |

---

## 三、 Oracle 模板选择（O1 / O2 / O3）与效果验证器（CRUD）

### 1. 三类 Oracle 模板（定义“理应发生什么”）
- **`O1`（未授权资源操作）**：调用者本来无权对指定资源、功能或敏感字段执行 `READ / CREATE / UPDATE / DELETE`，但攻击直接产生了受保护效果。
- **`O2`（非法获取并使用额外能力）**：攻击者通过非法角色注入、跨项目自授成员、伪造管理凭据交换等取得新能力，**并由受益主体（`A` 或新建账号 `U`）使用自身会话实际完成一项原本被 `401/403` 拒绝的受限操作**。*铁律：只看到 `role="admin"` 字段变化而未验证阶段 2 能力实际生效，绝不构成完整 `O2`！*
- **`O3`（跨主体请求状态/身份污染）**：受害者 `V` 的请求状态、会话或凭据跨请求污染了攻击者 `A`，使 `A` 获得 `V` 的私有数据或高权限执行上下文。*铁律：必须同时设计“无 `V` 请求时的单跑拒绝基线（`solo_baseline_blocked`）”与“有 `V` 请求时的调度触发（`o3_schedule`）”。*

### 2. 四类效果不变量与防假阳性铁律（定义“如何观测实际发生了什么”）
所有观测与 `harness/gate.py` 动态注入的高熵随机值绑定：

- **`READ`（越权读取 / 敏感属性披露 BOPLA）**：
  - `before`：由合法观察者 `P`（或 `V`）读取目标资源 `R`，确认其中包含 `gate.py` 本轮注入的随机私密信标 `nonces["canary"]`，且公开接口与 `A` 自身资源不含该信标。
  - `after`（检验 `attack_response`）：确认 `A` 的攻击响应中精确提取出同一 `nonces["canary"]`（彻底排除请求参数回显、HTTP 200 登录框/空壳页、公开摘要）。
- **`UPDATE`（越权修改既有资源）**：
  - `before`：`prep.py` 在既有对象 `R.id` 的受限字段写入 `nonces["old_value"]`；`P` 独立回读确认 `target_id == R.id` 且 `observed_value == nonces["old_value"]`。
  - **全量更新约束**：若攻击接口为 `PUT` 等全量覆盖语义（如 ZITADEL `PUT /admin/v1/idps/ldap/{id}`），必须在 `request_constraints` 和 `public_attacker.json` 中提供非机密必填基准结构（如 `servers`、`baseDn`），防止因漏传普通必填项报 400 掩盖鉴权漏洞。
  - `after`：`P` 对**同一 `R.id`** 独立回读，断言 `observed_value == nonces["new_value"]`（彻底拦截“用 `POST` 新增配置冒充 `PUT` 修改配置”）。
- **`CREATE`（越权创建资源）**：
  - `before`：`P` 在目标受限作用域查询确认不存在带 `nonces["create_tag"]` 的对象（`target_exists: false`）。
  - `after`：`P` 在目标受限作用域独立回读，确认带 `nonces["create_tag"]` 的对象已真实持久化且归属该受限作用域（仅攻击响应返回 `id` 不算数）。
- **`DELETE`（越权删除资源）**：
  - `before`：在受限作用域同时创建目标对象 `R`（**严禁将观察者 `P` 本人设为被删目标！**）与**同域未触碰哨兵对象 `R_sentinel`**（`target_id != sentinel_id`）；`P` 实测确认两者均 `alive: true`。
  - `after`：`P` 经同一可信通道回读，确认 `R` 进入源码定义的真实删除态（`target_deleted: true`，如软删除 `deleted=true` 或硬删除记录不存在），**且同一时刻 `R_sentinel` 依然 `sentinel_alive: true`**（彻底排除服务崩溃、Token 失效、列表过滤假象）。

---

## 四、 落盘文件精确格式（由 `harness/gate.py validate-contract` 强校验）

### 1. `runs/<CVE-ID>/01_tp.json`
```json
{
  "cve_id": "CVE-YYYY-NNNNN",
  "classification": ["TP3"],
  "combination_mode": "single",
  "source_grounding": {
    "vulnerable_version": "vX.Y.Z",
    "route_file": "path/to/routes.py:L42",
    "handler_file": "path/to/views.py:L88-L112",
    "auth_mechanism": "Bearer token via WorldTokenAuthentication; checks WORLD_USERS_MANAGE on path world_id only",
    "patch_diff_summary": "Replaced global User.objects.filter(id=user_id) with request.world.users.filter(id=user_id)"
  },
  "core_requests": [
    {
      "id": "attack_req_1",
      "actor": "attacker",
      "method": "POST",
      "endpoint": "/api/v1/worlds/{world_id}/delete_user",
      "trigger_points": [
        {
          "location": "body",
          "field": "user_id",
          "action": "replace",
          "description": "Path world_id uses attacker's world_A, while JSON body user_id specifies target_user in victim's world_B"
        }
      ]
    }
  ],
  "interaction": {
    "victim_request_required": false,
    "relation": null,
    "condition": null
  }
}
```

### 2. `runs/<CVE-ID>/02_oracle_contract.json`
```json
{
  "cve_id": "CVE-YYYY-NNNNN",
  "oracle_type": "O1",
  "effect_type": "DELETE",
  "subjects": {
    "attacker": {
      "is_anonymous": false,
      "role_description": "Manager in World A only",
      "required_permissions": ["world_A:api_access", "world_A:world.users.manage"],
      "forbidden_permissions": ["world_B:world.users.manage", "system:admin"]
    },
    "observer": {
      "role_description": "Independent manager/admin in World B (distinct from target_user)",
      "required_permissions": ["world_B:users.read", "world_B:world.users.manage"],
      "distinct_from_target": true
    }
  },
  "target_operation": {
    "resource_type": "User account belonging to World B",
    "operation": "DELETE",
    "restricted_field": "deleted",
    "expected_policy": "A token scoped to World A with world.users.manage must be denied deleting any user belonging to World B",
    "policy_basis": "GHSA advisory + commit 02b9cbe5 scoping User lookup to request.world.users",
    "request_constraints": ["Content-Type: application/json", "user_id and token_id are mutually exclusive"]
  },
  "controls": {
    "positive": {
      "actor": "attacker",
      "action": "POST /api/v1/worlds/{world_A}/delete_user on isolated disposable_user_A in World A",
      "isolation_strategy": "Uses dedicated disposable_user_A in World A; never touches World B"
    },
    "negative": {
      "applicable": true,
      "action_or_reason": "Attacker calls POST /api/v1/worlds/{world_B}/delete_user directly with World A token -> expected 401/403 denial"
    }
  },
  "observations": {
    "before": {
      "actor": "observer",
      "channel": "Verified World B admin user-detail API or read-only DB query on venueless User table",
      "assertion": "Both target_user and sentinel_user exist in World B with deleted=false"
    },
    "after": {
      "actor": "observer",
      "channel": "Same channel as before observation",
      "assertion": "target_user transitions to soft-deleted state (deleted=true / profile wiped per soft_delete()) while sentinel_user in World B remains deleted=false"
    }
  }
}
```
*(若 `oracle_type == "O2"`，须额外包含 `"o2_capability": {"capability_change": "...", "capability_use_operation": "..."}`；若 `oracle_type == "O3"`，须在 `subjects` 包含 `"victim"` 并额外包含 `"o3_schedule": {"relation": "before|concurrent", "shared_state_condition": "...", "reset_strategy": "...", "attempt_limit": 20}`。)*
