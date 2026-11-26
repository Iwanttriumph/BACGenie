---
name: bac-state-prep
description: Solution 2 越权漏洞触发前置状态高效准备规范、4090-1 隔离靶场（Docker/VM）启停纪律，以及 prep.py / verify.py / exploit.py 与 harness/gate.py 的精确接口契约。在搭建靶场、准备数据与编写验证脚本时必须加载。
---

# Solution 2 前置状态准备与 `4090-1` 双盲验证脚本规范

本规范指导如何在 `4090-1` 共享服务器上安全隔离地拉起目标漏洞版本，按 **Solution 2** 最短路径准备触发与观测状态，并严格遵守 `harness/gate.py` 的物理双盲接口。

---

## 一、 `4090-1` 多用户服务器靶场隔离红线（硬约束）

1. **命名空间与端口隔离**：
   - 优先使用 **Docker / Docker Compose** 在 `runs/<CVE-ID>/env/` 下编排目标服务及数据库（启动快、易重置）。
   - 强制设置唯一项目名：`COMPOSE_PROJECT_NAME=bacgenie_<cve_lowercase>`，所有容器名带 `bacgenie-` 前缀。
   - **严禁使用 `--network host` 或绑定 `0.0.0.0:常用端口`**（`4090-1` 上有其他同学的 `range-*` 靶场及常驻服务）！所有暴露给宿主机的端口一律绑定回环随机端口或探测确认空闲的高位端口：`127.0.0.1:<free_port>:<container_port>`。
   - **严禁触碰、重启或清理任何非 `bacgenie_` 前缀的容器、镜像、进程或宿主机全局包**。
2. **重型环境回退**：仅当漏洞强依赖完整 Linux systemd / 内核特性无法容器化时，才使用 `cve-genie/vm_library` 的 QEMU overlay 虚机（绑定独立空闲本地端口）。

---

## 二、 Solution 2：前置状态准备六步法与常见暗坑排查

从 `02_oracle_contract.json` 的攻击请求与验证断言**反向拆解最小依赖对象**，避免无意义的复杂初始化：

1. **反向拆解参数绑定**：列出路径、Query、Body、Header 所需的全部实体（如组织/World、攻击主体 `A`、观察主体 `P`、目标对象 `R`、同域哨兵 `R_sentinel`、正对照一次性对象 `R_ctrl`）。
2. **核对源码级隐式业务约束（防连环报错）**：
   - **接口可选 vs 数据库 `NOT NULL`**：阅读 ORM Model / SQL Migration，检查那些 API 文档未标必填但数据库要求非空的字段（例如 Lunary 创建模型时的 `tokenizer`、注册时的 `projectName`）。
   - **默认套餐 / Feature Flag / 许可证限制**：检查新注册组织默认的 Plan/Tier 是否会拦截后续邀请特定角色或开启目标功能（如 Lunary 默认 `free` 套餐禁止创建细粒度成员角色、Grafana Datasource 需开启 `oauthPassThru`、ZITADEL 需对应实例/组织上下文 Header `x-zitadel-orgid` 与 `Host`）。
3. **按优先级选择状态构造方式**：
   - **优先级 1 — 复用已有干净状态**：靶场初始化自带的默认管理员可作为观察者 `P`（但**严禁直接拿默认最高管理员作为攻击者 `A`**！）。
   - **优先级 2 — 调用受支持的应用 API**：优先用官方注册/管理 API 创建 `A`、分配低权限角色并创建业务资源 `R`，确保关联表、缓存与默认字段完整同步。
   - **优先级 3 — 直接数据库初始化 + 强制应用 API 回读核验**：当某个前置条件（如企业套餐升级、邀请 Token、特定历史状态）缺少便捷 API 时，允许在 `prep.py` 中按目标版本精确 Schema 写入数据库，但**随后必须在 `verify.py --phase before` 中经由应用层真实接口回读确认应用认可该状态**。
4. **每次运行幂等自洽**：`gate.py` 会多次生成全新随机 `nonce_bundle` 重跑 `prep.py`。因此 `prep.py` 必须**完全幂等**（每次使用唯一后缀创建隔离测试租户/账号/资源，或先清理上次测试实体再写入新 `nonces`），确保连续运行 5 次均稳定成功。

---

## 三、 三件套脚本与 `harness/gate.py` 的精确 CLI 与 JSON 契约

### 1. `prep.py`（特权准备端 —— 允许访问管理凭据与 DB，严禁发起漏洞攻击）
调用方式：
```bash
python3 prep.py --nonce-in <nonce.json> --public-out <public.json> --private-out <private.json>
```
- 输入 `<nonce.json>` 由 `gate.py` 生成，格式为：
  `{"run_id": "...", "canary": "bacgenie_canary_...", "old_value": "bacgenie_old_...", "new_value": "bacgenie_new_...", "create_tag": "bacgenie_create_..."}`
- **双信封物理切分输出（`gate.py` 会做秘密泄漏扫描！）**：
  - `<public.json>`（唯一允许给盲态 `exploit.py` 看的文件）：
    - **只允许包含**：`base_url`、`attacker_auth`（低权限 `A` 的 Token/Cookie；匿名漏洞则为 `{}`）、目标公开引用 ID（如 `target_id`、`attacker_scope_id`、`target_scope_id`），以及：
      - 若 `effect_type == "UPDATE"`：包含 `"desired_new_value": nonces["new_value"]` 及全量更新所需的非机密常规字段；
      - 若 `effect_type == "CREATE"`：包含 `"create_tag": nonces["create_tag"]`。
    - **绝对禁止包含**：`P`（或 `V`）的凭据、数据库连接串、`READ` 的 `nonces["canary"]`、`UPDATE` 的 `nonces["old_value"]`、`R_sentinel` 的信息！一旦泄漏，`gate.py` 立即判 `INCONCLUSIVE`！
  - `<private.json>`（仅供 `verify.py` 读取，在 `exploit.py` 运行期间会被 `gate.py` 从磁盘抹除）：
    - 保存 `observer_auth`（`P` 的凭据）、`victim_auth`（`O3` 的 `V` 凭据）、`db_config`（若使用只读 SQL 辅助核验）、`target_id`、`sentinel_id`、`disposable_control_id` 等完整核验上下文。

### 2. `verify.py`（独立裁判端 —— 校验权限边界、正负对照与前后观测）
支持阶段：`--phase before`、`--phase after`（若为 `O3` 额外支持 `--phase victim_traffic`）。

#### (a) `--phase before`
调用方式：
```bash
python3 verify.py --phase before --private-in <priv.json> --public-in <pub.json> --nonce-in <nonce.json> --out <before_out.json>
```
`<before_out.json>` 必须输出如下结构（含**真实原始请求/响应或查询记录**，供主审官审计与写报告）：
```json
{
  "permission_checks": {
    "passed": true,
    "summary": "Verified A holds org.idp.write and lacks iam.idp.write; P holds iam.idp.read & iam.idp.write",
    "transcripts": [
      {"subject": "attacker", "request": {...}, "response": {...}},
      {"subject": "observer", "request": {...}, "response": {...}}
    ]
  },
  "positive_control": {
    "passed": true,
    "summary": "Authorized operation on isolated control resource succeeded without touching target R",
    "transcripts": [{"request": {...}, "response": {...}}]
  },
  "negative_control": {
    "passed": true,
    "summary": "Attacker token received HTTP 403 on unaffected instance-level endpoint /admin/v1/idps/google",
    "transcripts": [{"request": {...}, "response": {...}}]
  },
  "before_observation": {
    "passed": true,
    "summary": "Target R exists before attack with expected baseline state",
    "target_id": "...",
    "sentinel_id": "... (required for DELETE)",
    "observed_value": "... (must equal nonces['old_value'] for UPDATE)",
    "target_exists": false,
    "target_alive": true,
    "sentinel_alive": true,
    "raw_evidence": {"request": {...}, "response": {...}}
  }
}
```
*(按 `effect_type` 填写对应关键字段：`READ` 的 `raw_evidence` 须包含 `nonces["canary"]`；`UPDATE` 必填 `target_id` 与 `observed_value`；`CREATE` 必填 `"target_exists": false`；`DELETE` 必填互不相同的 `target_id`/`sentinel_id` 且 `target_alive: true, sentinel_alive: true`。)*

#### (b) `--phase after`
调用方式：
```bash
python3 verify.py --phase after --private-in <priv.json> --public-in <pub.json> --nonce-in <nonce.json> --before-in <before_out.json> --attack-in <attack_out.json> --out <after_out.json>
```
`<after_out.json>` 必须输出：
```json
{
  "after_observation": {
    "passed": true,
    "channel_healthy": true,
    "summary": "Observer P independently confirmed target R state change matching runtime nonce",
    "target_id": "...",
    "observed_value": "... (for UPDATE)",
    "target_exists": true,
    "target_deleted": true,
    "sentinel_alive": true,
    "raw_evidence": {"request": {...}, "response": {...}}
  },
  "capability_use_verified": true,
  "solo_baseline_blocked": true,
  "window_missed": false
}
```

### 3. `exploit.py`（纯盲态外部网络攻击端 —— 严禁特权操作）
调用方式（在空临时目录、干净环境变量下由 `gate.py` 调起）：
```bash
python3 exploit.py --public-in <public.json> --out <attack_trace.json>
```
- **硬性反作弊禁令（`gate.py audit-exploit` 静态 AST 强检）**：
  - **严禁导入** `subprocess`、`docker`、`paramiko`、`sqlite3`、`psycopg2`、`pymysql`、`sqlalchemy`、`redis` 等任何容器/Shell/数据库模块，严禁调用 `os.system`/`os.popen`；
  - 只允许使用纯网络客户端库（如标准库 `urllib.request`、`http.client`、`socket`、`ssl`、`hashlib`、`hmac`、`base64`、`json`，或已安装的 `requests`）对 `<public.json>` 中的 `base_url` 发包！
- `<attack_trace.json>` 输出结构：
```json
{
  "requests_sent": [
    {
      "step": "cross_world_delete",
      "request": {"method": "POST", "url": "...", "headers": {...}, "body": {...}},
      "response": {"status": 204, "headers": {...}, "body": ""}
    }
  ],
  "extracted_data": "... (for READ / O3, place leaked secret content here)",
  "capability_use_requests": []
}
```
*(若为 `O2`，必须在阶段 1 获取能力后，继续用受益主体的新会话发起阶段 2 受限操作，并将阶段 2 的请求/响应同时记入 `capability_use_requests` 与 `requests_sent`！)*
