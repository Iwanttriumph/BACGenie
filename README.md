# Kaiti v2 — 双盲可信越权漏洞动态复现系统 (OpenCode Primary/Worker + Double-Blind Gate)

## Kaiti v2 架构与运行方式（`4090-1` 实验环境）

`Kaiti v2` 基于 OpenCode 原生 `Primary + Worker` 双层智能体、模块化领域技能（Skills）与确定性双盲重放门禁（`harness/gate.py`）实现越权漏洞（Broken Access Control）的可信动态复现：

- **两类正交智能体（`.opencode/agents/`）**：
  - `kaiti-planner`（`mode: primary`，怀疑论主审架构师）：权限级锁死仅能读写战略账本 `00_ledger.md` / 终审报告 `reproduction_report.md`、调度 `kaiti/worker`、调用唯一受控门禁 `python3 harness/gate.py`。
  - `kaiti/worker`（`mode: subagent`，最小知情面现场执行员）：叶子执行节点（禁止再派子智能体，禁止修改 `harness/`、`verdict.json` 与 `evidence_bundle.json`）；每次拉起独立子会话，按信息防火墙分别承担**源码定位与契约起草**、**隔离靶场与 Solution 2 前置准备**、**Clean-Room 纯盲态攻击开发**。
- **三个领域技能（`.opencode/skills/`）**：
  - `bac-trigger-and-oracle`：源码锚定的 `TP1`–`TP5` 分类、`Solution 1`（`O1`/`O2`/`O3` × `READ`/`CREATE`/`UPDATE`/`DELETE`）契约与 OWASP 正负对照规范。
  - `bac-state-prep`：`Solution 2` 反向拆解依赖、`复用 > 应用 API > 直接 DB 初始化(必回读)` 策略、`4090-1` 容器/虚机隔离规范与三件套 CLI 契约。
  - `bac-convincing-report`：基于实测原始报文的六段式复现证明报告与六项假阳性排除核对表。
- **确定性双盲重放门禁（`harness/gate.py`）**：
  - 静态 AST 反作弊检查（拦截 `exploit.py` 导入容器/Shell/数据库模块）；
  - 每次运行动态生成随机信标（`canary` / `old_value` / `new_value` / `create_tag`），扫描拦截 `prep.py` 向公开输入泄漏秘密；
  - 在运行盲态 `exploit.py` 期间将 `private_verifier.json` 物理从磁盘抹除仅存于内存，杜绝偷读管理凭据；
  - 结合同域哨兵（`sentinel_id`）与独立观察者回读，签发 `PROVEN` / `NOT_OBSERVED` / `INCONCLUSIVE` 三值裁决单 `verdict.json` 与全链路原始证据包 `evidence_bundle.json`。

### 在 `4090-1` 上一键运行与自检

```bash
# 1. 运行门禁单元测试
python3 -m unittest harness/test_gate.py -v

# 2. 启动端到端越权动态复现（自动使用隔离 .opencode-runtime，避开多用户端口与 DB 锁冲突）
./kaiti_run.sh CVE-2025-27507 yeowl/glm-5.3

# 3. 单独重跑指定案例的双盲动态信标终审复核
python3 harness/gate.py run runs/CVE-2025-27507
```

---

## Legacy v1 说明：Trigger Pattern Agent

## Oracle 设计与 src 目录

实现位于 `src`：`main.py` 编排阶段，`agents` 包含触发抽取和 Oracle 设计，`toolbox` 提供模型客户端、静态分类、校验与文件保存；提示词和 Schema 分别在 `src/prompts`、`src/schemas`。根目录 `agent.py` 是兼容入口。测试迁至 `tests`。

```powershell
.\.venv\Scripts\python.exe agent.py --stage tp --results-dir "results - v2" --cve CVE-2026-5599
.\.venv\Scripts\python.exe agent.py --stage oracle --results-dir "results - v2" --cve CVE-2026-5599
.\.venv\Scripts\python.exe src/main.py --stage all --results-dir "results - v2" --cve CVE-2026-5599
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

`--stage` 默认 `tp`；`oracle` 读取同目录已有 TP 输出和抽取依据，输入哈希不匹配或 TP 失败时要求重跑 TP。`all` 先 TP 后 Oracle。`--overwrite` 对选中的阶段生效。

Oracle 使用原始内联材料及 TP，形成共享攻击方案并选择全部有证据支持的 O1（未授权操作）、O2（非法能力获取及使用）、O3（跨主体状态污染）目标，再设计效果检查。候选位置保留待确认分支；联合修改归入同一方案。仅生成设计，不执行请求、查询、数据准备或漏洞验证。语义正确性仍需要人工审阅。

新增 `oracle.json`、`oracle_analysis.md`、`oracle_run.json` 和 `oracle_llm_response.json`。Oracle JSON 仅包含 cve_id 和 oracles，每项为 id、template、verifier。subjects 按主体名保存语言描述，resources 描述资源归属与前置状态；attack_request 直接给出请求数组，controls 区分 positive/negative。verifier 使用单个 type、必要 observations 和一条 success_condition。方案编排、模板选择、证据与缺口写入分析文件；未知接口和查询保留 null。

Oracle 缓存核对输入、TP、抽取分析、提示词和 Schema 哈希；失败保留先前有效设计，最近状态查看 `oracle_run.json`。Oracle 模型输出预算为 24000 tokens，TP 为 12000；截断输出拒绝保存。方法来源：用户文档 Solution 1（https://my.feishu.cn/wiki/QfsOw2qxqiRdOTktB3jcHhsPndg），已整理为本地提示词，运行时不访问文档。

抽取提示词 v7-core-operation-focus：先选择公告明确强调的核心操作或 PoC 主流程，再抽取请求，不再机械展开全部受影响接口。不能唯一确定时保留核心操作的多个可能入口，方法未知仍为 null。选择理由及未纳入接口记录在 extraction_analysis.md。此结果是核心流程的分类，并不声称覆盖同一 CVE 下所有受影响功能。静态分类逻辑仍为 locations 并集。

当前输出使用单一标签数组，例如 `"classification": ["TP2", "TP3"]`。不再输出 confirmed/alternatives。标签表示涉及或可能涉及的类型，不表示各标签均已独立证实。每个触发点的 locations 仍保留位置不确定性；不同实际触发点分开记录。

当前流程 v8-source-api-evidence / static-v3-location-union：agent 负责分析所有可能的触发位置，静态代码只求标签并集。参数修改位置未知时不能默认为 api；若 URL/body 无法区分则保留两者，更广的不确定性保留 url/body/header。完全没有触发动作线索时允许空数组。普通参数不等于触发参数。

每个输入表达一条触发流程。仅当 `interaction.victim_request_required=false` 时 api+invoke 才映射 TP1；依赖为 true 时加入 TP5，普通调用不另记为 api 触发点。字段修改仍可与 TP5 同时成立。列表正常调用自动泄露其他范围数据可属于 TP1；指定越界对象执行操作则保留参数触发点。

读取准备好的 CVE JSON，用 LLM 抽取请求和 trigger_points，再由静态规则分类。分类阶段不调用 LLM、不接收原始材料或抽取阶段的解释。不获取 URL、不执行 PoC、不扫描源码。

环境配置、运行方法和排错统一收录在本文。

## 运行

在本目录打开 PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe agent.py --cve CVE-2024-10762
```

项目使用独立 `.venv`，无需激活即可用上面的解释器路径运行。环境基于本机 Anaconda Python 3.9.13 创建，依赖不安装到 Anaconda 环境中；`.venv` 已加入 `.gitignore`。`requirements.txt` 已统一固定本次全部直接与间接依赖版本。

也可先激活环境，再使用简短命令（仅当前终端生效）：

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python agent.py --input "results/CVE-2024-10762/CVE-2024-10762.json"
# 或按 CVE 选择
python agent.py --cve CVE-2024-10762
# 默认批量处理尚未生成有效结果的输入
python agent.py
# 明确重新生成
python agent.py --cve CVE-2024-10762 --overwrite
```

模型默认 `deepseek-v4.1-flash`，接口 `https://opencode.ai/zen/go/v1/chat/completions`。可用 `--model` 指定其他模型，不自动降级。

按照 OpenCode Go 客户端要求，程序发送自己的 `User-Agent: trigger-pattern-agent/1.0`，并在同一次 CVE 抽取和修正、重试中保持稳定的 `x-opencode-session`。分类不产生 API 请求。

设置 `OPENCODE_GO_API_KEY` 环境变量。程序优先读取进程环境；Windows 下未继承时直接读取 Machine 系统变量。不将密钥保存在源码、输出或日志中。

## 输入和结果

输入要求 `vulnerability.id` 为合法 CVE ID；使用 `description`、`advisories[].content`、`patches[].content`，以及可选的 `source_code[].content`、`api_documentation[].content`。其余背景字段原样提供给模型；兼容 `cwes[].value`、可选的 `effective`。URL 仅用于溯源，内容缺失保留未知。

输入默认位置 `results/<CVE-ID>/<CVE-ID>.json`。外部输入复制到该位置；同 ID 不同内容拒绝覆盖。现有原始输入不改动。

输出：

- `output.json`：严格模板结果，参见 `src/schemas/trigger.schema.json`。
- `extraction.json`：第一阶段抽取结果，不含分类。
- `analysis.md`：静态生成的 JSON 字段映射依据与信息缺口。
- `extraction_analysis.md`：抽取阶段的原文证据、字段来源和响应证据性质；不传给分类阶段。
- `run.json`：最近一次运行状态、模型、输入和提示词哈希、耗时、用量。
- `llm_response.json`：最近一次运行的模型回答和修正记录；不记录隐藏推理或认证头。

默认仅跳过输入哈希匹配且上次运行成功的有效 TP 输出；修改所选目录内的输入后会重新抽取。修改提示词后需要 `--overwrite`。失败保留先前有效的 output/extraction/analysis，run 与 llm_response 记录最新尝试，因此请先检查 run.status。每个文件原子写入，单个 CVE 应串行执行。

`params` 仅为 `{path, query}`，两者保存参数名到值的映射，未知为 null，已知为空为 {}。body 和 headers 单独保存；endpoint 仅包含路径。删除 requires_input_mutation 和参数中的 operation。

`trigger_points` 每项包含 request_id、locations、field、action、before、after。locations 为单个触发点的可能位置，多个位置表示候选；确认多处同时修改则拆成多项。位置完全未知为 []。普通请求参数不加入触发点。请求 ID 必须唯一且触发点指向攻击者请求。

静态规则实现于 src/toolbox/classification.py 的 classify：api+invoke（并且无受害者依赖）→TP1；url/body/header→TP2/TP3/TP4；interaction.victim_request_required=true→TP5。即使 action=unknown，已提取的非 api 触发位置也参与映射。多个位置和多个触发点取并集、去重、排序。空 locations 不映射，矛盾组合拒绝。是否属于触发位置由 agent 判断，代码不重新解释原材料。

抽取规则见 `src/prompts/trigger.md`。response 状态码可能源于代码，不代表已发请求；证据性质在 extraction_analysis.md 中说明。

旧 confirmed/alternatives 对象不符合新 Schema，会重新生成。`run.json` 中 classification_engine=static-v3-location-union、classification_input=extraction_only 标记当前流程。修改提示词或输入后使用 `--overwrite`。

网络错误、429、5xx 最多重试两次；每次连接超时 30 秒、读取超时 240 秒。非法模型 JSON 或一致性错误最多修正一次。认证、模型不存在和长度限制错误不会自动切换模型或截断材料。批量运行有任何失败时退出码为 1。

## 环境检查与排错

Python 环境已在 3.9.13 下验证。换机时重新创建 `.venv`，不要复制旧虚拟环境。

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe agent.py --help
```

- 找不到 requests/jsonschema：使用 `.venv` 中的解释器，并安装 `requirements.txt`。
- PowerShell 无法激活：直接用上述解释器路径运行即可，无需调整执行策略。
- 密钥未找到：配置 `OPENCODE_GO_API_KEY` 环境变量；系统变量已配置时不需要再次输入。程序不自动读取 `.env`。
- 401/403：检查密钥及服务访问权限；429/5xx/超时：自动重试仍失败后再检查网络或服务状态。
- 修改提示词后结果不变：显式添加 `--overwrite`。
- 结果判断：真实模型抽取仍需人工审阅，分类结果不代表已经实际复现漏洞。

## 仓库内容

- `agent.py`：兼容旧命令的入口，实现位于 `src`。
- `src/schemas/trigger.schema.json`：输出结构与字段约束。
- `src/prompts/trigger.md`：运行所需提示词，独立保留。
- `requirements.txt`：统一的固定版本依赖清单。
- `results/`：当前 CVE 输入、抽取、分类结果和分析。

本地虚拟环境、缓存、历史 experiments、旧 trigger pattern 输出目录与原始模型日志不纳入版本管理。`tests` 纳入版本管理。支持 Solution 1 Oracle 设计生成；不执行目标请求。

## 源码与 API 文档补全（v8-source-api-evidence）

输入可在 vulnerability 中添加 source_code（content/path/commit/url）与 api_documentation（content/url/title）数组。抽取联合使用内联材料，URL 仅溯源，不联网获取；输出 Schema 和静态 TP 分类保持不变。分析文件记录字段来源、版本限制、互斥分支以及响应属于代码声明还是文档示例。没有可靠证据的字段继续为 null。

--results-dir 同时指定批量发现输入和保存输出的目录，默认仍为 results。与 --input 合用时，外部输入复制到指定结果目录；同 ID 不同内容仍拒绝覆盖。旧结果不会因提示词更新自动刷新，需显式 --overwrite。

```powershell
.\.venv\Scripts\python.exe agent.py --results-dir "results - v2" --cve CVE-2026-5599 --overwrite
```

### Oracle 请求与观测格式

Oracle id 按输出顺序使用 `o1`、`o2`。`resources` 是资源名到自然语言描述的字典。所有请求统一使用 TP 的 `id/method/handler/endpoint/params/headers/body/response` 加 `actor`，不再使用扁平 `parameters`。`response` 是材料支持的预期响应，不表示实际执行。每条 observation 必须包含 `actor` 和 `target` 字典，确保查询通道未知时仍保留主体和目标绑定；API 主体必须与 observation 主体一致。未知 API/SQL 仍为 null，不编造查询。Schema 和提示词已更新，已有结果可通过 `--stage oracle --overwrite` 重新生成。
