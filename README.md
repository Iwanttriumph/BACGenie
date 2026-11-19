# Trigger Pattern Agent

当前输出使用单一标签数组，例如 `"classification": ["TP2", "TP3"]`。不再输出 confirmed/alternatives。标签表示涉及或可能涉及的类型，不表示各标签均已独立证实。每个触发点的 locations 仍保留位置不确定性；不同实际触发点分开记录。

当前流程 v6-location-union / static-v3-location-union：agent 负责分析所有可能的触发位置，静态代码只求标签并集。参数修改位置未知时不能默认为 api；若 URL/body 无法区分则保留两者，更广的不确定性保留 url/body/header。完全没有触发动作线索时允许空数组。普通参数不等于触发参数。

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

输入要求 `vulnerability.id` 为合法 CVE ID；使用 `description`、`advisories[].content`、`patches[].content`。其余背景字段原样提供给模型；兼容 `cwes[].value`、可选的 `effective`。URL 仅用于溯源，内容缺失保留未知。

输入默认位置 `results/<CVE-ID>/<CVE-ID>.json`。外部输入复制到该位置；同 ID 不同内容拒绝覆盖。现有原始输入不改动。

输出：

- `output.json`：严格模板结果，参见 `output.schema.json`。
- `extraction.json`：第一阶段抽取结果，不含分类。
- `analysis.md`：静态生成的 JSON 字段映射依据与信息缺口。
- `extraction_analysis.md`：抽取阶段的原文证据、字段来源和响应证据性质；不传给分类阶段。
- `run.json`：最近一次运行状态、模型、输入和提示词哈希、耗时、用量。
- `llm_response.json`：最近一次运行的模型回答和修正记录；不记录隐藏推理或认证头。

默认跳过已有有效输出。修改输入或提示词后需要 `--overwrite`。失败保留先前有效的 output/extraction/analysis，run 与 llm_response 记录最新尝试，因此请先检查 run.status。每个文件原子写入，单个 CVE 应串行执行。

`params` 仅为 `{path, query}`，两者保存参数名到值的映射，未知为 null，已知为空为 {}。body 和 headers 单独保存；endpoint 仅包含路径。删除 requires_input_mutation 和参数中的 operation。

`trigger_points` 每项包含 request_id、locations、field、action、before、after。locations 为单个触发点的可能位置，多个位置表示候选；确认多处同时修改则拆成多项。位置完全未知为 []。普通请求参数不加入触发点。请求 ID 必须唯一且触发点指向攻击者请求。

静态规则实现于 agent.py 的 classify：api+invoke（并且无受害者依赖）→TP1；url/body/header→TP2/TP3/TP4；interaction.victim_request_required=true→TP5。即使 action=unknown，已提取的非 api 触发位置也参与映射。多个位置和多个触发点取并集、去重、排序。空 locations 不映射，矛盾组合拒绝。是否属于触发位置由 agent 判断，代码不重新解释原材料。

抽取规则见 `prompts/rules.md`。response 状态码可能源于代码，不代表已发请求；证据性质在 extraction_analysis.md 中说明。

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

- `agent.py`：抽取、校验、静态分类和文件保存。
- `output.schema.json`：输出结构与字段约束。
- `prompts/rules.md`：运行所需提示词，独立保留。
- `requirements.txt`：统一的固定版本依赖清单。
- `results/`：当前 CVE 输入、抽取、分类结果和分析。

本地虚拟环境、缓存、历史 experiments、测试脚本、旧 trigger pattern 输出目录与原始模型日志不纳入版本管理。当前阶段尚未实现 Oracle 生成与漏洞执行。
