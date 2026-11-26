# Trigger Pattern Agent

本项目从 CVE 公告、补丁和本地已解压源码中抽取一条触发流程，按固定优先级给出单一 trigger pattern，并基于同一份证据设计可人工审阅的 Oracle。项目不下载源码、不访问远端 URL、不执行目标代码或 PoC。

## 实现结构

实现位于 `src`：

- `main.py`：命令行编排，支持单文件、按 CVE 和平面目录批量输入。
- `agents/trigger_extractor.py`：触发信息抽取、源码检索、静态分类、缓存与结果保存。
- `agents/oracle_designer.py`：复用 TP 证据并继续检索源码，先选 O1/O2/O3，再实例化单个 Oracle。
- `toolbox/source.py`：输入适配、本地源码索引、只读 list/search/read 操作和检索预算。
- `toolbox/classification.py`：固定优先级静态分类。
- `toolbox/llm_client.py`：模型客户端、JSON 修复与重试。
- `prompts/`、`schemas/`：提示词与输出 Schema。

根目录 `agent.py` 是入口。

## 运行

```powershell
# 单文件
.\.venv\Scripts\python.exe agent.py --stage all --input "project/bench_input/CVE-2024-10273.json" --results-dir "results - bench"

# 批量读取平面目录下的 CVE-*.json
.\.venv\Scripts\python.exe agent.py --stage all --input-dir "project/bench_input" --results-dir "results - bench"

# 读取 results 目录中已保存的新版输入
.\.venv\Scripts\python.exe agent.py --stage tp --cve CVE-2024-10273 --results-dir "results - bench"

# 覆盖已有结果
.\.venv\Scripts\python.exe agent.py --stage all --input-dir "project/bench_input" --results-dir "results - bench" --overwrite
```

`--stage` 可取 `tp`、`oracle`、`all`，默认 `tp`。`oracle` 读取同目录已有 TP 输出；`all` 先 TP 后 Oracle，TP 失败时不会继续 Oracle。未指定 `--input`、`--input-dir` 或 `--cve` 时，默认扫描 `--results-dir` 下 `CVE-*/*.json` 的已保存输入。批量结束分别统计 `success`、`ready`、`incomplete`、`failed`、`skipped`；仅 `failed` 返回非零退出码。

模型默认 `deepseek-v4.1-flash`，接口 `https://opencode.ai/zen/go/v1/chat/completions`。可用 `--model` 指定其他模型，不自动降级。设置 `OPENCODE_GO_API_KEY` 环境变量；Windows 未继承时程序会读取 Machine 系统变量。密钥不写入源码、输出或日志。

## 输入

输入文件名必须是 `CVE-xxxx-xxxx.json`，CVE ID 从文件名获取。可选顶层 `cve_id` 必须与文件名一致，否则报错。

只接受新版顶层结构：`description`、`cwes`、`patch_commits`、`sec_adv`、`sw_version`、`dir_tree`、`repo_path`。工具内部将其规范化为 `vulnerability.description/cwes/patches/advisories/sw_version/dir_tree` 供模型使用，原始输入保持不变。旧的 `vulnerability` 嵌套结构不再支持，会明确报错。

`repo_path` 指向已解压的本地源码目录。绝对路径直接使用；相对路径以输入文件所在目录为基准，缺失时直接报错，不再尝试其他目录。不会下载或解压。`dir_tree` 仅用于导航，实际文件系统为准。输入复制到结果目录后，如果仍需单独用 `--cve` 运行，建议使用绝对 `repo_path`。

源码访问只读且限制在 `repo_path` 内。索引会忽略符号链接、`.git`、`.venv`、`node_modules`、`__pycache__`、`dist`、`build`、二进制文件以及大于 2 MB 的文件。

## 源码检索

模型采用 JSON 动作循环按需检索：

- `{"op":"list","path":"相对前缀","offset":0}`：列出某目录的直接子项。
- `{"op":"search","query":"字面关键词","path":"可选前缀","offset":0}`：不区分大小写的字面搜索。
- `{"op":"read","path":"相对路径","start":1,"end":200}`：分段读取，每次最多 200 行。

每阶段最多 20 轮，每轮最多 5 个操作，返回给模型的源码累计最多 120,000 字符。Oracle 的模板选择与实例化共享同一检索预算。达到限制后必须用已有证据完成分析，并在分析文件中记录缺口。读取记录包含相对路径、行号、内容哈希；`source_evidence.json` 保存 TP 阶段实际检索动作和返回结果，`oracle_source_evidence.json` 保存 Oracle 复用的 TP 读取和 Oracle 新增读取。

## 输出

每个 CVE 在 `--results-dir` 下生成：

- `output.json`：最终结果，含唯一 `classification`。结构见 `src/schemas/trigger.schema.json`。
- `extraction.json`：第一阶段抽取结果，不含分类。
- `extraction_analysis.md`：抽取阶段原文来源、源码证据、响应证据性质和缺口；不传给分类阶段。
- `analysis.md`：静态分类的候选标签、被覆盖标签和保留原因。
- `source_evidence.json`：TP 源码检索审计记录；无源码时为空数组。
- `run.json`：最近一次 TP 运行状态、模型、依赖哈希、源码指纹、耗时、用量。
- `llm_response.json`：最近一次 TP 模型回答和修复记录。
- `oracle_selection.json`：模板选择结果，含 O1/O2/O3 候选、证据、缺口、淘汰原因和策略版本。
- `oracle_selection_analysis.md`：模板选择说明。
- `oracle.json`：最终 Oracle 设计；选定模板时 `oracles` 恰好一项，无法选择时为空数组。
- `oracle_analysis.md`：选定模板后的实例化说明、证据和缺口；未生成 Oracle 时为说明性文本。
- `oracle_source_evidence.json`：TP、选择阶段和实例化阶段的源码读取记录。
- `oracle_run.json`：最近一次 Oracle 运行状态（`ready`/`incomplete`/`failed`）、阶段、依赖哈希和缺口。
- `oracle_llm_response.json`：最近一次 Oracle 两阶段模型回答和修正记录。
- `oracle.previous.json` / `oracle.previous.analysis.md`：被覆盖的上一版有效 Oracle 及分析（仅在存在时生成），用于失败或待补全时保留旧结果。

`params` 仅为 `{path, query}`，未知为 `null`，已知为空为 `{}`。body 和 headers 单独保存，endpoint 仅含路径。`trigger_points` 每项包含 `request_id`、`locations`、`field`、`action`、`before`、`after`；`locations` 是同一触发点的候选位置，多个位置表示不确定，不是确认多处同时修改。

## 静态分类

分类只依据抽取 JSON，不调用模型、不读取原始材料。固定优先级：

**TP5 > TP4(header) > TP3(body) > TP2(URL) > TP1**

先按 `locations` 和 `interaction.victim_request_required` 生成候选标签，再只保留优先级最高的一项。`classification` 保持数组格式，但最多一个标签；无候选时仍为空数组。分析文件记录每个触发点的候选、保留项和被覆盖标签。

`api/invoke` 只有在交互依赖为 false 时才可能作为独立直接调用；依赖为 true 时 TP5 覆盖 TP1，依赖未知时不生成 TP1 候选。`locations` 为空不映射类别。分类结果只表示最高优先级候选，不代表该位置已被证实；候选位置不确定性完整保留在 `trigger_points.locations` 中，Oracle 仍使用完整抽取信息。

## 缓存与失败处理

TP 缓存核对输入哈希、源码目录内可检索文件的路径与内容指纹、提示词哈希、Schema 哈希，以及 pipeline/classification/retrieval 版本。源码新增、删除或修改，提示词或 Schema 变化，都会触发重新抽取。

Oracle 分为两个模型阶段：`oracle_select` 选择唯一模板，`oracle_instantiate` 只按所选模板生成一个 Oracle。缓存额外核对模板选择策略版本、选择结果哈希、两阶段提示词与 Schema；若选择结果仍有效但实例化失败，重跑会复用选择阶段，只重试实例化。单独运行 Oracle 时，若 TP 对应源码、输入或提示词已变化，程序要求先重跑 TP；`all` 会按顺序重建。

`oracle_run.json` 的 `status`：

- `ready`：结构和必需证据齐备，不代表已复现漏洞。
- `incomplete`：模板无法唯一确定，或存在权限依据、观测通道、未决条件等明确缺口；`oracle.json` 可为空。
- `failed`：模型调用、JSON 或结构校验失败；保留上次有效的 `oracle.json`。

模型输出预算：TP 12,000 tokens，Oracle 模板选择 12,000 tokens、实例化 24,000 tokens；截断输出拒绝保存。网络错误、429、5xx 最多重试两次；TP 非法 JSON 最多修正一次，Oracle 两阶段最多各修正两次，并返回具体 JSON 路径和约束。原子写入每个文件，最终 `output.json`/`oracle.json` 最后提交；失败时保留先前有效结果。每个 CVE 应串行执行。

## 测试

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

测试使用模拟模型，覆盖新版输入、旧嵌套输入拒绝、文件名 ID 冲突、相对/绝对 `repo_path`、目录不存在、路径越界、检索分页与预算、源码变化导致缓存失效、失败保留结果，以及 TP1+TP5、header+URL、body+URL、header+body、全部类别、空候选和候选位置不确定等分类场景。Oracle 测试覆盖 O1/O2/O3 代表性设计、单选约束、Subject–Access–Object 绑定、O2 beneficiary 与获取/使用分离、O3 隔离与调度、`ready`/`incomplete`/`failed`、选择复用、缓存失效、10274/10275 定向修正和观测/权限缺口。默认不执行漏洞请求或实际 PoC。

## 环境与排错

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe agent.py --help
```

- 找不到 requests/jsonschema：使用 `.venv` 中的解释器，并安装 `requirements.txt`。
- PowerShell 无法激活：直接使用上述解释器路径，无需调整执行策略。
- 密钥未找到：配置 `OPENCODE_GO_API_KEY`；程序不自动读取 `.env`。
- 401/403：检查密钥和服务访问权限；429/5xx/超时：自动重试仍失败后再检查网络或服务状态。
- 修改提示词后结果不变：显式添加 `--overwrite`。
- 源码路径不存在：检查 `repo_path` 是绝对路径，或相对于输入 JSON 所在目录是否存在。
- 结果判断：真实模型抽取和 Oracle 设计仍需人工审阅，不代表已经复现漏洞。

## Oracle 请求与观测格式

Oracle 只生成一个，id 固定为 `o1`。`resources` 是资源名到自然语言描述的字典。所有请求统一使用 TP 的 `id/method/handler/endpoint/params/headers/body/response` 加 `actor`，不再使用扁平 `parameters`。`response` 是材料支持的预期响应，不表示实际执行。

模板的 `access_checks` 每项显式绑定 Subject–Access–Object：

- `subject`：引用 `subjects` 中的主体。
- `phase`：`baseline`、`acquisition`、`use`、`attack`、`effect` 或 `operation`。
- `access`：业务动作、HTTP 方法、请求 id 和受限字段。
- `object`：资源、唯一标识、归属、作用域和前置状态。
- `expected_decision` 与 `policy_basis`：应允许/拒绝及权限依据，未知为 null。

O2 的 `subjects` 必须包含 `beneficiary`，并分别有 `acquisition` 和 `use` access check；O3 必须包含攻击者/受害者主体、受害者请求、共享状态和 `schedule`，并区分攻击者真实身份与被污染采用的受害者身份。

每条 observation 必须包含 `access_check`、`actor` 和 `target`，确保查询通道未知时仍保留主体、动作和目标绑定；API 主体必须与 observation 主体一致。未知 API/SQL 仍为 null，不编造查询。`verifier.unresolved_conditions` 记录无法判定条件。已有结果可通过 `--stage oracle --overwrite` 重新生成。
