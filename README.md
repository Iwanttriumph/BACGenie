# BACGenie — 越权缺陷动态复现与双容器自动化核验系统

**BACGenie** 基于 OpenCode 双层正交智能体（`bacgenie-planner` + `bacgenie/worker`）、双盲确定性门禁（`harness/gate.py`）、**Harbor 0.22.0** 交付打包器以及后置独立的 **Two-Container Flag Gate + Agent Verifier**，提供从源码级 TP/Oracle 建模到双容器物理隔离终审的单项目闭环流水线：

```text
[Stage 1: Reproduce]       bacgenie_run.sh / experiment/run_batch.py
                           ├── 源码定位 + TP 分类 (01_tp.json) + Oracle 契约生成 (02_oracle_contract.json)
                           ├── 隔离靶场与前置准备 (prep.py / verify.py)
                           └── Clean-Room 盲态客户端 + harness/gate.py 门禁 -> runs/<CVE>/
        │
        ▼
[Stage 2: Harbor Bundle]   experiment/build_harbor_bundle.py
                           └── 标准 Harbor 0.22.0 交付包 -> deliverables/BACGenie/<App>/<CVE>/
        │
        ▼
[Stage 3: Auto Verifier]   verify.py / verifier/
                           └── 双容器物理隔离 Flag 捕获 + 源码对齐 Agent 终审 -> verifier_results/
```

---

## 1. 目录结构

```text
BACGenie/
├── pipeline.py                  # 三阶段统一编排入口（支持 all / post-reproduce / reproduce / bundle / verify）
├── verify.py                    # 后置独立自动化 Verifier 快捷入口
├── bacgenie_run.sh              # 单题动态复现启动脚本（默认模型 yeowl/deepseek-v4.1-flash，支持 BACGENIE_AUTO_VERIFY=1）
├── .opencode/                   # bacgenie-planner 与 bacgenie/worker 智能体配置及三大领域技能
│   ├── agents/
│   │   ├── bacgenie-planner.md  # 主审架构师（统筹 TP/Oracle 契约审定、分信封派单与门禁调用）
│   │   └── bacgenie/worker.md   # 最小知情面执行员（源码契约、靶场准备、盲态客户端三态物理隔离）
│   └── skills/
│       ├── bac-trigger-and-oracle/ # TP1–TP5 识别与 O1/O2/O3 × CRUD Oracle 契约规范
│       ├── bac-state-prep/         # Solution 2 状态准备与正负对照规范
│       └── bac-convincing-report/  # 六段式可信复现证明报告规范
├── harness/                     # 复现阶段内部双盲重放门禁 gate.py 及测试 test_gate.py
├── experiment/                  # 23 题基准配置、批量调度 run_batch.py、交付包构建 build_harbor_bundle.py
├── verifier/                    # 后置独立双容器物理隔离 Flag Gate 沙箱 + 源码只读对齐 Agent 审计器
│   ├── sandbox/                 # 自动分配无冲突子网的双网隔离 Docker 引擎（兼容本地 Docker 与 --ssh 远端执行）
│   ├── agents/                  # 双标准裁决器（标准1：动态效果 Flag；标准2：低权限完整链路、拒绝有权限角色混入）
│   ├── toolbox/                 # 模型客户端与受限于 repo_path 的只读源码检索工具
│   ├── prompts/ & schemas/      # 四阶段 Oracle 抽取提示词与三值裁决 JSON Schema
│   └── reporting/               # True 分层随机抽样、unknown 100% 必审清单与 SUMMARY.md 生成器
└── tests/                       # 自动化 Verifier 与流水线单元测试
```

---

## 2. 后置自动化 Verifier 判定标准

后置 Verifier 对每条复现产物输出三值裁决（`True` / `False` / `unknown`）及四阶段 Oracle 对照表：

1. **标准 1（`criterion_1_flag_proof`）**：在双容器物理隔离网络（客户端容器 `UID=65534`、只读挂载、阻断 `db`/`redis` 直连）且通过 **No-Op 空跑探针**（排除前置预污染）的前提下，成功捕获绑定当轮随机信标的 `FLAG{...}`。
2. **标准 2（`criterion_2_workflow_integrity`）**：全链路凭据隔离、正负对照、独立权威回读闭环，且对照官方补丁与源码权限矩阵确认调用方确属无权主体（`caller_is_unprivileged=true`）。

| 裁决结果 | 人工复核策略 | 含义 |
| :--- | :--- | :--- |
| **`True`** | `sample_audit`（按应用×Oracle×效果类型分层随机抽样核验） | 标准 1 与标准 2 同时通过 |
| **`False`** | `rejected`（直接剔除并定位缺陷） | 未捕获有效动态标识、No-Op 空跑误过、凭据泄漏或调用方本就具备合法权限 |
| **`unknown`** | `mandatory_manual_audit`（100% 逐条人工核验） | 缺少构建产物、容器异常，或动态通过但标准 2 存在无法自动消解的边界歧义 |

---

## 3. 快速使用

### 3.1 运行全套单元测试

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s harness -p "test_*.py" -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

### 3.2 统一流水线调用（`pipeline.py`）

```powershell
# 1. 对远端或本地已生成的交付包运行后置双容器 + Agent 核验
.\.venv\Scripts\python.exe pipeline.py --stage verify --ssh ddk@10.176.46.12 --concurrency 3
.\.venv\Scripts\python.exe pipeline.py --stage verify --ssh ddk@10.176.46.12 --cve CVE-2024-11300 CVE-2024-10273

# 2. 在 Linux Docker 宿主机上一键串联：动态复现 -> 构建 Harbor 交付包 -> 双容器独立核验
python3 pipeline.py --stage all --cve CVE-2024-11300

# 3. 对已有 runs/<CVE> 一键打包并执行后置独立核验
python3 pipeline.py --stage post-reproduce --cve CVE-2024-11300
```

### 3.3 单题或批量复现直接挂载后置核验

```bash
# 单题启动（默认模型已设为 yeowl/deepseek-v4.1-flash；设置 BACGENIE_AUTO_VERIFY=1 自动串联后置核验）
BACGENIE_AUTO_VERIFY=1 ./bacgenie_run.sh CVE-2024-11300

# 批量启动（跑完自动构建交付包并输出 verifier_results/SUMMARY.md）
python3 experiment/run_batch.py --round 1 --jobs 4 --verify
```
