你上一轮输出的 JSON 未通过结构或一致性校验：
错误信息：{{error}}

请严格按以下约束修正并仅输出单个完整 JSON 对象：
1. `verdict` 只能为 `"True"`、`"False"` 或 `"unknown"`。
2. 一致性约束：
   - 当 `verdict == "True"` 时，`human_review_policy` 必须为 `"sample_audit"`，且 `criterion_1_flag_proof.status == "PASS"`、`criterion_2_workflow_integrity.status == "PASS"`、`caller_is_unprivileged == true`。
   - 当 `verdict == "False"` 时，`human_review_policy` 必须为 `"rejected"`，且至少一个标准为 `"FAIL"`。
   - 当 `verdict == "unknown"` 时，`human_review_policy` 必须为 `"mandatory_manual_audit"`，且不能有任何标准为 `"FAIL"`（若存在实锤 `"FAIL"` 应判为 `"False"`）。
3. `oracle_table` 必须恰好包含 4 个阶段条目（数据准备、前置检查、目标触发、后置验证）。
