# Migration Assessment Agent

## 定位

辅助路径·执行层。事件驱动，与安全主链路物理隔离，输出仅作开发者参考。

## 职责

- **AST 规则匹配**（确定性，前置）：regex 匹配已知 Breaking Changes 模式到变更文件
- **LLM 辅助分析**（可选，后置）：将 Breaking Changes 精准映射到具体代码行
- **风险评估**：综合影响范围和版本幅度，输出 high/medium/low
- **工作量预估**：基于受影响文件数估算人天

## LLM 使用边界

```
LLM 可以做：
  - 将 KNOWN Breaking Changes 映射到具体代码行
  - 生成逐文件的修复建议

LLM 禁止做：
  - 发现新的 Breaking Changes（那是 ChangelogStore 的职责）
  - 参与安全裁决（此 Agent 输出不进入安全链路）
```

## 输入

| 字段 | 类型 | 说明 |
|------|------|------|
| `code_metadata` | dict | 含 changed_files（文件内容/语言） |
| `target_version` | dict | `{framework, from_version, to_version}` |
| `scan_id` | str | 关联扫描 ID |

## 输出

`MigrationReport`（Pydantic 模型），包含：
- `breaking_changes`: 每个 Breaking Change 的受影响文件 + 修复建议
- `risk_level`: `high` / `medium` / `low`
- `effort_estimate`: `{affected_file_count, estimated_person_days, confidence}`
- `degraded`: LLM 不可用时标记 true（AST 结果仍可用）

## 支持的框架

| 框架 | MVP 覆盖 |
|------|----------|
| FastAPI | 0.100.0 -> 0.110.0（3 条 Breaking Changes） |
| Django | v0.2 计划 |
| Flask | v0.2 计划 |

## 使用方式

```python
from src.agents.migration.agent import MigrationAssessmentAgent

agent = MigrationAssessmentAgent(llm_api_key="sk-xxx")
result = await agent.execute(
    code_metadata=metadata,
    target_version={"framework": "fastapi", "from_version": "0.100.0", "to_version": "0.110.0"},
)
# result["data"] -> MigrationReport dict
```

## 降级策略

| 故障场景 | 降级行为 |
|----------|----------|
| LLM API 超时/不可用 | 降级为纯 AST 匹配，confidence=low |
| 无目标版本 | 标记 degraded，跳过分析 |
| AST 匹配无结果 | 正常返回空列表，risk=low |

## 测试

```bash
pytest tests/unit/test_agents/test_migration/ -v
# 40 tests, 88% coverage
```
