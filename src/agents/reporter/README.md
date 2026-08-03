# Report Aggregation Agent

## 定位

输出层·呈现层。**4/4 最后一个 Agent。** 不承载任何业务判断。

## 职责

- **分级输出**：安全结果优先渲染 → PR 评论立即输出；迁移结果异步追加
- **模板渲染**：Jinja2 生成 Markdown（PR 评论）+ HTML（完整报告）
- **信息去重排序**：阻断项优先、严重度高优先

## 输入

| 字段 | 来源 | 说明 |
|------|------|------|
| `security_data.security` | 安全审计 Agent | SecurityReport |
| `security_data.conflict` | 冲突消解 Agent | FinalSecurityDecision |
| `migration_data` | 迁移评估 Agent | MigrationReport |
| `code_metadata` | 预处理模块 | 仓库/提交/扫描范围元信息 |

## 输出

`AggregatedReport`（Pydantic 模型），包含：
- `summary`: ReportSummary（blocking_count / warning_count / pass_count）
- `security`: 上游安全结果（未经修改）
- `migration`: 上游迁移结果（未经修改）
- `pr_comment_markdown`: 渲染后的 PR 评论
- `full_report_url`: 完整报告链接

## 红线

1. **禁止修改任何上游业务结论**——阻断状态、风险等级、严重度 100% 沿用上游
2. **禁止新增任何风险判定规则**——仅做信息去重、排序、格式化
3. **安全结果就绪必须优先输出**——不得等待迁移评估结果

## PR 评论模板结构

```
## CodeGuard 安全分析报告
> 扫描范围 · 文件数 · 耗时

### 阻断项 (N)
| 严重度 | 问题 | 位置 | 修复方案 |

### 建议项
#### 安全建议
#### 迁移建议

### 通过项
```

## 使用方式

```python
from src.agents.reporter.agent import ReportAggregationAgent

agent = ReportAggregationAgent()
result = await agent.execute(
    security_data={"security": security_report, "conflict": conflict_decision},
    migration_data=migration_report,
    repo_url="https://github.com/user/repo",
    code_metadata=metadata,
)
# result["data"]["pr_comment_markdown"] -> PR comment string
# result["data"]["summary"] -> ReportSummary with counts
```

## 测试

```bash
pytest tests/unit/test_agents/test_reporter/ -v
# 18 tests, 84% coverage
```
