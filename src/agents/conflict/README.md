# Conflict Resolution Agent

## 定位

关键路径·决策层。零 LLM，纯规则引擎 + 人在回路。

## 职责

- **自动裁决**：5 条核心规则匹配豁免规则库，自动产出 block/waive/defer 决策
- **人在回路**：规则无法覆盖的争议项通过 LangGraph Checkpoint 暂停，等待人工输入
- **审计日志**：所有裁决操作写入 append-only 审计日志（链式哈希）

## 裁决规则（优先级从高到低）

| # | 规则 | 条件 | 裁决 |
|---|------|------|------|
| 1 | CVE 白名单 | CVE ID 在豁免规则 `cve_whitelist` 中 | waive |
| 2 | 路径白名单 | 文件路径匹配 `path_whitelist` 规则 | waive |
| 3 | 升级自动修复 | 框架升级 PR + 目标版本 >= 修复版本 | waive |
| 4 | 高危阻断 | CVSS >= 7.0 + 非白名单 | block |
| 5 | 低置信度放行 | confidence=low | waive |
| D | 默认规则 | 直接依赖 → block，传递依赖 → waive | block/waive |

## 安全红线

1. **禁止调用任何 LLM**：裁决逻辑全确定性，来自规则匹配或人工输入
2. **Critical 禁止豁免**：CVSS >= 9.0，仅 CVE 白名单可豁免，人工不可豁免
3. **fail-safe 超时**：人在回路超时默认 block
4. **审计不可篡改**：全部操作写入 append-only 审计日志

## 输入

| 字段 | 类型 | 说明 |
|------|------|------|
| `security_report` | dict | SecurityAuditAgent 输出的 SecurityReport |
| `code_metadata` | dict | 可选，用于检测框架升级场景 |
| `config` | dict | 可选 ResolutionConfig 覆盖 |

## 输出

`FinalSecurityDecision`（Pydantic 模型），包含：
- `overall_blocking`: 是否有任何 finding 被阻断
- `decisions`: 每个 finding 的 SecurityVerdict（verdict/reason/rule_id/operator）
- `audit_trail`: AuditTrail（append-only 审计记录）
- `human_intervention_required`: 是否需要人工介入

## 人在回路流程

```
SecurityReport → AutoResolver
    ├── 规则匹配 → 自动裁决 → SecurityVerdict
    └── 规则未覆盖 → LangGraph Checkpoint 暂停
         ├── 人工输入 → 恢复 → SecurityVerdict
         └── 超时(24h) → fail-safe: 全部 block
```

## 使用方式

```python
from src.agents.conflict.agent import ConflictResolutionAgent
from src.storage.rule_store import RuleStore
from src.storage.audit_log import AuditLogger

agent = ConflictResolutionAgent(
    rule_store=RuleStore(),
    audit_logger=AuditLogger(),
    human_loop_timeout_hours=24,
)
result = await agent.execute(
    security_report=security_report_dict,
    code_metadata={"target_version": {"framework": "fastapi", "to_version": "0.110.0"}},
    config={"critical_cannot_waive": True},
)
# result["data"] -> FinalSecurityDecision dict
```

## 配置项

| 配置 | 默认值 | 说明 |
|------|--------|------|
| `human_loop_timeout_hours` | 24 | 人工裁决超时（小时） |
| `critical_cannot_waive` | True | Critical 级漏洞是否禁止人工豁免 |
| `auto_waive_low_confidence` | True | 低置信度 code_issue 是否自动 waive |
| `fail_safe_blocking` | True | 超时后是否默认 block |

## 测试

```bash
pytest tests/unit/test_agents/test_conflict/ -v
# 49 tests, 87% coverage
```
