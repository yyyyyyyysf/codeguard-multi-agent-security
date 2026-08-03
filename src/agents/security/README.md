# Security Audit Agent

## 定位

关键路径·执行层。零 LLM，纯规则引擎。

## 职责

- **CVE 依赖扫描**：三级缓存（Redis → SQLite → OSV API），覆盖直接依赖 + 传递依赖
- **代码规则扫描**：Semgrep 静态分析，检测硬编码密钥、SQL 注入、不安全反序列化等
- **阻断分级**：直接依赖高危 CVE 默认阻断，代码硬编码密钥默认阻断，低置信度不阻断

## 输入

| 字段 | 类型 | 说明 |
|------|------|------|
| `code_metadata` | dict | 预处理输出的 CodeMetadata（依赖清单 + 文件列表 + 语言） |
| `scan_scope` | str | `"full"` 或 `"diff"` |
| `scan_config` | dict | 可选，覆盖默认扫描配置 |

## 输出

`SecurityReport`（Pydantic 模型），包含：
- `vulnerabilities`: CVE 漏洞列表（cve_id / severity / cvss_score / blocking / evidence_source）
- `code_issues`: 代码问题列表（rule_id / file_path / line_number / confidence / blocking）
- `degraded`: 是否触发降级
- `degraded_reasons`: 降级原因列表（禁止静默降级）

## 安全红线

1. **禁止调用任何 LLM**：本 Agent 的任何代码路径不得引入大模型调用
2. **证据链溯源**：每个 vulnerability 必须绑定 `evidence_source`（OSV/GitHub Advisory/local_cache）
3. **阻断优先**：高危漏洞默认 blocking=true，外部分依赖故障时不自动放行

## 使用方式

```python
from src.agents.security.agent import SecurityAuditAgent

agent = SecurityAuditAgent(redis_client=redis, cve_db_path="data/cve.db")
result = await agent.execute(
    code_metadata=metadata,
    scan_scope="full",
    scan_config={"block_severity": "high"},
)
# result["data"] -> SecurityReport dict
```

## 配置项

| 配置 | 默认值 | 说明 |
|------|--------|------|
| `enable_cve_scan` | `true` | 是否执行 CVE 扫描 |
| `enable_code_scan` | `true` | 是否执行 Semgrep 扫描 |
| `block_severity` | `"high"` | 阻断阈值：`"high"` / `"critical"` |
| `file_blacklist` | `["test/", "tests/", "docs/"]` | 代码扫描排除路径 |

## 降级策略

| 故障场景 | 降级行为 |
|----------|----------|
| OSV API 不可用 | 使用本地 SQLite 缓存继续扫描 |
| Semgrep CLI 不可用/超时 | 跳过代码规则扫描，CVE 扫描不受影响 |
| CVE 扫描完全失败 | `degraded_run()` 回退：仅查本地 SQLite |
| run() 抛出未捕获异常 | `degraded_run()` 生成 best-effort 报告 |

## 测试

```bash
pytest tests/unit/test_agents/test_security/ -v
# 34 tests, 89% coverage
```
