# CodeGuard 自举验证（Self-Verification）

> 用 CodeGuard 扫描 CodeGuard 自身，存档真实扫描结果作为可复现证据。
> 对应 PROJECT_RULES §18.3「用 CodeGuard 保障 CodeGuard 开发」的自举闭环。

## 最新结果（2026-08-25）

| 指标 | 值 |
|---|---|
| 扫描对象 | CodeGuard 自身（156 个文件，src/ + 配置） |
| 代码规则检查 | 13 项规则全部通过，**零误报、零阻断** |
| CVE 扫描 | 25 个依赖（扫描依赖 OSV API，离线环境下 vulnerabilities 为空） |
| 安全扫描耗时 | ~29 s（本地规则 + 无缓存回源） |
| 结论 | `overall_blocking=false`，可合并 |

## 如何复现

```bash
cd C:\Users\86186\codeguard
python -m src.cli.main analyze . --no-migration --output docs/verification/self-scan-2026-08-25.json
```

完整 JSON 结果见同目录 `self-scan-2026-08-25.json`（含每条命中详情、审计记录、PR 评论）。

## 规则精度验证记录

- **2026-08-25 初版扫描**：自定义规则 `config/semgrep/codeguard-rules.yml` 命中 13 条 `python-sql-string-concat`，**全部为误报**——根因是规则中 `$CONN.execute($QUERY)` 模式过宽，把参数化安全查询（如 `audit_log.py` 的 `conn.execute("SELECT ...")`）也匹配了。
- **修复**：
  1. 规则收紧：删除过宽的 `$CONN.execute($QUERY)`，仅保留明确字符串拼接模式（`"..." + $VAR`、`f"...{$VAR}"`）
  2. `code_scanner._parse_semgrep_output`：新增 Semgrep 严重度映射 `ERROR→high / WARNING→medium / INFO→low`（此前 `error` 永远不触发阻断）
- **复扫**：误报清零，且对靶点仓库的 2 条真实 SQL 拼接仍可命中（查 `git log` 中 `config/semgrep` 历史与实测记录）——证明规则"能抓真、不误伤"。

## 与其他验证的关系

| 证据 | 作用 |
|---|---|
| 268 个自动化测试（`pytest tests/`） | 功能正确性 |
| 本自举扫描存档 | 安全规则有效性（真实仓库零误报） |
| 靶点仓库实测（命中 SQL 注入并阻断） | 端到端链路可用性 |
