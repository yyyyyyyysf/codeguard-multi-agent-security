# CodeGuard 演示指南（Demo Guide）

> 面向演示 / 自查的一页纸：怎么跑、能看到什么、常见坑、怎么讲。
> 关联：`docs/verification/self-scan-2026-08-25.json`（自举扫描存档）、`../verification/README.md`。

## 一、演示素材

| 素材 | 位置 | 用途 |
|---|---|---|
| 含漏洞演示仓库 | `C:\Users\86186\codeguard_demo`（项目外） | 5 个真实漏洞：3 处 SQL 拼接、硬编码密钥、非恒定时间 HMAC 比较 |
| 一键演示脚本 | `C:\Users\86186\codeguard_demo\run-demo.bat` | **双击即可**，跑完窗口保持（pause） |
| 自举扫描存档 | `docs/verification/self-scan-2026-08-25.json` | 用 CodeGuard 扫 CodeGuard：156 文件零误报 |

## 二、跑法

### 方式 A：双击（推荐，不需要会命令行）

双击 `C:\Users\86186\codeguard_demo\run-demo.bat`，约 10 秒出结果。

### 方式 B：终端命令

```bash
cd C:\Users\86186\codeguard
C:\Users\86186\.workbuddy\binaries\python\envs\default\Scripts\python.exe -m src.cli.main analyze C:\Users\86186\codeguard_demo --no-migration
```

> `--no-migration` 跳过 AI 迁移评估（无需 API key）。要看 AI 辅助迁移评估：去掉该参数并配置 `.env` 的 `LLM_API_KEY`、`LLM_BASE_URL`。

## 三、CLI 完整参数（按需选用）

命令模板：

```bash
python -m src.cli.main analyze <仓库路径> [参数]
```

| 参数 | 作用 | 示例 |
|---|---|---|
| `<仓库路径>` | 必填，本地 git 仓库路径（必须有 `.git`） | `analyze C:\my-project` |
| `--no-migration` | 跳过 AI 迁移评估（推荐，快且无需 LLM key） | `analyze . --no-migration` |
| `--target <f:from:to>` | 启用迁移评估，格式 `框架:旧版本:新版本` | `--target fastapi:0.100.0:0.110.0` |
| `--json` | 终端输出原始 JSON（默认输出 Markdown 摘要） | `--json` |
| `--output <路径>` | 把完整报告另存为 JSON 文件 | `--output D:\report.json` |
| `--scan-type <full/diff>` | 全量扫描 / 仅差异扫描 | 默认 `full` |
| `--branch <分支>` | 指定扫描分支 | 默认 `main` |
| `--block-severity <high/critical>` | 阻断阈值 | 默认 `high` |
| `--no-migration` 外可选组合 | 例：存档 + 跳过迁移 | `--no-migration --json --output r.json` |

典型用法：

```bash
# 日常快速扫（不调 LLM、不依赖网络 key）
python -m src.cli.main analyze C:\my-project --no-migration

# 扫 + 存完整 JSON 报告
python -m src.cli.main analyze C:\my-project --no-migration --output C:\my-project\scan.json

# 含 AI 迁移评估（需配置 LLM_API_KEY）
python -m src.cli.main analyze C:\my-project --target fastapi:0.100.0:0.110.0
```

## 四、预期输出

```
Blocking:  2 / Warnings: 1 / Passed: 1
MERGE BLOCKED — fix the issues above before merging.
```

- 阻断项 2 条：`config.semgrep.python-sql-string-concat`（Critical，`main.py:L43`）
- 建议项 1 条：`python-insecure-hmac-comparison`（medium，复核不阻断）
- 扫描降级标识：无（`degraded=False`）

## 五、完整报告在哪

**CLI 模式现在会自动落盘**（2026-08-26 起）：

```
%TEMP%\codeguard_reports\<task_id>\
├── report.json      # 完整机器可读报告（每条命中详情）
└── pr_comment.md    # PR 评论 Markdown（就是终端里那段表格）
```

终端里也会打印 `Report persisted to: <路径>`。task_id 每次不同，按时间排最新的就是刚跑的。

> 历史背景：CLI 曾不落盘（reporter 的 `_report_store` 默认 None），2026-08-26 已加自动落盘并与 API 模式共用 `LocalFileReportStorage`；同时修复 Windows 下 `/tmp/` 路径被解析成 `C:\tmp\` 的问题（现映射到 `%TEMP%`）。

另外，报告里的 `/api/v1/tasks/<id>/report?format=html` 是 **API 模式**的端点（需启动服务，见第七节）。

## 六、怎么读报告（三步）

**第一步：先看 `degraded`**——`true` 说明本次扫描降级（外部依赖故障），结论不完整，先修环境重跑，不要继续解读。

**第二步：看三分类**（`pr_comment.md` 最直观）：

| 分类 | 含义 | 行动 |
|---|---|---|
| 阻断项 (Blocking) | 高危问题，裁决为必须修复 | **必须处理**，否则合并被阻 |
| 建议项 (Warnings) | 中危/低置信，转人工复核 | 人工判断是否处理 |
| 通过项 (Passed) | 规则检查通过 | 无动作 |

**第三步：看命中细节**（`report.json` 里 `security.security_report.code_issues[]`，每条）：

| 字段 | 含义 |
|---|---|
| `rule_id` | 命中哪条规则（`config.semgrep.*` = 本地自定义规则） |
| `severity` | 严重度（high/critical = 阻断级） |
| `confidence` | 置信度（high = 确定性模式匹配） |
| `file_path` + `line_number` | 命中位置（文件 + 行号，可直接打开核对） |
| `code_snippet` | 命中的真实代码行（证据链核心，从源文件读取） |
| `message` | 问题描述 + 修复建议 |
| `blocking` | 是否阻断（true = 合并会被阻） |

示例（`report.json` 单条）：

```json
{
  "rule_id": "config.semgrep.python-sql-string-concat",
  "severity": "high",
  "confidence": "high",
  "file_path": "C:\\my-project\\main.py",
  "line_number": 43,
  "code_snippet": "query = \"SELECT * FROM users WHERE name = '\" + q + \"'\"",
  "message": "SQL query built by string concatenation...",
  "blocking": true
}
```

> 想核对某条命中是否真实：打开 `file_path` 定位到 `line_number`，对照 `code_snippet`——一致即证据成立。

## 七、CLI / API / Celery 三种模式

| 模式 | 入口 | 适用场景 | 报告落盘 |
|---|---|---|---|
| **CLI** | `python -m src.cli.main analyze <repo>` | 本地快速自查、现场演示 | ✅ 自动落盘 JSON + MD（同上） |
| **API** | `uvicorn src.api.app:create_app --factory` | 对外接口、集成调用 | ✅ reporter 落盘（JSON + HTML，另有 `report.html`） |
| **Celery** | `docker compose up`（worker 消费任务队列） | 生产异步处理、Webhook 链路 | ✅ 同 API（由 tasks 传 `LocalFileReportStorage`） |

关系：CLI 直连编排引擎（进程内，无需 Redis/Celery）；API 接 HTTP 请求并把任务投到 Celery 队列，由 worker 执行（需要 Redis broker）。Webhook（GitHub 回调）→ API → Celery 是完整 CI/CD 形态；CLI 是最小可用形态。

## 八、"降级（degraded）"是什么

**降级 = 某个外部依赖不可用时，系统不报错崩溃，而是输出 `degraded=true` + 原因，按 fail-safe 原则处理。**

| 降级场景 | 表现 | 设计意图 |
|---|---|---|
| OSV 漏洞库网络不可达 | `vulnerabilities` 为空 + `degraded` 标记 | 不因外部故障假报"无漏洞"（宁可标记降级，不让结论失真） |
| Semgrep 不可用 | `code_issues` 为空 + `degraded` 标记 | 不静默通过；安全裁决保持保守 |
| 冲突消解异常 | `overall_blocking=true` | **fail-safe：拿不准就默认阻断，绝不默认放行** |

判断扫描是否可信：看输出里有没有 `degraded=true`。有 → 结论不完整，需要修环境后重跑；没有（`degraded=False`）→ 结论完整可信。

## 九、讲解口径（30 秒版）

> "我本地跑一个演示：这个仓库里有 5 个故意植入的漏洞。CodeGuard 约 10 秒扫完，命中 2 条 SQL 注入并判定为 Critical、自动阻断合并（MERGE BLOCKED），还有 1 条转人工复核。完整报告自动存档为 JSON + Markdown。整个安全链路零 LLM——每条命中都能溯源到规则 ID、代码行号和严重度。另外我用它扫了自己项目，156 个文件零误报（自举验证）。"

## 十、常见坑速查

| 坑 | 现象 | 解决 |
|---|---|---|
| 命令框闪退 | 双击 .py / 独立窗口跑完自动关 | 用 `run-demo.bat`（带 pause）；或在已打开终端里跑 |
| `Semgrep SDK failed`（9ms 秒降级） | 环境 PATH 找不到 semgrep | 2026-08-26 已修复（`_locate_semgrep` 回退 venv Scripts）；旧环境重装/重跑即可 |
| `Not a git repository` | 目标不是 git 仓库 | `git init` 后再扫 |
| OSV 网络慢/超时 | 首次跑 CVE 扫描等 30s+，`vulnerabilities` 空 | 属正常降级；demo 仓库无依赖文件可跳过 CVE |
| 报告路径带 `\tmp\` | Windows 原生 Python 把 /tmp 解析成 C:\tmp | 2026-08-26 已修复（映射到 %TEMP%）；旧版本重跑即可 |
