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

## 三、预期输出

```
Blocking:  2 / Warnings: 1 / Passed: 1
MERGE BLOCKED — fix the issues above before merging.
```

- 阻断项 2 条：`config.semgrep.python-sql-string-concat`（Critical，`main.py:L43`）
- 建议项 1 条：`python-insecure-hmac-comparison`（medium，复核不阻断）
- 扫描降级标识：无（`degraded=False`）

## 四、完整报告在哪

**CLI 模式现在会自动落盘**（2026-08-26 起）：

```
%TEMP%\codeguard_reports\<task_id>\
├── report.json      # 完整机器可读报告（每条命中详情）
└── pr_comment.md    # PR 评论 Markdown（就是终端里那段表格）
```

终端里也会打印 `Report persisted to: <路径>`。task_id 每次不同，按时间排最新的就是刚跑的。

> 历史背景：CLI 曾不落盘（reporter 的 `_report_store` 默认 None），2026-08-26 已加自动落盘并与 API 模式共用 `LocalFileReportStorage`；同时修复 Windows 下 `/tmp/` 路径被解析成 `C:\tmp\` 的问题（现映射到 `%TEMP%`）。

另外，报告里的 `/api/v1/tasks/<id>/report?format=html` 是 **API 模式**的端点（需启动服务，见第五节）。

## 五、CLI / API / Celery 三种模式

| 模式 | 入口 | 适用场景 | 报告落盘 |
|---|---|---|---|
| **CLI** | `python -m src.cli.main analyze <repo>` | 本地快速自查、现场演示 | ✅ 自动落盘 JSON + MD（同上） |
| **API** | `uvicorn src.api.app:create_app --factory` | 对外接口、集成调用 | ✅ reporter 落盘（JSON + HTML，另有 `report.html`） |
| **Celery** | `docker compose up`（worker 消费任务队列） | 生产异步处理、Webhook 链路 | ✅ 同 API（由 tasks 传 `LocalFileReportStorage`） |

关系：CLI 直连编排引擎（进程内，无需 Redis/Celery）；API 接 HTTP 请求并把任务投到 Celery 队列，由 worker 执行（需要 Redis broker）。Webhook（GitHub 回调）→ API → Celery 是完整 CI/CD 形态；CLI 是最小可用形态。

## 六、"降级（degraded）"是什么

**降级 = 某个外部依赖不可用时，系统不报错崩溃，而是输出 `degraded=true` + 原因，按 fail-safe 原则处理。**

| 降级场景 | 表现 | 设计意图 |
|---|---|---|
| OSV 漏洞库网络不可达 | `vulnerabilities` 为空 + `degraded` 标记 | 不因外部故障假报"无漏洞"（宁可标记降级，不让结论失真） |
| Semgrep 不可用 | `code_issues` 为空 + `degraded` 标记 | 不静默通过；安全裁决保持保守 |
| 冲突消解异常 | `overall_blocking=true` | **fail-safe：拿不准就默认阻断，绝不默认放行** |

判断扫描是否可信：看输出里有没有 `degraded=true`。有 → 结论不完整，需要修环境后重跑；没有（`degraded=False`）→ 结论完整可信。

## 七、讲解口径（30 秒版）

> "我本地跑一个演示：这个仓库里有 5 个故意植入的漏洞。CodeGuard 约 10 秒扫完，命中 2 条 SQL 注入并判定为 Critical、自动阻断合并（MERGE BLOCKED），还有 1 条转人工复核。完整报告自动存档为 JSON + Markdown。整个安全链路零 LLM——每条命中都能溯源到规则 ID、代码行号和严重度。另外我用它扫了自己项目，156 个文件零误报（自举验证）。"

## 八、常见坑速查

| 坑 | 现象 | 解决 |
|---|---|---|
| 命令框闪退 | 双击 .py / 独立窗口跑完自动关 | 用 `run-demo.bat`（带 pause）；或在已打开终端里跑 |
| `Semgrep SDK failed`（9ms 秒降级） | 环境 PATH 找不到 semgrep | 2026-08-26 已修复（`_locate_semgrep` 回退 venv Scripts）；旧环境重装/重跑即可 |
| `Not a git repository` | 目标不是 git 仓库 | `git init` 后再扫 |
| OSV 网络慢/超时 | 首次跑 CVE 扫描等 30s+，`vulnerabilities` 空 | 属正常降级；demo 仓库无依赖文件可跳过 CVE |
| 报告路径带 `\tmp\` | Windows 原生 Python 把 /tmp 解析成 C:\tmp | 2026-08-26 已修复（映射到 %TEMP%）；旧版本重跑即可 |
