# CodeGuard v0.1 — 正式设计规格文档

> **状态**: 已评审通过
> **版本**: v0.1
> **日期**: 2026-08-03
> **说明**: 本文档为 CodeGuard MVP 阶段的唯一设计依据，所有开发、评审、验收均以本文档为准。

---

## 目录

1. [系统总览与数据流](#1-系统总览与数据流)
2. [四个 Agent 内部设计](#2-四个-agent-内部设计)
3. [API 设计与 Webhook 集成](#3-api-设计与-webhook-集成)
4. [数据模型与存储设计](#4-数据模型与存储设计)
5. [错误处理、降级策略与安全设计](#5-错误处理降级策略与安全设计)
6. [项目目录结构与模块划分](#6-项目目录结构与模块划分)
7. [测试策略与 MVP 范围](#7-测试策略与-mvp-范围)
8. [附录：设计决策汇总](#8-附录设计决策汇总)

---

## 1. 系统总览与数据流

### 1.1 整体拓扑

```
                          GitHub/GitLab Webhook
                                  │
                                  ▼
                    ┌──────────────────────┐
                    │   FastAPI Webhook     │  ← 接收事件，立即返回 200
                    │   Receiver            │
                    └──────┬───────────────┘
                           │ 投递任务
                           ▼
                    ┌──────────────────────┐
                    │   Celery Task Queue   │  ← Redis Broker
                    └──────┬───────────────┘
                           │
                    ┌──────▼──────────────────────┐
                    │   预处理模块（非 Agent）      │
                    │   · 仓库 Clone / 拉取        │
                    │   · Tree-sitter AST 解析     │
                    │   · 依赖清单提取             │
                    │   · 技术栈识别               │
                    │   输出：标准化 CodeMetadata   │
                    └──────┬──────────────────────┘
                           │ 发布事件 + 启动 DAG
                    ┌──────▼──────────────────────┐
                    │                             │
              ┌─────▼─────┐              ┌───────▼──────┐
              │ 安全 DAG   │              │ 辅助链路      │
              │ 主链路     │              │ (事件驱动)    │
              │            │              │              │
              │ ①安全审计  │              │ ③迁移评估    │
              │ Agent      │              │ Agent        │
              │ (规则引擎)  │              │ (LLM辅助)    │
              │    │       │              │              │
              │    ▼       │              │              │
              │ ②冲突消解  │              │              │
              │ Agent      │              │              │
              │ (规则仲裁)  │              │              │
              └─────┬─────┘              └───────┬──────┘
                    │                             │
                    │  安全结果→直接执行阻断       │
                    │  (通过 integrations 层)      │
                    │                             │
                    └──────────┬──────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │  ④报告聚合 Agent     │
                    │  · 结果去重合并       │
                    │  · 风险分级排序       │
                    │  · 模板渲染           │
                    └──────┬───────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        PR 评论回写   工单创建    报告文件存储
        (GitHub API)  (Jira/飞书)  (本地 JSON/HTML)
```

### 1.2 关键设计原则

| 原则 | 说明 |
|------|------|
| 预处理下沉 | 预处理模块非 Agent，不使用 LLM，纯确定性逻辑，所有 Agent 共享统一输入 |
| 双链路物理隔离 | 安全 DAG 主链路与辅助事件驱动链路完全并行，迁移评估结果不进入安全决策链路 |
| 安全阻断前置 | 冲突消解 Agent 做出决策后，通过 integrations 层直接执行 PR 阻断，不经过报告聚合中转 |
| 分级输出 | 安全结果就绪 → 立即回写 PR（精简版）；迁移就绪 → 异步追加；全量就绪 → 完整报告 |
| 人在回路 | 位于冲突消解 Agent 内部，仅在自动裁决规则无法覆盖时触发 |

### 1.3 事件驱动细节

- 预处理完成后，向 Redis Pub/Sub 发布 `code_metadata.ready` 事件
- 迁移评估 Agent（及后续扩展的分析 Agent）各自订阅该事件，独立启动任务
- 安全主链路优先执行（DAG 直接启动），不等待辅助链路
- 报告聚合 Agent 订阅 `security.complete` 和 `migration.complete` 事件，采用「先到先输出、全到再聚合」策略

---

## 2. 四个 Agent 内部设计

### 2.1 Agent ① 安全审计 Agent

**定位**：关键路径·执行层

```
输入: CodeMetadata (依赖清单 + 文件列表 + 代码片段)
       │
       ├─→ [依赖漏洞扫描] ──────────────────────
       │   1. 提取所有直接/间接依赖
       │   2. 本地热点缓存查询 (SQLite, 近1年高危CVE)
       │   3. 缓存未命中 → OSV API 实时查询
       │   4. 输出: 漏洞列表 (CVE编号/严重度/修复版本/证据来源)
       │
       ├─→ [代码规则扫描] (Semgrep 规则引擎) ─────
       │   1. 硬编码密钥检测
       │   2. SQL注入模式匹配
       │   3. 不安全反序列化
       │   4. 输出: 代码安全问题 (文件/行号/规则ID/修复建议)
       │
       └─→ 输出: SecurityReport
```

**阻断分级规则**：

| 条件 | 处理 |
|------|------|
| 直接依赖 + CVSS >= 7.0 | `blocking: true` |
| 直接依赖 + CVSS < 7.0 | `blocking: false`, warning |
| 间接依赖 + CVSS >= 7.0 | `blocking: false`, warning（可配置为阻断） |
| 间接依赖 + CVSS < 7.0 | `blocking: false`, info |
| 硬编码密钥 / SQL 注入 | `blocking: true` |
| 中低危代码规则 | `blocking: false`, warning |

**语言适配**：基于预处理输出的技术栈识别结果，动态加载对应语言的 Semgrep 规则集（MVP: Python only）。

**扫描范围标记**：`scan_scope: "full" | "diff"`，同步写入审计日志。

**零 LLM**：此 Agent 不使用任何 LLM 调用。所有结论来自 OSV/GitHub Advisory API + Semgrep 确定性规则。

### 2.2 Agent ② 冲突消解 Agent

**定位**：关键路径·决策层

```
输入: SecurityReport (来自安全审计Agent)
       +
      本地豁免规则库 (rule_exemptions)
       +
      人工输入 (仅在规则无法裁决时触发)
       │
       ├─→ [自动裁决引擎] ────────────────────────
       │   规则1: CVE在豁免白名单 → 降权为 info
       │   规则2: 漏洞文件在目录白名单(如test/) → 降权
       │   规则3: CVE修复版本 <= 目标升级版本 → 自动豁免
       │         (仅当本次变更被识别为框架版本升级时生效)
       │   规则4: 高危(CVSS>=7.0) + 非白名单 → 维持blocking=true
       │   规则5: 低置信度(confidence=low) → 放行,仅提示
       │
       ├─→ [人工裁决] (仅触发条件) ────────────────
       │   触发: 规则库无匹配 + 开发者提交豁免申请
       │   状态: LangGraph checkpoint 暂停，等待人工输入
       │   硬性限制: Critical(CVSS>=9.0) 禁止人工豁免
       │   超时: 默认24h, 超时维持blocking=true
       │   恢复: 人工确认后继续执行
       │
       └─→ 输出: FinalSecurityDecision
           { overall_blocking: bool, decisions: [...], audit_trail: [...] }
```

**双输入源**：
- **自动裁决**：安全审计结果 + 本地豁免规则库（CVE 白名单、目录白名单、风险豁免规则）
- **人工裁决**：仅规则无法覆盖的争议项 + 高危风险豁免申请

**关键约束**：
- 裁决逻辑为确定性规则引擎，不使用 LLM
- 仅做出阻断/放行的**业务决策**，不直接调用 GitHub API（由 integrations 层执行）
- 安全决策不可推翻原始证据链，仅可基于合规规则豁免
- 所有操作写入审计日志（append-only + 链式哈希）

### 2.3 Agent ③ 迁移评估 Agent

**定位**：辅助路径·执行层

```
输入: CodeMetadata (增量: 本次变更的AST diff)
       + 全量代码元数据 (模块依赖图、函数调用链, 作为参考上下文)
       + 目标版本信息 (如 fastapi: 0.100.0 -> 0.110.0)
       │
       ├─→ [AST 静态规则匹配] (确定性, 前置) ─────
       │   1. 匹配 @deprecated 装饰器标记的函数
       │   2. 匹配已知 Breaking Changes 规则库
       │   3. 确定性结论直接输出, 不走 LLM
       │
       ├─→ [LLM 辅助代码影响分析] ──────────────
       │   1. 将 Breaking Changes + 变更文件代码送入 DeepSeek-Coder
       │   2. LLM 判断: 哪些代码使用了被废弃的API
       │   3. LLM 生成: 逐文件的修复建议
       │   4. 输出: 影响文件清单 + 修复建议
       │
       └─→ 输出: MigrationReport
```

**LLM 使用边界**：LLM 仅用于「匹配 Breaking Changes 到具体代码行」，变更日志本身来自官方 Changelog 的确定性数据。

**降级**：LLM 超时/报错时降级为纯 AST 规则匹配，`effort_estimate.confidence` 标记为 `low`。

**安全边界**：迁移评估 Agent 的结果**不进入安全决策链路**，仅作为开发者参考。

### 2.4 Agent ④ 报告聚合 Agent

**定位**：输出层·呈现层

```
输入: FinalSecurityDecision (来自冲突消解)
       +
      MigrationReport (来自迁移评估)
       │
       ├─→ [分级输出策略] ─────────────────────────
       │   安全结果就绪 -> 渲染 PR 评论 (Jinja2 模板)
       │   迁移结果就绪 -> 追加到同一条 PR 评论 (幂等更新)
       │   全部就绪   -> 生成完整 JSON/HTML 报告 -> 存储
       │
       ├─→ [PR 评论模板渲染] (Jinja2) ────────────
       │   阻断项 (blocking issues)
       │   建议项 (安全建议 / 迁移建议 分类展示)
       │   通过项 (pass)
       │   修复示例 (代码片段)
       │
       └─→ 输出: 渲染后的 Markdown -> integrations 层发布
                 完整报告 -> report_store 持久化
```

**PR 评论精简版模板**：

```markdown
## CodeGuard 安全分析报告
> 本次扫描：PR 增量 diff · 8 个文件 · 安全扫描耗时 1.2s

### 阻断项 (1)
| 严重度 | 问题 | 位置 | 修复方案 |
|--------|------|------|----------|
| Critical | [CVE-2024-3842] Log4j RCE [OSV] | requirements.txt:L15 | 升级至 >=2.17.1 · [申请豁免] |

### 建议项
#### 安全建议
- 硬编码密钥风险：`config.py:L28` 存在明文 AK 泄露风险
#### 迁移建议
- `response_model` 参数在 FastAPI 0.110.0 已移除，影响 `api/user.py:L42` -> [修复建议]

### 通过项
- 代码安全规则扫描：12/12 通过
- 依赖漏洞扫描：47/48 依赖无高危漏洞

---
[查看完整报告] · [管理豁免规则]
```

**关键约束**：
- 此 Agent **不承载任何业务判断**，只做信息整合与格式渲染
- 不直接调用外部 API（生成的 Markdown 交给 integrations 层发布）
- 复用模板引擎（Jinja2）而非 LLM 生成报告，成本可控、格式稳定

---

## 3. API 设计与 Webhook 集成

### 3.1 核心 API 端点

```
POST   /api/v1/analyze              # 提交分析任务（异步）
  Body: {
    repo_url: "https://github.com/user/repo",     // 必填
    branch: "main",                                // 可选，默认 main
    commit_sha: "abc123",                          // 可选，幂等校验
    target: {                                      // 可选，迁移评估目标
      framework: "fastapi",
      from_version: "0.100.0",
      to_version: "0.110.0"
    },
    scan_type: "full" | "diff",                   // 默认 diff
    scan_config: {                                 // 可选，覆盖全局策略
      enable_security: true,
      enable_migration: true,
      block_severity: "high",                      // high/critical
      file_whitelist: [],
      file_blacklist: ["test/"]
    },
    pr_info: {                                     // PR 场景必填
      pr_number: 42,
      base_branch: "main",
      head_branch: "feat/upgrade-fastapi"
    },
    callback_url: "https://your-app.com/hook"     // 可选
  }
  -> 202 Accepted { task_id: "uuid" }

GET    /api/v1/tasks/{task_id}       # 查询任务状态
  -> {
      task_id, status: "pending|running|completed|failed",
      progress: 60,                              // 整体进度百分比
      current_stage: "migration",                // 当前执行阶段
      created_at, started_at, finished_at,
      security_result: {...} | null,             // 安全结果就绪后立即可查
      migration_result: {...} | null,
      full_report_url: "..." | null
    }

GET    /api/v1/tasks/{task_id}/report # 获取完整报告
  ?format=json|html

POST   /api/v1/tasks/{task_id}/appeal  # 提交豁免申诉 (人在回路入口)
  Body: {
    finding_id: "CVE-2024-xxxx",
    reason: "该漏洞触发条件需要物理访问，生产环境不存在此风险",
    evidence_url: "https://..."
  }
  -> 200 { appeal_id, status: "pending_review", estimated_hours: 24 }

GET    /api/v1/tasks/{task_id}/appeals # 查询申诉状态

GET    /api/v1/rules                  # 查询当前豁免规则配置
PUT    /api/v1/rules/{rule_id}        # 更新规则 (Web 管理后台用)

GET    /api/v1/health                 # 健康检查
```

### 3.2 Webhook 集成流程

| GitHub 事件 | 系统处理 |
|-------------|----------|
| `pull_request.opened` | 自动触发增量扫描 |
| `pull_request.synchronize` | 幂等判断（commit_sha 去重），代码更新后重新扫描，更新已有评论 |
| `pull_request.reopened` | 重新触发扫描 |
| `pull_request.closed` | 忽略 |
| `pull_request.edited`（仅标题/描述） | 忽略 |
| Draft PR | 默认跳过（可配置开关） |
| `push` (to main) | 可选：触发全量扫描并归档报告 |

**处理流程**：
1. FastAPI 接收 Webhook -> 验证 HMAC-SHA256 签名 -> 返回 200（<1s）
2. 幂等校验：`repo + pr_number + head_commit_sha` 去重
3. 解析事件类型 -> 投递 Celery 任务
4. 安全结果就绪 -> integrations 层调用 GitHub Check Runs API：
   - `POST /repos/{owner}/{repo}/check-runs`（创建检查）
   - `PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}`（更新状态）
   - `POST /repos/{owner}/{repo}/issues/{pr_number}/comments`（发布/更新评论）
5. 迁移结果就绪 -> 幂等更新同一条 PR 评论

### 3.3 Webhook 回调

**事件分级**：

| 事件 | 触发时机 | 用途 |
|------|----------|------|
| `security.complete` | 安全扫描完成 | 即时阻断告警 |
| `migration.complete` | 迁移评估完成 | 异步追加信息 |
| `analysis.complete` | 全量分析完成 | 完整数据交付 |

**回调请求**：
```
POST {callback_url}
Header: X-CodeGuard-Signature-256: HMAC-SHA256(body, pre_shared_secret)
Body: { event, task_id, repo, pr_number, security: {...}, migration: {...}, report_url }
```

**重试策略**：超时 5s，指数退避（1s/3s/10s/30s/60s），最多 5 次，最终失败记录告警日志。

---

## 4. 数据模型与存储设计

### 4.1 存储职责矩阵

| 存储 | 引擎 | 内容 | 生命周期 |
|------|------|------|----------|
| 任务状态 | Redis | 运行中任务的状态、进度、Celery 队列 | 完成后 1h TTL |
| 分析结果缓存 | Redis | 热点 SecurityReport / MigrationReport 摘要 | 24h TTL |
| 分析结果持久 | 文件系统 | 完整 JSON/HTML 报告 | 永久 |
| 审计日志 | SQLite (MVP) | 安全裁决、人工操作、豁免记录（append-only + 链式哈希） | 永久 |
| 规则配置 | SQLite (MVP) | 豁免规则、阻断阈值、白名单 | 永久 |
| CVE 热点缓存 | Redis -> SQLite -> OSV API | 三级缓存（Redis Top 200 热门依赖 + SQLite 近 1 年高危 CVE + OSV 回源） | Redis 1h TTL, SQLite 每日同步 |
| Breaking Changes | JSON 文件（本地, MVP） | 各框架版本 Breaking Changes 规则 | 随版本手动/脚本同步 |
| 报告存储 | 文件系统（MVP） | 完整报告 JSON/HTML | 永久 |

### 4.2 核心数据结构

```python
# ============================================================
# (1) 预处理模块输出
# ============================================================

class CodeMetadata(BaseModel):
    """所有 Agent 的统一输入，预处理模块生成"""
    task_id: str                       # UUID v4
    scan_id: str                       # UUID v4
    repo_url: str
    commit_sha: str
    base_commit_sha: str | None        # diff 模式基线
    head_commit_sha: str | None        # diff 模式当前
    scan_scope: Literal["full", "diff"]
    language: str                      # "python" | "javascript" | ...
    dependencies: list[Dependency]
    transitive_deps: list[Dependency]
    changed_files: list[FileInfo]
    file_graph: dict                   # 模块依赖关系图
    ast_trees: dict[str, Any]          # 文件路径 -> AST (按需加载)

class Dependency(BaseModel):
    name: str                          # "fastapi"
    version: str                       # "0.100.0"
    dependency_type: Literal["direct", "transitive"]
    ecosystem: str                     # "pypi" | "npm" | "maven"

class FileInfo(BaseModel):
    path: str
    change_type: Literal["added", "modified", "deleted"]
    diff_lines: str | None             # git diff 内容 (增量)
    content: str | None                # 完整文件内容 (全量)
    language: str | None               # 文件语言
    file_size: int | None              # 字节，预处理过滤超大/二进制文件


# ============================================================
# (2) 安全审计 Agent 输出
# ============================================================

class SecurityReport(BaseModel):
    scan_id: str
    scan_scope: Literal["full", "diff"]
    rule_set_version: str              # Semgrep 规则版本
    cve_db_version: str                # 漏洞库版本
    vulnerabilities: list[Vulnerability]
    code_issues: list[CodeIssue]
    scan_duration_ms: int
    scanned_deps_count: int

class Vulnerability(BaseModel):
    cve_id: str                        # "CVE-2024-3842"
    package_name: str
    affected_version: str
    affected_version_range: str | None # 受影响版本区间
    fixed_version: str
    fix_available: bool                # 是否存在官方修复版本
    severity: Literal["critical", "high", "medium", "low"]
    cvss_score: float
    dependency_type: Literal["direct", "transitive"]
    evidence_source: str               # "OSV" | "GitHub Advisory" | "local_cache"
    evidence_url: str
    file_location: str                 # "requirements.txt:L15"
    blocking: bool
    description: str

class CodeIssue(BaseModel):
    rule_id: str                       # "python.lang.security.audit.detect-sql-injection"
    severity: str
    confidence: Literal["high", "medium", "low"]
    file_path: str
    line_number: int
    code_snippet: str
    message: str
    fix_suggestion: str


# ============================================================
# (3) 冲突消解 Agent 输出
# ============================================================

class FinalSecurityDecision(BaseModel):
    scan_id: str
    overall_blocking: bool             # 本次扫描的最终阻断结论
    decisions: list[SecurityVerdict]
    audit_trail: AuditTrail
    executed_at: str                   # UTC ISO 8601
    executed_by: str                   # "auto" | "human:{operator_id}"

class SecurityVerdict(BaseModel):
    finding_id: str
    finding_type: Literal["vulnerability", "code_issue"]
    verdict: Literal["block", "waive", "defer"]
    reason: str
    rule_id: str | None                # 命中的豁免规则ID
    operator: str | None               # 操作人 (人工裁决)
    evidence_link: str | None
    appealable: bool                   # 是否允许申诉

class AuditTrail(BaseModel):
    """仅追加结构，不可修改/删除历史条目"""
    entries: list[AuditEntry]

class AuditEntry(BaseModel):
    timestamp: str                     # UTC ISO 8601
    action: str
    detail: dict
    operator: str                      # "system" | "human:{id}"
    evidence_link: str | None
    row_hash: str                      # SHA256(prev_hash + current_row)


# ============================================================
# (4) 迁移评估 Agent 输出
# ============================================================

class MigrationReport(BaseModel):
    scan_id: str
    framework: str
    from_version: str
    to_version: str
    breaking_changes: list[BreakingChangeImpact]
    risk_level: Literal["high", "medium", "low"]
    effort_estimate: EffortEstimate

class BreakingChangeImpact(BaseModel):
    change_desc: str
    source: Literal["ast_rule", "llm_analysis"]
    official_reference_url: str | None
    affected_files: list[AffectedFile]
    fix_suggestion: str

class AffectedFile(BaseModel):
    path: str
    line_number: int
    code_snippet: str
    impact_level: Literal["breaking", "warning"]

class EffortEstimate(BaseModel):
    affected_file_count: int
    estimated_person_days: float
    confidence: Literal["high", "medium", "low"]


# ============================================================
# (5) 报告聚合 Agent 输出
# ============================================================

class AggregatedReport(BaseModel):
    scan_id: str
    repo_url: str
    commit_sha: str
    scan_scope: Literal["full", "diff"]
    generated_at: str                  # UTC ISO 8601
    summary: ReportSummary
    security: FinalSecurityDecision | None
    migration: MigrationReport | None
    full_report_url: str | None
    appeal_count: int | None           # 待申诉/申诉中数量
    degraded: bool                     # 是否触发降级
    degraded_reasons: list[str]        # 降级原因列表

class ReportSummary(BaseModel):
    blocking_count: int
    warning_count: int
    pass_count: int
    security_scan_duration_ms: int
    migration_scan_duration_ms: int


# ============================================================
# (6) 规则配置
# ============================================================

class ExemptionRule(BaseModel):
    rule_id: str
    rule_type: Literal["cve_whitelist", "path_whitelist", "severity_downgrade"]
    pattern: str
    scope: Literal["global"] | str     # "global" | "repo:{url}" | "path:{pattern}"
    reason: str                        # 豁免理由 (必填)
    created_by: str
    created_at: str
    expires_at: str | None
    enabled: bool
```

### 4.3 Redis Key 设计

```
# 任务状态
task:{task_id}:status          -> "running" | "completed" | "failed"
task:{task_id}:progress        -> {security: "done", migration: "running", ...}
task:{task_id}:result          -> JSON (24h TTL)

# 幂等控制
task:dedup:{repo_hash}:{pr_number}:{commit_sha}  -> task_id (72h TTL)

# 结果复用缓存
cache:scan:{commit_sha}:security  -> JSON (7d TTL)

# 规则配置缓存
config:exemption:hash             -> 规则集哈希 (1h TTL)

# 限流防护
rate_limit:{ip/repo}:{minute}     -> 计数 (1m TTL, MVP 预留)

# 事件总线 (Pub/Sub)
channel: code_metadata.ready      -> 预处理完成事件
channel: security.complete        -> 安全扫描完成事件
channel: migration.complete       -> 迁移评估完成事件
channel: analysis.complete        -> 全量分析完成事件
```

### 4.4 全局数据约定

- 所有业务 ID 统一使用 **UUID v4**
- 所有时间字段统一使用 **UTC 时区 ISO 8601** 格式
- 所有降级场景的输出必须携带 `degraded: true` + `degraded_reason`，**禁止静默降级**

---

## 5. 错误处理、降级策略与安全设计

### 5.1 分层降级策略

| 故障层 | 降级行为 | SLA 影响 |
|--------|----------|----------|
| OSV API 超时/不可用 | 降级为本地缓存规则扫描，结果标记 `degraded: true`，记录审计日志 + 触发告警 | 扫描延迟不变，覆盖范围略微下降 |
| Semgrep 规则引擎异常 | 跳过代码规则扫描，漏洞扫描结果不受影响 | 仅依赖漏洞扫描仍可产出阻断结论 |
| Redis 不可用 | 降级为同步模式，Celery 用内存队列（短期），幂等/缓存失效但任务不丢 | 延迟增加（无缓存加速） |
| SQLite 写入失败 | 审计日志写本地文件兜底，后续自动恢复同步 | 不影响安全阻断（阻断指令已发出） |
| 迁移评估 LLM 超时/报错 | 降级为纯 AST 规则匹配，`EffortEstimate.confidence = low` | 不影响安全主链路 |
| 人工裁决超时 | fail-safe：维持 `blocking=true`（默认 24h，可配置） | 安全优先，不自动放行 |
| Celery Worker 崩溃 | 任务自动重试（max_retries=3），幂等 Key 保证不重复执行 | 重试后仍失败标记 failed |

**核心原则**：安全阻断能力永远不变。任何外部依赖故障时，宁可多报一个 warning，绝不漏掉一个 blocking。

### 5.2 错误码体系

```python
class CodeGuardError(Exception):
    code: str           # 机器可读错误码
    message: str        # 人类可读描述
    http_status: int    # HTTP 响应码
    retryable: bool     # 调用方可重试?

# 任务层
TASK_NOT_FOUND       = ("TASK-001", 404, False)
TASK_DUPLICATE       = ("TASK-002", 409, False)   # 幂等: 返回已有 task_id
TASK_INVALID_PARAM   = ("TASK-003", 400, False)

# 分析层
REPO_CLONE_FAILED    = ("ANALYSIS-001", 502, True)
AST_PARSE_FAILED     = ("ANALYSIS-002", 500, False)
SCAN_PARTIAL_FAILED  = ("ANALYSIS-003", 200, False)  # 部分失败但整体有结果

# 外部服务
OSV_API_UNAVAILABLE  = ("EXT-001", 502, True)    # 触发降级
GITHUB_API_RATE_LIMIT= ("EXT-002", 429, True)    # 等待重试
LLM_TIMEOUT          = ("EXT-003", 504, True)    # 触发降级

# 安全
APPEAL_EXPIRED       = ("SEC-001", 410, False)
RULE_CONFLICT        = ("SEC-002", 409, False)
UNAUTHORIZED_ACTION  = ("SEC-003", 403, False)
```

### 5.3 系统自身安全

| 层面 | 措施 |
|------|------|
| Webhook 验证 | HMAC-SHA256 签名校验，失败直接 401，Secret 环境变量注入 |
| 任务隔离 | 用户提交的仓库代码在独立工作目录执行，每次分析后清理临时文件 |
| API 限流 | IP/Token 级别限流（MVP 预留 Key，生产启用） |
| 注入防护 | 所有用户输入经 Pydantic 严格校验 + URL scheme 白名单 |
| 回调签名 | 出站回调附加 `X-CodeGuard-Signature-256`（HMAC-SHA256） |
| 敏感脱敏 | 扫描发现的密钥/Token 在报告中默认脱敏（`sk-***abcd`） |
| 沙箱执行 | Tree-sitter/Semgrep 在独立子进程内执行，超时 30s 强制终止 |

### 5.4 监控指标埋点

```
# 业务指标
scan_request_total          Counter     # 总扫描请求
scan_duration_seconds       Histogram   # 扫描耗时分布
blocking_rate               Gauge       # 阻断率
cache_hit_rate              Gauge       # CVE 缓存命中率

# 健康指标
external_api_errors         Counter     # 外部API错误（按服务分）
degraded_scan_count         Counter     # 降级扫描次数
worker_queue_depth          Gauge       # Celery 队列积压
task_failure_rate           Gauge       # 任务失败率

# 安全事件
blocking_executed           Counter     # 实际执行阻断次数
appeal_count                Counter     # 申诉次数
human_intervention_count    Counter     # 人工裁决触发次数
```

---

## 6. 项目目录结构与模块划分

### 6.1 完整目录树

```
codeguard/
├── PROJECT_RULES.md                # 唯一权威开发规范
├── ARCHITECTURE.md                 # 系统架构总览
├── DEVELOPMENT_LOG.md              # 开发日志
├── README.md
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
│
├── config/                          # 静态配置文件
│   ├── exemption_rules.yaml
│   ├── semgrep/
│   │   └── python_security.yaml
│   └── breaking_changes/
│       ├── fastapi_0.100_0.110.yaml
│       └── django_4.2_5.0.yaml
│
├── src/
│   ├── core/                        # 核心公共层（全项目依赖）
│   │   ├── errors.py                # 统一异常体系
│   │   ├── models.py                # 数据模型基类、通用枚举
│   │   └── constants.py             # 全局常量
│   │
│   ├── utils/                       # 工具层（全项目依赖）
│   │   ├── git.py                   # Git 操作封装
│   │   ├── hashing.py               # HMAC-SHA256 签名
│   │   ├── retry.py                 # 指数退避重试装饰器
│   │   ├── logging.py               # 结构化日志
│   │   ├── id_gen.py                # UUID v4 生成
│   │   └── sandbox.py               # 子进程隔离 + 超时控制
│   │
│   ├── storage/                     # 数据与存储层
│   │   ├── cve_cache.py             # CVE 三级缓存
│   │   ├── osv_client.py            # OSV API 客户端
│   │   ├── github_advisory.py       # GitHub Advisory 客户端
│   │   ├── changelog_store.py       # Breaking Changes 规则库
│   │   ├── audit_log.py             # 审计日志 (append-only + 链式哈希)
│   │   ├── rule_store.py            # 豁免规则 CRUD
│   │   └── report_store.py          # 报告存储接口抽象
│   │
│   ├── preprocess/                  # 预处理模块 (非Agent，纯确定性)
│   │   ├── repo.py                  # Git clone/pull, diff 抽取
│   │   ├── dependency.py            # 依赖清单解析
│   │   ├── parser.py                # Tree-sitter AST 解析
│   │   └── metadata.py              # CodeMetadata 组装 + 语言识别
│   │
│   ├── engine/                      # 引擎层
│   │   ├── orchestrator.py          # 编排引擎: DAG + 事件总线
│   │   ├── event_bus.py             # Redis Pub/Sub 封装
│   │   └── base_agent.py            # BaseAgent 抽象基类
│   │
│   ├── agents/                      # Agent 层
│   │   ├── base.py                  # BaseAgent: 公共接口、日志、指标
│   │   ├── security/
│   │   │   ├── agent.py             # SecurityAgent: 编排 (无LLM)
│   │   │   ├── cve_scanner.py       # 依赖漏洞扫描 (三级缓存)
│   │   │   ├── code_scanner.py      # Semgrep 规则引擎调用
│   │   │   └── models.py            # SecurityReport 等数据模型
│   │   ├── conflict/
│   │   │   ├── agent.py             # ConflictAgent: LangGraph StateGraph
│   │   │   ├── auto_resolver.py     # 自动裁决引擎
│   │   │   ├── human_loop.py        # 人在回路: checkpoint 暂停/恢复
│   │   │   └── models.py            # FinalSecurityDecision 等数据模型
│   │   ├── migration/
│   │   │   ├── agent.py             # MigrationAgent: 事件驱动独立Graph
│   │   │   ├── changelog_matcher.py # AST 静态规则匹配 (确定性)
│   │   │   ├── llm_analyzer.py      # LLM 代码影响分析
│   │   │   └── models.py            # MigrationReport 等数据模型
│   │   └── reporter/
│   │       ├── agent.py             # ReporterAgent: 事件订阅 + 分级输出
│   │       ├── templates/           # Jinja2 模板
│   │       │   ├── pr_comment.md    # PR 评论精简版
│   │       │   └── full_report.html # 完整报告
│   │       └── models.py            # AggregatedReport 等数据模型
│   │
│   ├── integrations/                # 外部系统集成层
│   │   ├── github_client.py         # GitHub API (Check Runs, Comments, Status)
│   │   ├── gitlab_client.py         # GitLab 客户端 (扩展)
│   │   └── webhook_sender.py        # 通用出站 Webhook (签名+重试)
│   │
│   ├── api/                         # FastAPI 接口层
│   │   ├── app.py                   # FastAPI 应用工厂
│   │   ├── deps.py                  # 依赖注入
│   │   ├── routers/
│   │   │   ├── analyze.py           # 分析任务接口
│   │   │   ├── appeal.py            # 申诉接口
│   │   │   ├── rules.py             # 规则管理接口
│   │   │   └── health.py            # 健康检查
│   │   ├── middleware/
│   │   │   ├── rate_limit.py        # 限流中间件 (MVP 预留)
│   │   │   └── error_handler.py     # 统一异常 -> JSON
│   │   └── schemas/
│   │       ├── request.py           # 请求 Pydantic 模型
│   │       └── response.py          # 响应 Pydantic 模型
│   │
│   ├── webhook/                     # Webhook 处理层
│   │   ├── receiver.py              # 事件接收 + 签名校验
│   │   ├── router.py                # 分发 (GitHub/GitLab)
│   │   └── handlers/
│   │       ├── github.py            # GitHub 事件解析
│   │       └── gitlab.py            # GitLab 事件解析 (扩展)
│   │
│   ├── tasks/                       # Celery 异步任务层
│   │   ├── celery_app.py            # Celery 实例配置
│   │   ├── analysis.py              # 主分析任务入口
│   │   └── callbacks.py             # 出站 Webhook 回调 + 重试
│   │
│   ├── monitoring/                  # 可观测性层
│   │   ├── metrics.py               # 指标埋点定义
│   │   └── tracing.py               # 链路追踪 (MVP 简化)
│   │
│   ├── cli/                         # CLI 工具
│   │   └── main.py                  # Click/Typer 入口
│   │
│   └── web/                         # Web 管理后台
│       ├── app.py                   # FastAPI 静态页面挂载
│       └── static/
│           └── dashboard.html       # 风险看板 (极简, 渐进增强)
│
├── tests/
│   ├── conftest.py                  # pytest fixtures
│   ├── unit/
│   │   ├── test_preprocess/
│   │   ├── test_agents/
│   │   │   ├── test_security/
│   │   │   ├── test_conflict/
│   │   │   ├── test_migration/
│   │   │   └── test_reporter/
│   │   └── test_storage/
│   ├── integration/
│   │   ├── test_api.py
│   │   ├── test_webhook.py
│   │   ├── test_full_pipeline.py
│   │   └── test_degradation.py
│   └── fixtures/
│       ├── sample_repos/
│       │   ├── python_fastapi_vuln/
│       │   └── python_clean/
│       ├── mock_responses/
│       │   ├── osv_fastapi.json
│       │   ├── github_advisory.json
│       │   └── llm_analysis.json
│       └── rule_fixtures/
│           ├── exemption_rules.yaml
│           └── breaking_changes_fastapi.yaml
│
└── docs/
    ├── specs/
    │   └── codeguard-v0.1-design-spec.md   # 本文档
    ├── adr/
    │   └── ...
    └── guides/
        ├── setup-guide.md
        └── api-reference.md
```

### 6.2 模块导入约束

```
调用方向                           允许?    说明
--------------------------------------------------------------
所有模块 -> src/core/*              Y       核心层为全项目公共依赖
所有模块 -> src/utils/*             Y       工具层为全项目公共依赖
任意模块 -> 直接调用外部 API        N       必须走 integrations 层
src/api/* -> src/tasks/*            Y       接口投递异步任务
src/api/* -> src/agents/*           N       接口不直接调 Agent, 需通过 Celery 任务
src/tasks/* -> src/agents/*         Y       任务编排 Agent
src/tasks/* -> src/preprocess/*     Y       任务先跑预处理
src/agents/* -> src/storage/*       Y       Agent 读取数据源
src/agents/* -> src/engine/*        Y       Agent 订阅事件、注册到引擎
src/agents/* -> src/integrations/*  N       Agent 不调外部 API, 只出业务决策
src/agents/* -> src/preprocess/*    N       Agent 不调预处理, 输入已是 CodeMetadata
src/preprocess/* -> src/storage/*   N       预处理不依赖外部数据, 纯本地计算
src/engine/* -> src/agents/*        N       引擎不调具体 Agent, 只依赖 BaseAgent 抽象
```

### 6.3 模块边界细化

| 模块 | 定位 | 可依赖 | 不可依赖 |
|------|------|--------|----------|
| core | 全项目公共基础 | 无 | 任何业务模块 |
| utils | 全项目工具 | core | 任何业务模块 |
| storage | 数据持久化 | core, utils | agents, engine, api |
| preprocess | 代码预处理 | core, utils | storage, agents |
| engine | 编排调度 | core, utils, BaseAgent(抽象) | 具体 Agent, storage |
| agents | 业务分析 | core, utils, storage, engine(注册/订阅) | preprocess(不调), integrations(不调) |
| integrations | 外部 API 封装 | core, utils | agents, preprocess |
| api | HTTP 接口 | core, utils, tasks, schemas | agents(不直调) |
| webhook | Webhook 处理 | core, utils, tasks | agents(不直调) |
| tasks | 异步任务编排 | core, utils, preprocess, agents, engine, integrations | - |
| monitoring | 可观测性 | core, utils | 业务模块 |
| cli | 命令行工具 | core, utils, tasks | - |
| web | Web 后台 | core, utils, storage | agents |

---

## 7. 测试策略与 MVP 范围

### 7.1 测试分层

| 层级 | 覆盖目标 | 工具 | CI 门禁 |
|------|----------|------|---------|
| 单元测试 | 每个 Agent 核心逻辑、自动裁决引擎所有规则分支、数据模型、预处理解析器 | pytest | 覆盖率 >= 70% |
| 集成测试 | API 端点请求-响应、Webhook 签名校验与事件分发、数据库/Redis 读写、Celery 任务 | pytest + httpx | 所有端点通过 |
| 端到端测试 | 完整分析链路（真实仓库->安全扫描->冲突消解->报告输出） | Docker Compose + 本地服务 | 核心场景通过 |
| 降级测试 | OSV/Redis/LLM 不可用时的降级行为 | Mock 外部依赖 | 降级场景通过 |
| 安全测试 | Webhook 伪造签名拒绝、回调签名验证、SQL 注入、路径遍历、审计日志不可篡改 | pytest | 全部通过 |
| Benchmark | CVE 查询延迟（三级缓存命中）、安全主链路端到端延迟、迁移评估耗时 | pytest-benchmark | 安全链路 <3s / PR 场景 <5s |

### 7.2 测试 Fixtures

```
tests/fixtures/
├── sample_repos/
│   ├── python_fastapi_vuln/          # 含已知漏洞 + Breaking Changes
│   └── python_clean/                 # 无漏洞对照
├── mock_responses/
│   ├── osv_fastapi.json              # OSV API Mock
│   ├── github_advisory.json          # GitHub Advisory Mock
│   └── llm_analysis.json             # DeepSeek-Coder Mock
└── rule_fixtures/
    ├── exemption_rules.yaml           # 测试用豁免规则
    └── breaking_changes_fastapi.yaml   # 测试用 Breaking Changes
```

### 7.3 Benchmark 指标

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 安全关键路径延迟 | <= 3s | Webhook 接收 -> 安全扫描 -> 冲突消解 -> PR 状态更新 |
| 全量分析总延迟 | <= 5s | 含迁移评估 + 完整报告生成 |

### 7.4 MVP 范围 (v0.1)

**MVP 必须完成**：

- [x] Webhook 接收 + 签名校验 (GitHub)
- [x] 预处理: 依赖解析 + Tree-sitter AST (Python only)
- [x] 安全审计 Agent: CVE 扫描（三级缓存）+ Semgrep 代码规则
- [x] 冲突消解 Agent: 自动裁决（4 条核心规则）+ 人在回路（checkpoint 暂停）
- [x] 迁移评估 Agent: Breaking Changes 规则库 (FastAPI) + LLM 辅助分析
- [x] 报告聚合 Agent: PR 评论模板渲染
- [x] 安全结果前置回写 PR (Check Runs API)
- [x] 内置平台回调（GitHub PR 状态更新、评论发布）
- [x] 审计日志 (SQLite, append-only + 链式哈希)
- [x] CLI 工具 (本地预检)
- [x] Docker Compose 一键部署

**MVP 不做（v0.2+）**：

- [ ] GitLab Webhook（架构预留）
- [ ] 多语言代码规则扩展（仅 Python）
- [ ] Web 管理后台（仅极简健康检查页）
- [ ] 定时全量仓库扫描（Celery Beat）
- [ ] 通用第三方 Webhook 回调（自定义 callback_url、飞书/钉钉/Jira）
- [ ] 增量 diff 扫描模式（MVP 先全量）
- [ ] OAuth/登录体系

**v0.2 迭代**：

- -> 增量 diff 扫描模式
- -> GitLab 支持
- -> Web 管理后台（规则配置 + 风险看板）
- -> 通用第三方 Webhook 出站回调
- -> 多语言扩展（JavaScript/TypeScript）

**v1.0 生产就绪**：

- -> OAuth 2.0 认证
- -> PostgreSQL 替换 SQLite
- -> S3 对象存储报告
- -> Prometheus + Grafana 监控
- -> Kubernetes Helm Chart

---

## 8. 附录：设计决策汇总

| 决策项 | 选择 | 核心理由 |
|--------|------|----------|
| 安全审计不使用 LLM | 纯规则引擎 + OSV API + Semgrep | 合规要求、零幻觉、证据链可追溯 |
| 编排框架 | LangGraph | 原生 StateGraph + Checkpoint 人在回路 |
| 编排模式 | 混合（安全 DAG + 辅助事件驱动） | 安全链路确定性 + 辅助链路扩展性 |
| 后端框架 | FastAPI + Celery + Redis | 异步、任务队列解耦、Redis 复用为事件总线 |
| CVE 数据源 | 三级缓存（Redis->SQLite->OSV API） | 保障 3s SLA，冷热分层 |
| 交互核心 | API + Webhook | 嵌入 CI/CD，风险发生点自动拦截 |
| 人在回路位置 | 冲突消解 Agent 内部 | 规则无法覆盖时触发，不打断自动化流程 |
| PR 状态 API | GitHub Check Runs API | 原生通过/失败/进行中，与 Actions 一致 |
| 审计日志 | append-only + 链式哈希 | 等保 2.0 合规，防篡改 |
| 报告策略 | 安全结果优先回写 + 迁移异步追加 | 兼顾阻断 SLA 与分析完整性 |
| 预处理定位 | 非 Agent 纯确定性模块 | 统一数据源，避免 Agent 间数据不一致 |
| 降级原则 | fail-safe 保守原则 | 外部故障时维持 blocking，不自动放行 |
| Agent 数 | 4 个（安全审计、冲突消解、迁移评估、报告聚合） | 权责分离，每个 Agent 数据源独立 |
| LLM 使用边界 | 仅迁移评估的代码影响分析 | 安全链路零 LLM，辅助链路按需 LLM |
| 开发语言 | Python 3.11+ | 当前生态主流、Tree-sitter 支持好、AI 工具链成熟 |

---

> **文档状态**: 已评审通过，MVP 开发唯一设计依据
> **创建时间**: 2026-08-03
> **关联文档**: PROJECT_RULES.md, ARCHITECTURE.md, docs/adr/*
