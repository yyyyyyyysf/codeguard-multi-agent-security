# CodeGuard — 系统架构总览

> **版本**: v0.1  
> **日期**: 2026-08-03  
> **说明**: 本文档为 CodeGuard 系统架构的快速查阅入口。开发前必读，完整设计规格见 `docs/specs/codeguard-v0.1-design-spec.md`，开发行为规范见 `PROJECT_RULES.md`。

---

## 一、项目定位

CodeGuard 是一个**多 Agent 协作的代码库智能分析平台**，以 API + Webhook 为核心交付形态，嵌入 CI/CD 研发工作流，在 PR 提交、依赖变更等风险发生点自动拦截安全问题与迁移风险。

### 核心差异化

- **不是"事后报告"工具**：安全结果在提交时直接阻断，而非生成 PDF 等待查阅
- **安全链路零 LLM**：所有安全结论来自确定性规则引擎 + 权威漏洞库，证据链 100% 可追溯
- **混合编排**：安全链 DAG（确定性） + 分析链事件驱动（可扩展），兼顾合规与灵活性

---

## 二、系统架构图

```
                          GitHub/GitLab Webhook
                                  │
                                  ▼
┌─────────────────────────────────────────────────────┐
│                    API / Webhook 层                  │
│  FastAPI (async)  ·  HMAC-SHA256 签名校验          │
│  Webhook 接收 -> 200 OK (<1s) -> Celery 任务投递   │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│                Celery 异步任务队列 (Redis Broker)    │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │    预处理模块 (非Agent)  │
          │  · Git Clone/Diff       │
          │  · Tree-sitter AST      │
          │  · 依赖清单提取         │
          │  输出: CodeMetadata     │
          └────────────┬────────────┘
                       │ Pub/Sub: code_metadata.ready
          ┌────────────▼──────────────────────┐
          │                                    │
┌─────────▼──────┐                   ┌────────▼───────┐
│  安全 DAG 主链路│                   │  辅助事件链路   │
│  (LangGraph)    │                   │  (Redis Pub/Sub)│
│                 │                   │                 │
│  ① 安全审计     │                   │  ③ 迁移评估     │
│  · CVE扫描      │                   │  · AST规则匹配  │
│  · Semgrep规则  │                   │  · LLM影响分析  │
│  · 零LLM        │                   │                 │
│       │         │                   │                 │
│       ▼         │                   │                 │
│  ② 冲突消解     │                   │                 │
│  · 自动裁决引擎 │                   │                 │
│  · 人在回路     │                   │                 │
│  · 零LLM        │                   │                 │
└─────────┬──────┘                   └────────┬────────┘
          │ 安全决策 -> integrations 层 -> 直接阻断PR  │
          └──────────────────┬─────────────────────────┘
                             ▼
          ┌──────────────────────────────────┐
          │        ④ 报告聚合 Agent           │
          │  · 安全结果 -> 立即回写PR (精简版) │
          │  · 迁移结果 -> 异步追加            │
          │  · 全量就绪 -> 完整报告             │
          └──────────────┬───────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    PR 评论回写     工单创建      报告文件存储
    (Check Runs API) (Jira/飞书)   (JSON/HTML)
```

### 关键设计决策

| 决策 | 说明 |
|------|------|
| **预处理非 Agent** | 不依赖 LLM，纯确定性逻辑。所有 Agent 接收统一的 CodeMetadata |
| **安全阻断前置** | 冲突消解决策 -> integrations 层直接调 GitHub API 执行阻断，不经报告聚合中转 |
| **双链路并行** | 安全 DAG 不等待迁移评估；迁移评估结果不进入安全裁决 |
| **分级输出** | 安全结果就绪立即回写 PR（保鲜 SLO），迁移结果异步追加，不刷屏 |
| **人在回路** | LangGraph checkpoint 暂停，仅在自动裁决规则无法覆盖时触发 |

---

## 三、模块职责总览

### 3.1 分层架构

```
src/
├── core/           核心公共层 (异常体系、通用模型、常量) - 全项目依赖
├── utils/          工具层 (Git、签名、重试、日志、沙箱) - 全项目依赖
├── storage/        存储层 (CVE缓存、OSV客户端、审计日志、规则CRUD)
├── preprocess/     预处理 (Git操作、依赖解析、AST生成) - 非Agent
├── engine/         编排层 (Orchestrator、EventBus、BaseAgent抽象)
├── agents/         Agent层 (安全审计、冲突消解、迁移评估、报告聚合)
├── integrations/   外部集成 (GitHub Client、Webhook Sender)
├── api/            FastAPI (路由、中间件、请求/响应Schema)
├── webhook/        Webhook处理 (接收、签名校验、事件分发)
├── tasks/          Celery任务 (异步编排、回调)
├── monitoring/     可观测性 (指标埋点、追踪)
├── cli/            CLI工具
└── web/            Web管理后台
```

### 3.2 四个 Agent 权责

| Agent | 定位 | 核心职责 | 禁止行为 |
|-------|------|----------|----------|
| ① 安全审计 | 关键路径·执行层 | CVE 扫描（三级缓存）+ Semgrep 代码规则；输出 SecurityReport | 使用 LLM、修改安全结论、直接执行阻断 |
| ② 冲突消解 | 关键路径·决策层 | 自动裁决（豁免规则匹配）+ 人工裁决调度；输出阻断/放行决策 | 使用 LLM、直接调 GitHub API、推翻原始证据链 |
| ③ 迁移评估 | 辅助路径·执行层 | AST 静态规则 + LLM 辅助代码影响分析；输出 MigrationReport | 参与安全决策、调用外部 API |
| ④ 报告聚合 | 输出层·呈现层 | 结果去重合并、风险分级、Jinja2 模板渲染；输出 Markdown/HTML | 修改安全/迁移结论、直接调外部 API |

### 3.3 调度拓扑

```
┌─ 安全 DAG (LangGraph StateGraph) ──────────────┐
│  ① SecurityAgent ──► ② ConflictAgent            │
│  (规则引擎,零LLM)     (规则仲裁,人在回路)        │
│                       │                         │
│                       ├─ blocking=true ──► integrations/github_client
│                       │                     · Check Runs API 标红
│                       │                     · PR 评论发布阻断信息
│                       └─ blocking=false ─► 放行，结果推送 Reporter
└────────────────────────────────────────────────┘

┌─ 辅助链路 (Redis Pub/Sub 事件驱动) ────────────┐
│  code_metadata.ready ──► ③ MigrationAgent       │
│                            · 订阅事件启动        │
│                            · 与安全主链并行       │
│                            · 失败不影响安全输出   │
└────────────────────────────────────────────────┘

┌─ 聚合层 (事件订阅) ────────────────────────────┐
│  订阅 security.complete / migration.complete    │
│  ④ ReporterAgent                                │
│  · 先到先输出 (安全优先)                         │
│  · 全到再聚合完整报告                            │
│  · 生成内容 -> integrations 层发布                │
└────────────────────────────────────────────────┘
```

---

## 四、核心数据流

```
[Webhook 事件]
      │
      ▼
[幂等判断] repo + pr_number + commit_sha 去重
      │
      ▼
[预处理] -> CodeMetadata
      │
      ├──> [安全审计] -> SecurityReport
      │         │
      │         ▼
      │    [冲突消解] -> FinalSecurityDecision
      │         │
      │         ├── overall_blocking=true  -> GitHub API 阻断 PR
      │         ├── 审计日志写入 (append-only + 链式哈希)
      │         └── 推送 security.complete 事件
      │
      └──> [迁移评估] -> MigrationReport (异步)
                │
                └── 推送 migration.complete 事件
                         │
      ┌──────────────────┘
      ▼
[报告聚合] -> AggregatedReport
      │
      ├── PR 评论 (精简版, 幂等更新)
      ├── 完整报告 (JSON/HTML)
      └── 可选: 通用 Webhook 回调
```

### 关键时刻要求

| 指标 | 目标 |
|------|------|
| Webhook 响应 | < 1s |
| 安全链路端到端 (Webhook -> 阻断) | <= 3s |
| 全量分析 (含迁移) | <= 5s |

---

## 五、技术栈总览

| 层级 | 选型 | 关键能力 |
|------|------|----------|
| **LLM** | 安全: 零 LLM；迁移: DeepSeek-Coder；聚合: Jinja2 模板 | 安全链零幻觉，对症下药 |
| **编排** | LangGraph (StateGraph + Checkpoint) | DAG、人在回路、断点续跑 |
| **后端** | FastAPI + Celery + Redis | 异步 API、任务队列、事件总线三合一 |
| **漏洞源** | OSV API + GitHub Advisory + 本地缓存 (三级) | 权威、实时、高性能 |
| **代码解析** | Tree-sitter + 依赖文件解析器 | 统一 AST，多语言扩展预埋 |
| **规则引擎** | Semgrep + 自定义规则 | 代码安全检查，确定性输出 |
| **存储** | Redis (热) + SQLite (持久/MVP) + 文件系统 (报告) | 冷热分层，MVP 轻量化 |
| **部署** | Docker Compose | 一键启动，开发即生产 |

---

## 六、安全设计红线

1. **安全主链路不可旁路**：任何模块故障、降级不得绕过安全判断
2. **安全审计零 LLM**：安全结论不能由黑盒模型生成
3. **冲突消解零 LLM**：裁决基于确定性规则匹配
4. **证据链溯源**：所有安全结论绑定 CVE 编号 / Semgrep 规则 ID + 权威来源链接
5. **fail-safe**：外部依赖故障时维持 `blocking=true`，不自动放行
6. **审计不可篡改**：append-only + 链式哈希 (SHA256)
7. **降级不静默**：所有降级输出标记 `degraded: true` + `degraded_reason`
8. **Critical 禁止豁免**：CVSS >= 9.0 的漏洞不允许人工豁免

---

## 七、文档索引

| 文档 | 用途 | 何时读 |
|------|------|--------|
| `PROJECT_RULES.md` | 唯一权威开发规范 | **开发前必读** |
| `docs/specs/codeguard-v0.1-design-spec.md` | 完整设计规格 | 查阅具体设计细节时 |
| `docs/adr/*.md` | 架构决策记录 | 理解技术选型背景时 |
| `docs/guides/setup-guide.md` | 环境搭建指南 | 首次搭建项目时 |
| `DEVELOPMENT_LOG.md` | 开发日志 | 了解当前进度和历史改动 |

---

## 八、模块开发状态

| 模块 | 状态 | 测试 | 覆盖 |
|------|------|------|------|
| Module 1: 项目骨架 | ✅ | N/A | N/A |
| Module 2: core/ | ✅ | 手动 | N/A |
| Module 3: utils/ | ✅ | 手动 | N/A |
| Module 4: storage/ | ✅ | 手动 | N/A |
| Module 5: preprocess/ | ✅ | 手动 | N/A |
| Module 6: engine/ | ✅ | 手动 | N/A |
| **Module 7: Security Agent** | ✅ | 34/34 ✅ | **89%** |
| **Module 8: Conflict Agent** | ✅ | 49/49 ✅ | **87%** |
| **Module 9: Migration Agent** | ✅ | 40/40 ✅ | **88%** |
| **Module 10: Reporter Agent** | ✅ | 18/18 ✅ | **84%** |
| 🎉 **全部 4 个 Agent 完成** | | | |
| **Module 11: Integrations** | ✅ | 25/25 ✅ | **87%** |
| **Module 12: API + Webhook** | ✅ | 40/40 ✅ | **79%** |
| Module 13: Celery Tasks | ⬜ | - | - |
| Module 14: CLI | ⬜ | - | - |
| Module 15-18: 测试/部署 | ⬜ | - | - |

---

> **最后更新**: 2026-08-03  
> **关联**: PROJECT_RULES.md, docs/specs/codeguard-v0.1-design-spec.md
