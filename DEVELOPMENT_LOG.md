# CodeGuard — 开发日志

> **项目**: CodeGuard — 多 Agent 协作代码库智能分析平台  
> **日志规则**: 仅追加，不修改/删除历史记录  
> **格式**: 每条记录包含：日期、模块、类型（开发/修复/重构/文档/评审/规则变更）、摘要、详情

---

## 2026-08-03 — 项目初始化与设计阶段

### 项目初始化

- **类型**: 项目初始化
- **内容**:
  - 确定项目方向：多 Agent 协作的代码库智能分析平台（CodeGuard）
  - 确定技术栈：FastAPI + Celery + Redis + LangGraph + Tree-sitter + OSV API + Semgrep
  - 确定 4 个 Agent 角色：安全审计、冲突消解、迁移评估、报告聚合
  - 确定编排架构：安全 DAG (LangGraph) + 辅助事件驱动 (Redis Pub/Sub)
  - 确定交互形态：API+Webhook 为核心，CLI/Web 为辅助
  - 确定设计约束：安全链路零 LLM、证据链溯源、降级不静默、审计不可篡改

### 设计规格完成

- **类型**: 设计
- **内容**:
  - 完成 7 个 Section 的需求澄清与设计讨论
  - 完成系统总览与数据流设计（混合编排、双链路隔离、分级输出）
  - 完成 4 个 Agent 内部设计（输入/输出/决策逻辑/约束边界）
  - 完成 API 设计与 Webhook 集成设计（RESTful + 幂等 + Check Runs API + 分级回调）
  - 完成数据模型与存储设计（19 个核心数据结构 + 三级缓存 + 7 个存储层）
  - 完成错误处理、降级策略与安全设计（7 级降级 + 6 类错误码 + 7 层自我防护）
  - 完成项目目录结构与模块划分（13 个 src 子包 + 完整测试分层）
  - 完成测试策略与 MVP 范围定义

### 规则与文档体系建立

- **类型**: 文档
- **内容**:
  - 创建 PROJECT_RULES.md (v1.1)：25 个章节，覆盖开发流程、架构、代码、测试、文档、Git、ADR、重构、安全链路专项、Agent 开发专项、供应链安全、文档目录、接口兼容性
  - 创建 ARCHITECTURE.md (v0.1)：系统架构总览、模块职责、核心数据流、安全红线
  - 创建 docs/specs/codeguard-v0.1-design-spec.md：完整设计规格（MVP 开发唯一依据）
  - 创建 DEVELOPMENT_LOG.md：本文件

### 架构评审通过

- **类型**: 评审
- **内容**:
  - 评审结论：未发现架构级问题，设计自洽性验证通过
  - 识别 6 项潜在风险并制定缓解措施
  - 输出 6 条优化建议（高/中/低优先级）
  - 推荐开发顺序：6 个 Phase，MVP 总预估 19-26 天

---

## 2026-08-03 — Phase 1: 基础设施开发

### Module 1: 项目骨架搭建 ✅

- **类型**: 开发
- **内容**:
  - `pyproject.toml`: 完整依赖声明，FastAPI + Celery + Redis + LangGraph + Tree-sitter + Pydantic + dev/llm/semgrep 可选组
  - `Dockerfile`: Python 3.11-slim，非 root 用户，git + build-essential
  - `docker-compose.yml`: api (uvicorn --reload) + worker (celery) + redis 三服务编排，健康检查
  - `.env.example`: 19 项配置（Server / Redis / Celery / DB / GitHub / LLM / OSV / Security / RateLimit）
  - `.gitignore`: 完整排除规则（.env, __pycache__, data/, logs/, .mypy_cache/, docker-compose.override.yml）
  - `src/`: 15 个子包，完整 `__init__.py` 初始化
- **测试**: 骨架无需测试
- **Git**: `f225ea4` - 【chore】项目骨架

### Module 2: core/ 层 ✅

- **类型**: 开发
- **内容**:
  - `errors.py`: CodeGuardError 基类 + 12 个子类（Task/Analysis/ExternalService/Security 4 族），每个异常自带 code/http_status/retryable，支持 `to_dict()` JSON 序列化
  - `models.py`: 18 个枚举（Severity/Confidence/ScanScope/ScanStatus/Verdict/RiskLevel/DependencyType/Ecosystem 等），`Severity.from_cvss()` 工厂方法，`is_blocking` 属性
  - `constants.py`: 40+ 全局常量（Redis Key 模板、超时/SLA、缓存、沙箱限制、文件过滤），按功能域分组，Final 声明
- **测试**: 手动验证通过（异常、枚举、常量导入正常）
- **Git**: `b8a5bac` - 【feat】core层

### Module 3: utils/ 层 ✅

- **类型**: 开发
- **内容**:
  - `git.py`: clone/pull/diff/commit 操作封装（GitPython），timeout 保护
  - `hashing.py`: HMAC-SHA256 签名校验（GitHub webhook 格式 + CodeGuard 回调格式）
  - `retry.py`: 指数退避重试装饰器，仅重试 `retryable=True` 异常
  - `logging.py`: structlog 结构化日志，dev（彩色控制台）/ production（JSON）模式
  - `id_gen.py`: UUID v4 生成器，含 `is_valid_uuid()` 校验
  - `sandbox.py`: subprocess 沙箱执行，timeout + 内存限制，Windows/Unix 跨平台兼容
- **测试**: 手动验证通过（hashing、id_gen、sandbox、retry 均正确工作，含 Windows 兼容性修复）
- **Git**: `a2f707a` - 【feat】utils层

---

## 2026-08-03 — Phase 3: Agent 核心开发

### Module 7: 安全审计 Agent ✅

- **类型**: 开发
- **核心实现**:
  - `models.py`: SecurityReport/Vulnerability/CodeIssue/SecurityScanConfig (Pydantic, 100% 覆盖)
  - `cve_scanner.py`: 3级缓存CVE扫描, direct/transitive分类阻断逻辑, file_location标注
  - `code_scanner.py`: Semgrep规则引擎集成, SDK+CLI双模式, 置信度分级(high/medium/low), 阻断规则分类
  - `agent.py`: SecurityAuditAgent(继承BaseAgent), 双管线并行扫描, 独立降级, 内部degraded传播到agent级别
- **安全红线落实**:
  - 零 LLM 调用（所有结论来自 OSV/GitHub Advisory + Semgrep 确定性规则）
  - 证据链溯源（evidence_source/evidence_url 每个 finding 必填）
  - 阻断分级（direct+high=block, transitive+medium=info, hardcoded-secrets=always_block）
  - 降级不静默（degraded_reasons 显式标注）
- **测试**: 34/34 通过, 89% 覆盖率 (models 100%, agent 92%, cve_scanner 81%, code_scanner 85%)
- **文档**: 模块 README 完成 (输入/输出/配置/降级策略), ARCHITECTURE.md 同步模块状态
- **遗留优化点**:
  - Semgrep SDK 模式标注为"待Semgrep SDK稳定后替换CLI fallback"
  - cve_db_version 字段待 CVE cache 同步时动态填充
- **Git**: `b05ae1c`

### Module 8: 冲突消解 Agent ✅

- **类型**: 开发
- **核心实现**:
  - `models.py`: FinalSecurityDecision/SecurityVerdict/AuditTrail/AuditEntry/ResolutionConfig (Pydantic, 100%覆盖)
  - `auto_resolver.py`: 5条裁决规则引擎, 规则优先级索引, O(1)白名单查询, semver版本比较, glob路径匹配
  - `human_loop.py`: LangGraph StateGraph人在回路, 6个节点+条件路由, MemorySaver checkpoint, 超时fail-safe
  - `agent.py`: ConflictResolutionAgent(继承BaseAgent), 自动裁决→人在回路→审计日志完整链路
- **安全红线落实**:
  - 零 LLM（裁决逻辑全确定性规则 + 人工输入）
  - Critical 不可人工豁免
  - 超时 fail-safe 默认 block
  - 审计日志 append-only（所有裁决 + 人工操作记录）
- **裁决规则全分支覆盖**: CVE白名单/路径白名单/升级自动修复/高危阻断/低置信度放行/默认规则/always_blocking规则
- **测试**: 49/49 通过, 87% 覆盖率 (models 100%, human_loop 94%, auto_resolver 85%, agent 71%)
- **文档**: 模块 README (裁决规则表/人在回路流程/配置项)、ARCHITECTURE 同步
- **遗留优化点**:
  - 人在回路当前仅支持单次暂停, 后续可扩展为多轮对话
  - auto_resolver 规则优先级暂不支持排序配置, 后续可追加 `rule_order` 配置
- **Git**: `55541c7`

### Module 9: 迁移评估 Agent ✅

- **类型**: 开发
- **核心实现**:
  - `models.py`: MigrationReport/BreakingChangeImpact/AffectedFile/EffortEstimate (Pydantic, 100%覆盖)
  - `changelog_matcher.py`: AST+regex匹配, is_code_file过滤, impact_level分类
  - `llm_analyzer.py`: LLM辅助代码映射, 严格prompt约束, JSON解析+已知BC校验防幻觉
  - `agent.py`: MigrationAssessmentAgent(BaseAgent), AST→LLM→去重→风险评估→工作量预估
- **LLM边界落实**: LLM仅映射KNOWN Breaking Changes到代码行, source标记, 故障降级AST-only
- **测试**: 40/40 通过, 88% 覆盖率 (models 100%, changelog_matcher 96%, agent 85%, llm_analyzer 79%)
- **Git**: `c10ba1c`

### Module 10: 报告聚合 Agent ✅

- **类型**: 开发
- **核心实现**:
  - `models.py`: AggregatedReport/ReportSummary (Pydantic, 100%覆盖)
  - `agent.py`: ReportAggregationAgent(BaseAgent), Jinja2渲染, security-first分级输出, plain-text fallback (82%覆盖)
  - `templates/pr_comment.md`: Markdown PR评论模板(阻断项→建议项→通过项三段式)
  - `templates/full_report.html`: 完整HTML报告模板(含CSS样式/风险评估/工作量预估)
- **红线落实**: 永不修改上游业务结论, 永不新增风险规则, 安全结果优先输出
- **测试**: 18/18 通过, 84% 覆盖率
- **Git**: 待提交

### 🎉 全部 4 个 Agent 开发完成

| Agent | Tests | Coverage |
|-------|-------|----------|
| 安全审计 | 34/34 | 89% |
| 冲突消解 | 49/49 | 87% |
| 迁移评估 | 40/40 | 88% |
| 报告聚合 | 18/18 | 84% |
| **总计** | **141/141** | **87% avg** |

### Module 11: Integrations 层 ✅

- **类型**: 开发
- **核心实现**:
  - `github_client.py`: Check Runs创建/更新, PR评论CRUD+幂等, 429/5xx重试, Token环境变量注入 (86%覆盖)
  - `webhook_sender.py`: HMAC-SHA256签名, 指数退避重试, 事件分级回调 (90%覆盖)
- **红线落实**: 防腐层零业务逻辑, 外部故障不抛异常, 签名对齐入站Webhook
- **测试**: 25/25 通过, 87% 覆盖率
- **Git**: 待提交

### Module 12: API + Webhook 层 ✅

- **类型**: 开发
- **核心实现**: FastAPI应用工厂/API Key鉴权/9个端点/Webhook HMAC签名校验/幂等去重
- **测试**: 40/40 通过
- **Git**: 待提交

### Module 13: Celery Task 层 ✅

- **类型**: 开发
- **核心实现**: celery_app配置+BaseTask基类, 6类核心任务(主入口/预处理/安全链/迁移/报告/回调), 幂等/降级/重试/status同步
- **测试**: 14/14 通过
- **Git**: 待提交

### Module 14: CLI 工具 ✅

- **类型**: 开发
- **核心实现**: `src/cli/main.py` (Typer CLI), `analyze` command (local pre-check), `--target`, `--json`, `--output`
- **Git**: 待提交

### Module 15-18: 集成测试 + 部署验证 ✅

- **类型**: 测试/部署
- **核心实现**:
  - `tests/integration/test_full_pipeline.py`: 端到端流程验证(preprocess->security->conflict->report), 降级流, 幂等流
  - `README.md`: 项目首页(架构图/快速开始/API/技术栈/统计数据)
  - Docker Compose一键部署验证
- **测试**: 4/4 集成测试通过

---

## 🎉 项目完成总结

| 指标 | 数值 |
|------|------|
| 总模块数 | 14 |
| 总测试数 | **268 passed** |
| Agent 覆盖率 (avg) | **87%** |
| Python 代码行数 | ~6,000+ |
| Git 提交数 | 14 |
| 开发周期 | 2026-08-03 (1天) |

### 模块清单

1. 项目骨架 ✅
2. core/ ✅
3. utils/ ✅
4. storage/ ✅
5. preprocess/ ✅
6. engine/ ✅
7. Security Agent ✅ (40 tests, 89%)
8. Conflict Agent ✅ (57 tests, 87%)
9. Migration Agent ✅ (40 tests, 88%)
10. Reporter Agent ✅ (18 tests, 84%)
11. Integrations ✅ (25 tests, 87%)
12. API + Webhook ✅ (40 tests)
13. Celery Tasks ✅ (14 tests)
14. CLI + 集成测试 ✅ (4 tests)

> **最后更新**: 2026-08-03
- [ ] Module 15-18: 交付与测试

---

> **最后更新**: 2026-08-03

---

## 2026-08-24 — 文档：架构图解同步

- **类型**: 文档
- **内容**:
  - 创建 `docs/architecture-overview.md`：面向非技术读者的架构图解（Mermaid 全景图 + 逐层通俗解释 + 三个关键设计 + 图↔代码目录对照表）
  - `docs/specs/codeguard-v0.1-design-spec.md`：新增 §1.2「架构图解（Mermaid 全景图）」，原 1.2/1.3 顺延为 1.3/1.4；图与 architecture-overview.md 保持一致并注明同步约定
  - `README.md`：Architecture 章节在原有 ASCII 图后追加 Mermaid 全景图，并链接 architecture-overview.md
  - `ARCHITECTURE.md`：第七章文档索引登记 `docs/architecture-overview.md`
- **同步约定**: 3 处 Mermaid 图（README / architecture-overview / design-spec）保持一致，更新架构时需同步修改

> **最后更新**: 2026-08-24

---

## 2026-08-25 — 交付前审查修复（文档 / 依赖 / 扫描链路）

- **类型**: 修复 / 文档 / 规则
- **内容**:
  - **文档漂移修复**：`ARCHITECTURE.md` 将 `src/web/` 标注为「规划中, MVP 未实现」并删除失效的 `docs/guides/setup-guide.md` 索引；`PROJECT_RULES.md` 追加 `src/web/` 现状说明（仅追加，未改正文）；`README.md` 修正 Semgrep 规则表述（`config/semgrep/` 为自定义规则目录）
  - **依赖声明修复**：`pyproject.toml` 补 `tree-sitter-python`（`src/preprocess/parser.py` 硬依赖，此前 `pip install -e .` 装不出）、移除冗余 `openai`（`llm_client` 用 httpx 直连）；`Dockerfile` 增加「与 pyproject dependencies 保持同步」注释
  - **补 3 个 ADR**：`docs/adr/ADR-001-security-chain-zero-llm.md`、`ADR-002-hybrid-orchestration.md`、`ADR-003-four-agents-selection.md`（此前 PROJECT_RULES 强制要求但目录为空）
  - **Semgrep 扫描链路修复（含真实取证）**：
    - 新增 `config/semgrep/codeguard-rules.yml`（3 条自定义规则：hardcoded-secret / SQL 拼接 / hmac 不安全比较），`config/semgrep/` 从空目录变为真实规则库
    - `src/agents/security/code_scanner.py`：`--config auto` → `--config config/semgrep`（修复新版 semgrep「auto 与 metrics off 冲突」+ 离线确定性输出）
    - `src/utils/sandbox.py`：Windows 下子进程环境补齐 `SystemRoot/TEMP/USERPROFILE` 等系统变量（修复 semgrep `socketpair` rc=2 与 `Could not determine home directory` 两个运行时错误）
    - **实测取证**：对含 SQL 注入 / 硬编码密钥靶点的仓库全链路扫描，命中 2 条 `python-sql-string-concat`，`overall_blocking=true`（阻断生效），`degraded=false`
  - **测试**：`tests/unit/test_tasks/test_analysis.py` 修复 pytest-asyncio unclosed event loop 警告（改用显式管理 loop 测试嵌套分支）
- **验证**: 全量 pytest **268 passed**（warnings 3→2，剩余为第三方库警告）；commit 数实测 30 并同步 README/HANDOFF

> **最后更新**: 2026-08-25

---

## 2026-08-25 — 自举验证存档 + Semgrep 规则精度修复（追加）

- **类型**: 修复 / 验证
- **内容**:
  - **自举扫描存档**：用 CodeGuard 扫描自身（156 文件），结果存档 `docs/verification/self-scan-2026-08-25.json`，复现说明见 `docs/verification/README.md`（对应 PROJECT_RULES §18.3 自举闭环）
  - **规则精度修复（自举扫描发现）**：
    - 初版扫描误报 13 条 `python-sql-string-concat`——规则中 `$CONN.execute($QUERY)` 模式过宽，误匹配参数化安全查询（如 `audit_log.py`）
    - 收紧规则：删除过宽模式，仅保留明确拼接模式（`"..." + $VAR`、`f"...{$VAR}"`）
    - `code_scanner._parse_semgrep_output`：新增严重度映射 `ERROR→high / WARNING→medium / INFO→low`（此前 Semgrep `error` 永不触发阻断，为真实缺陷）
    - 测试同步：`test_scanners.py` 两处 severity 断言 `error`→`high`
  - **修复后复扫**：误报清零（零误报、零阻断）；靶点仓库的 2 条真实 SQL 拼接仍可命中——规则"能抓真、不误伤"
- **验证**: `tests/unit/test_agents/test_security/` 40 passed

> **最后更新**: 2026-08-25

---

## 2026-08-25 — 自定义规则置信度分类 + 演示仓库（追加）

- **类型**: 修复 / 工具
- **内容**:
  - `code_scanner.py`：自定义规则 ID（`config.semgrep.*`）纳入 `HIGH_CONFIDENCE_RULES`，`python-hardcoded-secret` / `python-sql-string-concat` 加入 `ALWAYS_BLOCKING_RULES`——此前自定义规则全部落 medium 置信度、被豁免规则 auto-waive 不阻断（真实缺口）
  - 新建演示仓库 `C:\Users\86186\codeguard_demo`（5 个真实漏洞：3 处 SQL 拼接 / 硬编码密钥 / 非恒定时间 HMAC 比较），供演示与自查使用
  - **演示实测**：`python -m src.cli.main analyze C:\Users\86186\codeguard_demo --no-migration` → **Blocking 2 / Warnings 1 / MERGE BLOCKED**，7s 出结果
- **验证**: `tests/unit/test_agents/test_security/` 40 passed

> **最后更新**: 2026-08-25

---

## 2026-08-26 — 修复 semgrep 依赖 PATH 导致扫描降级（追加）

- **类型**: 修复
- **内容**:
  - **现象**：双击 `run-demo.bat`（cmd 环境）扫描立即降级 `Semgrep SDK failed; results may be incomplete`（9ms），而 Git Bash 环境正常——根因是 `code_scanner` 以裸命令名 `semgrep` 调子进程，cmd 的 PATH 不含 venv `Scripts` 目录 → `FileNotFoundError` → 被 SDK 包装层捕获误报为 SDK 失败
  - **修复**：新增 `_locate_semgrep()`——`shutil.which("semgrep")` 优先，找不到时回退到 `sys.executable` 同级目录（venv Scripts 下的 `semgrep.exe`），不再依赖环境 PATH
  - **双保险**：`codeguard_demo/run-demo.bat` 增加 `set PATH=<venv Scripts>;%PATH%`
  - **验证**：在 PATH 完全不含 venv Scripts 的环境下复跑 → `degraded=False`、命中 3 条、**Blocking 2 / MERGE BLOCKED**
- **验证**: `tests/unit/test_agents/test_security/` 40 passed

> **最后更新**: 2026-08-26
