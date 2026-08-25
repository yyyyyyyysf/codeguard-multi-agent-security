# CodeGuard 项目交接文档

> **写给下一个会话的 Claude**：这份文档是你在新会话中理解项目全貌、接续工作的唯一入口。请先通读全文，再对照项目文件进行验证。

---

## 一、我们是谁，在做什么

**用户背景**：方向「AI 应用与智能体开发」（非算法岗），纯 Python 技术栈，不会 Java。

**项目定位**：CodeGuard —— 一个多 Agent 协作的代码库智能分析平台。核心价值是嵌入 GitHub CI/CD 工作流，在开发者提交 PR 时自动扫描安全漏洞和框架升级风险，发现高危问题直接阻止合并。不是「事后出 PDF 报告」的工具，而是「风险发生点自动拦截」。

**项目路径**：`C:\Users\86186\codeguard`

**项目文档**（开发前必读）：
- `PROJECT_RULES.md` — 唯一权威开发规范，20 章，所有开发行为以此为准
- `ARCHITECTURE.md` — 系统架构总览
- `docs/specs/codeguard-v0.1-design-spec.md` — 完整设计规格文档
- `DEVELOPMENT_LOG.md` — 开发日志

---

## 二、已经完成了什么

### 整体进度：14 个模块全部开发完成，268 个测试通过

| 阶段 | 模块 | 状态 | 说明 |
|------|------|:----:|------|
| Phase 1 | 项目骨架 + core/ + utils/ | ✅ | pyproject.toml, Docker Compose, .env, 目录结构, 异常体系, 枚举, 常量, Git/HMAC/重试/日志/沙箱 |
| Phase 2 | storage/ + preprocess/ + engine/ | ✅ | CVE三级缓存, OSV/GitHub Advisory客户端, 审计日志(链式哈希), 规则存储, 依赖解析, Tree-sitter AST, BaseAgent, EventBus, Orchestrator |
| Phase 3 | 安全审计 Agent | ✅ | 40 tests, 89% 覆盖, 零 LLM, CVE 扫描 + Semgrep 代码规则 |
| Phase 3 | 冲突消解 Agent | ✅ | 57 tests, 87% 覆盖, 零 LLM, 5 条裁决规则 + LangGraph StateGraph 人在回路 |
| Phase 4 | 迁移评估 Agent | ✅ | 40 tests, 88% 覆盖, AST 规则 + LLM 辅助(边界约束) |
| Phase 4 | 报告聚合 Agent | ✅ | 18 tests, 84% 覆盖, Jinja2 模板, 安全优先分级输出 |
| Phase 4.5 | Integrations 层 | ✅ | 25 tests, 87% 覆盖, GitHub Client + Webhook Sender |
| Phase 5 | API + Webhook 层 | ✅ | 40 tests, FastAPI 9 端点 + HMAC 签名校验 + 幂等 |
| Phase 5.5 | Celery 任务层 | ✅ | 14 tests, 6 类核心任务, 全链路编排 |
| Phase 6 | CLI + 集成测试 + README | ✅ | Typer CLI, 4 integration tests, 项目首页 |

### 测试总计：268 tests collected（实测 pytest 全量），Agent 层平均覆盖率 87%

```
Security Agent:  40 tests, 89%
Conflict Agent:  57 tests, 87%
Migration Agent: 40 tests, 88%
Reporter Agent:  18 tests, 84%
Integrations:    25 tests, 87%
API + Webhook:   40 tests
Tasks:           14 tests
Integration:      4 tests
─────────────────────────
Total:          268 tests
```
> 注：上表仅列核心模块明细，其余测试来自 storage/preprocess/engine/webhook/monitoring 等模块，全量实测 268 tests（2026-08-24 pytest 全量跑通）。

### Git 历史：30 commits（2026-08-25 实测），线性历史，规范化提交

---

## 三、当前进展到哪，还存在什么问题

### 当前状态：核心代码全部完成，

### 上次修复（commit a40ba54）：7 项代码质量修复

1. ConflictAgent 重构为真正 LangGraph StateGraph（编译后的 graph + ainvoke + interrupt_before）
2. Webhook GitHub handler 完成 Celery dispatch
3. 监控指标埋点（metrics.py 文件本身）
4. 配置驱动的语言过滤（LANGUAGE_EXTENSIONS dict 替代硬编码 if language=="python"）
5. 消灭静默吞错（cve_cache/orchestrator/event_bus 全部加 logger.warning）
6. repo.py 兼容无 remote 的本地仓库
7. cve_cache.py Redis 写失败日志

---

## 四、关键设计决策（不可随意推翻）

这些决策经过了多轮讨论和用户确认，新会话中除非用户明确要求，否则不要改动：

1. **安全链路零 LLM**——安全审计和冲突消解两个 Agent 绝对不能引入 LLM 调用。这是合规硬约束，不是性能优化
2. **4 个 Agent，不多不少**——用户亲自否定了「更多 Agent」的方案，用「数据源独立+推理策略独立+降级路径独立」三个标准精筛到 4 个
3. **Webhook 为核心交互形态**——用户明确提出「企业为风险控制能力付费，不为事后报告付费」
4. **混合编排**——安全 DAG（LangGraph）+ 辅助事件驱动（Redis Pub/Sub），用户拍板
5. **LLM 只在迁移评估中做辅助**——Prompt 约束 + JSON 输出校验 + source 标记三层防护
6. **所有外部调用必须走 integrations 层**——Agent 层不直接调 GitHub API/外部 HTTP

---

## 五、用户的工作风格

了解这些可以让新会话更高效地配合用户：

1. **先设计后编码**——用户拒绝「直接写代码」，要求先出设计、逐个 Section 评审确认、再动手。我们花了很长的讨论时间在 7 个 Section 设计上
2. **重产品思维**——用户对「企业为什么买单」「方案对外怎么呈现」的思考深度远超常规。每个技术决策都要能讲出商业价值
3. **拒绝浮夸**——用户多次纠正「精通」「75% 响应率」这类营销话术，要求数据可验证
4. **要求讲大白话**——用户明确要求「用零基础小白也能听懂的话解释技术」，这是对外讲解时的通用要求
5. **关注对外呈现**——所有讨论最终都落到「项目怎么介绍、方案怎么讲解」
6. **决策速度快**——一旦理解方案优劣，能迅速拍板，不纠结。Agent 数量、编排架构、技术栈都是在充分讨论后一次性敲定的

---

## 六、项目运行方式

### CLI 模式（零配置，立即可用）
```bash
cd C:\Users\86186\codeguard
python -m src.cli.main analyze .                           # 基础分析
python -m src.cli.main analyze . --target fastapi:0.100.0:0.110.0  # 含迁移评估
python -m src.cli.main analyze . --json                     # JSON 输出
```

### Web API 模式
```bash
uvicorn src.api.app:create_app --host 0.0.0.0 --port 8000 --factory
# 浏览器打开 http://localhost:8000/docs 调试 API
```

### Docker Compose 模式
```bash
docker compose up -d --build
```

### 跑测试（测试文件有同名冲突，需逐个目录跑）
```bash
python -m pytest tests/unit/test_agents/test_security/ -v
python -m pytest tests/unit/test_agents/test_conflict/ -v
python -m pytest tests/unit/test_agents/test_migration/ -v
python -m pytest tests/unit/test_agents/test_reporter/ -v
python -m pytest tests/unit/test_integrations/ -v
python -m pytest tests/unit/test_api/ tests/unit/test_webhook/ -v
python -m pytest tests/unit/test_tasks/ -v
python -m pytest tests/integration/ -v
```

---

## 七、记忆文件索引

以下 5 个记忆文件已写入用户目录，新会话会自动加载：

| 文件 | 内容 |
|------|------|
| `codeguard-project-context.md` | 项目定位、技术栈、Agent 角色 |
| `codeguard-agent-role-design.md` | 4 Agent 权责边界、LLM 使用边界、用户的设计贡献 |
| `codeguard-dev-process-rules.md` | 10 条模块完成标准、用户要求的开发流程 |
| `codeguard-audit-findings-2026-08-06.md` | 最近一次审查的结论和待修复问题 |
| `codeguard-lessons-learned.md` | 讲解口径、用户关键反馈、踩坑记录 |

---

> **给接手的新会话**：先读 PROJECT_RULES.md（开发规范）和 ARCHITECTURE.md（架构总览），。用户风格是「先设计后编码、重产品思维、拒绝浮夸、要求可验证的数据」——做任何改动前先出方案让他确认。
