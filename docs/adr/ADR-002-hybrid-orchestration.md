# ADR-002: 混合编排——安全 DAG + 辅助事件驱动（Hybrid Orchestration）

> **状态**: 已接受（2026-08-03）
> **关联**: PROJECT_RULES.md §5.3, docs/specs/codeguard-v0.1-design-spec.md

## 问题背景

4 个 Agent 需要被调度，但它们的约束完全不同：

- **安全审计 → 冲突消解**：严格串行依赖，冲突消解必须拿到安全审计的完整输出才能裁决，且是关键路径（SLA ≤ 3s）
- **迁移评估**：与安全链无数据依赖，可以并行；失败不应影响安全输出
- **报告聚合**：等各链路结果到达后统一聚合

需要一个编排方案，同时满足"关键路径确定性强"和"辅助链路可扩展"。

## 现状痛点

- 单一线性编排：迁移评估拖慢安全链路，且不可扩展
- 纯事件驱动：安全链路的时序依赖无法保证，难以满足 3s SLA
- 纯 DAG：所有节点都要显式连接，辅助分析（后续可加更多）改一处动全链

## 可选方案

| 方案 | 说明 |
|------|------|
| A. 纯线性流水线 | Agent 依次串行执行 |
| B. 纯事件驱动（Pub/Sub） | 所有 Agent 订阅事件、异步协作 |
| C. **混合（最终选择）** | 安全链用 LangGraph StateGraph 严格 DAG；辅助链用 Redis Pub/Sub 事件驱动 |

## 方案对比

| 维度 | A 线性 | B 事件驱动 | C 混合 |
|------|--------|-----------|--------|
| 关键路径 SLA 保障 | ✓ 但被辅助拖慢 | ✗ 时序不确定 | ✓ DAG 严格时序 |
| 辅助链路扩展性 | ✗ 改全链 | ✓ 订阅即接入 | ✓ 事件驱动扩展 |
| 数据一致性（迁移不进安全裁决） | ✗ 易耦合 | ✓ 天然隔离 | ✓ 双链路隔离 |
| 人在回路（Checkpoint） | ✗ 难暂停 | ✗ 难恢复 | ✓ LangGraph Checkpoint |

## 最终决策

**采用方案 C：安全主链路 LangGraph StateGraph（Security → Conflict，严格 DAG）；辅助链路 Redis Pub/Sub（`code_metadata.ready` → Migration）；报告聚合订阅 `security.complete` / `migration.complete` 事件。**

关键约束（写入 PROJECT_RULES §5.3）：
1. **安全主链路不可旁路**：任何故障/降级不得绕过安全判断
2. **迁移结果永不进入安全决策**：数据一致性靠链路隔离保证
3. **安全结果前置阻断**：冲突消解裁决后直接走 integrations 层执行阻断，不经报告聚合中转

## 落地影响

- 安全链路端到端（Webhook → 阻断）目标 ≤ 3s，不受迁移评估影响
- 新增辅助分析 Agent = 订阅一个事件，不改安全链
- 人在回路（HITL）通过 LangGraph Checkpoint 暂停/恢复，可断点续跑

## 实施步骤

1. `src/engine/orchestrator.py`：Agent 注册 + run_analysis 编排 ✅
2. `src/engine/event_bus.py`：Redis Pub/Sub 事件（code_metadata.ready / security.complete / migration.complete / analysis.complete）✅
3. Conflict Agent 重构为编译后的 LangGraph StateGraph + interrupt_before（commit a40ba54）✅

## 遗留问题

- Celery 任务层与 Orchestrator 双编排入口并存，需明确职责边界（tasks/analysis.py 为 Web/API 路径，CLI 走 Orchestrator）
- 事件在 Redis 不可用时降级为进程内订阅（EventBus 已实现 best-effort）
