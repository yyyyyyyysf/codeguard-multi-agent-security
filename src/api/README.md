# API + Webhook Layer

## 定位

系统入站网关——所有外部请求统一由此进入。FastAPI REST API + GitHub Webhook 接收。

## 端点总览

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/analyze` | 提交分析任务（异步，返回 202 + task_id） |
| GET | `/api/v1/tasks/{task_id}` | 查询任务状态与进度 |
| GET | `/api/v1/tasks/{task_id}/report` | 获取完整报告（?format=json\|html） |
| POST | `/api/v1/tasks/{task_id}/appeal` | 提交豁免申诉（人在回路入口） |
| GET | `/api/v1/tasks/{task_id}/appeals` | 查询申诉状态 |
| GET | `/api/v1/rules` | 豁免规则列表 |
| PUT | `/api/v1/rules/{rule_id}` | 更新规则（v0.2） |
| GET | `/health` | 健康检查（Redis 连通性） |
| POST | `/webhook/github` | GitHub Webhook 接收 |

## Webhook 签名校验

GitHub Webhook 使用 HMAC-SHA256 校验：
1. 配置环境变量 `GITHUB_WEBHOOK_SECRET`
2. GitHub 在 `X-Hub-Signature-256` 请求头携带 `sha256=<hmac>`
3. 校验失败返回 401，成功则立即返回 200，异步投递任务

## 中间件

| 中间件 | 说明 |
|--------|------|
| RequestLogMiddleware | 结构化请求日志（方法/路径/状态码/耗时） |
| RateLimitMiddleware | IP+Key 双层限流（默认关闭，`RATE_LIMIT_ENABLED=true` 开启） |
| ErrorHandler | 统一异常→JSON 映射（CodeGuardError/ValidationError/Exception→标准格式） |

## 认证

MVP：静态 API Key（`X-API-Key` 请求头 + `CODEGUARD_API_KEY` 环境变量）
v1.0：OAuth 2.0

## 入口层边界约束

1. 不承载任何分析/裁决类业务逻辑
2. 禁止直接调用 Agent 层或预处理层
3. 所有同步接口响应 < 200ms（长耗时任务全部异步投递 Celery）
