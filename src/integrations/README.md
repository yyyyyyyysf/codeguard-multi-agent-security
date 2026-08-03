# Integrations Layer

## 定位

外部系统防腐层。所有第三方平台调用统一收口于此，彻底隔离业务逻辑与外部依赖。Agent 层、任务层仅调用本层接口，禁止直接依赖第三方 SDK 或发起 HTTP 请求。

## 子模块

### GitHub Client

PR 场景下的结果回写，是「自动阻断」能力的执行端。

**核心能力**：
- Check Runs 生命周期管理（queued → in_progress → completed）
- PR 评论创建/幂等更新
- 自动重试（429/5xx）+ 限流退避
- Token 环境变量注入，禁止硬编码

```python
async with GitHubClient() as gh:
    check = await gh.create_check_run("owner/repo", head_sha)
    await gh.update_check_run("owner/repo", check["id"], "completed", "failure")
    comment = await gh.create_pr_comment("owner/repo", pr_number, markdown_body)
```

### Webhook Sender

出站 Webhook 回调，支持对接企业内部系统（飞书/钉钉/Jira）。

**核心能力**：
- HMAC-SHA256 签名（X-CodeGuard-Signature-256 请求头）
- 指数退避重试（1s/3s/10s/30s/60s，最多 5 次）
- 5s 超时控制
- 失败日志留存，支持手动重发

```python
sender = WebhookSender(pre_shared_key="secret")
ok = await sender.send_event(
    "https://hooks.example.com/codeguard",
    "security.complete",
    scan_id="s1",
    payload={"blocking_count": 3},
)
```

## 支持的事件类型

| 事件 | 触发时机 |
|------|----------|
| `security.complete` | 安全扫描+冲突消解完成 |
| `migration.complete` | 迁移评估完成 |
| `analysis.complete` | 全量分析完成 |

## 边界约束

1. 仅做协议适配、API 封装、重试/限流/签名 —— 不包含任何业务判断
2. 外部故障时自动降级重试，不阻塞内部分析主流程
3. 所有外部调用留痕（日志 + 指标）
