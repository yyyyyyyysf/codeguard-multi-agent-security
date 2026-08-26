# CodeGuard

**Multi-Agent Code Repository Security Analysis Platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![Tests](https://img.shields.io/badge/tests-268%20passed-brightgreen.svg)]()
[![GitHub](https://img.shields.io/badge/GitHub-Repo-181717?logo=github&logoColor=white)](https://github.com/yyyyyyyysf/codeguard-multi-agent-security)

CodeGuard embeds automated security analysis into your CI/CD pipeline — blocking vulnerabilities at the PR level before they reach production.

## Architecture

```
GitHub Webhook -> FastAPI -> Celery -> Preprocess -> 4 AI Agents -> GitHub Check Runs
                                                          |
                              ┌───────────────────────────┼───────────────────────────┐
                              ▼                           ▼                           ▼
                       Security Audit             Conflict Resolution          Migration Assessment
                       (CVE + Semgrep)            (Auto-resolver +             (Breaking Changes
                       Zero LLM                    Human-in-the-loop)           + LLM-assisted)
                              │                           │                           │
                              └───────────────────────────┼───────────────────────────┘
                                                          ▼
                                                   Report Aggregation
                                                   (PR Comment + HTML)
```

**Full picture at a glance** (Mermaid, renders on GitHub):

```mermaid
flowchart TB
    subgraph SG1["① 触发：开发者提交代码"]
        A1["👨‍💻 开发者提交 PR"]
        A2["🐙 GitHub 代码平台"]
    end

    subgraph SG2["② 入口：系统接收请求"]
        B1["📡 Webhook 接收器"]
        B2["🖥️ API 服务（FastAPI）"]
        B3["📥 任务队列（Celery）"]
    end

    subgraph SG3["③ 预处理：读懂代码（纯规则，不用 AI）"]
        C1["📦 拉取代码"]
        C2["🧩 解析依赖和代码结构"]
        C3["📋 代码画像 CodeMetadata"]
    end

    subgraph SG4["④ 智能分析：4 个 Agent 协作"]
        D1["🔒 安全审计<br/>查 CVE 漏洞 + 风险代码<br/>纯规则 · 零 AI"]
        D2["⚖️ 冲突消解<br/>裁决：放行 or 阻断"]
        D3["🔄 迁移评估<br/>评估依赖升级风险<br/>AI 辅助"]
        D4["📝 报告聚合<br/>汇总结果，生成报告"]
        D5["👤 人工复核<br/>规则覆盖不了时介入"]
    end

    subgraph SG5["⑤ 结果反馈"]
        E1["💬 PR 评论提醒"]
        E2["🚫 阻断合并"]
        E3["📄 完整报告（JSON/HTML）"]
    end

    subgraph SG6["🧰 支撑数据（后台）"]
        F1["📚 漏洞数据库<br/>OSV + GitHub Advisory"]
        F2["🔎 扫描规则<br/>Semgrep"]
        F3["💾 本地存储<br/>Redis 缓存 + SQLite"]
        F4["🔌 GitHub 对接接口"]
    end

    A1 --> A2 --> B1 --> B2 --> B3 --> C1 --> C2 --> C3
    C3 --> D1
    C3 --> D3
    D1 --> D2
    D2 --> D5
    D2 --> E1
    D2 --> E2
    D3 --> D4
    D1 --> D4
    D4 --> E3
    F1 -. 查询漏洞 .-> D1
    F2 -. 规则扫描 .-> D1
    F3 -. 读写缓存 .-> C3
    F4 -. 执行阻断/回写 .-> E2
    F4 -. 回写评论 .-> E1
```

> A plain-language walkthrough of this diagram lives in [`docs/architecture-overview.md`](docs/architecture-overview.md).

## Quick Start

```bash
# Clone and setup
git clone https://github.com/yyyyyyyysf/codeguard-multi-agent-security.git
cd codeguard
cp .env.example .env
# REQUIRED: edit .env and set CODEGUARD_API_KEY, GITHUB_WEBHOOK_SECRET
# The API and webhook endpoints will reject requests until these are configured.

# Run with Docker
docker-compose up -d

# Or CLI mode (no server needed, no API key required)
python -m src.cli.main analyze ./my-project
python -m src.cli.main analyze ./my-project --target fastapi:0.100.0:0.110.0
```

### CLI options

| Option | Description |
|--------|-------------|
| `<repo>` | Required. Path to a local git repository (must contain `.git`) |
| `--no-migration` | Skip AI migration assessment (fast, no LLM key needed) |
| `--target <framework:from:to>` | Enable migration assessment, e.g. `fastapi:0.100.0:0.110.0` |
| `--json` | Print raw JSON instead of Markdown summary |
| `--output <path>` | Also save the full report as JSON to a file |
| `--scan-type full\|diff` | Full scan or diff-only (default: `full`) |
| `--branch <name>` | Branch to scan (default: `main`) |
| `--block-severity high\|critical` | Blocking threshold (default: `high`) |

Reports are persisted automatically to `$REPORT_STORAGE_DIR/<scan_id>/report.json` (+ `pr_comment.md`). See `docs/verification/demo-guide.md` for a full walkthrough.

## Features

| Feature | Description |
|---------|-------------|
| CVE Scanning | 3-tier cache (Redis -> SQLite -> OSV API), direct/transitive classification |
| Code Security | Semgrep (auto rule set, `config/semgrep/` reserved for custom rules): hardcoded secrets, SQL injection, unsafe deserialization |
| Auto-blocking | PR merge blocked until all `blocking=true` findings are resolved |
| Human-in-the-loop | Exemption appeals for edge cases, with audit trail |
| Migration Assessment | Breaking Changes detection (AST rules + LLM-assisted) |
| Zero-LLM Security | Security conclusions from deterministic rules + authoritative databases only |

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/analyze` | Submit analysis task |
| GET | `/api/v1/tasks/{id}` | Query task status |
| GET | `/api/v1/tasks/{id}/report` | Get full report |
| POST | `/api/v1/tasks/{id}/appeal` | Submit exemption appeal |
| GET | `/health` | Health check |
| POST | `/webhook/github` | GitHub webhook receiver |

## Project Stats

```
Modules:     14 completed
Tests:       268 passed
Agent coverage: 87% avg (statement coverage, 2026-08-25 re-verified)
Lines:       ~10,700 Python (wc -l, incl. comments)
Commits:     30
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI + Pydantic v2 |
| Async Tasks | Celery + Redis |
| Agent Orchestration | LangGraph (StateGraph + Checkpoint) |
| CVE Data | OSV API + GitHub Advisory Database |
| Code Analysis | Tree-sitter + Semgrep |
| LLM (auxiliary only) | DeepSeek-Coder |
| Storage | SQLite (MVP) + Redis |
| Deployment | Docker Compose |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run specific agent tests
python -m pytest tests/unit/test_agents/test_security/ -v
```
