# CodeGuard

**Multi-Agent Code Repository Security Analysis Platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![Tests](https://img.shields.io/badge/tests-239%20passed-brightgreen.svg)]()

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

## Quick Start

```bash
# Clone and setup
git clone https://github.com/your/codeguard
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

## Features

| Feature | Description |
|---------|-------------|
| CVE Scanning | 3-tier cache (Redis -> SQLite -> OSV API), direct/transitive classification |
| Code Security | Semgrep rules: hardcoded secrets, SQL injection, unsafe deserialization |
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
Tests:       239 passed
Agent coverage: 87% avg
Lines:       ~6,000 Python
Commits:     20
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
