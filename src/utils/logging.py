"""Structured logging configuration using structlog.

Provides a consistent logging setup across all modules.
Outputs JSON to stdout (production) or colored console (development).

Usage:
    from src.utils.logging import get_logger
    logger = get_logger(__name__)
    logger.info("scan_completed", scan_id="abc", duration_ms=1200)
"""

from __future__ import annotations

import logging
import os
import sys

import structlog

LOG_LEVEL = os.getenv("CODEGUARD_LOG_LEVEL", "INFO")
LOG_ENV = os.getenv("CODEGUARD_ENV", "development")


def setup_logging() -> None:
    """Configure structlog for the entire application.

    Called once at application startup (src/api/app.py or src/tasks/celery_app.py).
    """
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    # Determine renderer
    if LOG_ENV == "production":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    # Shared processors
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    structlog.configure(
        processors=shared_processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging to route through structlog
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    # Remove existing handlers to avoid duplicate output
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "git.cmd", "urllib3", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger for the given module name."""
    return structlog.get_logger(name)
