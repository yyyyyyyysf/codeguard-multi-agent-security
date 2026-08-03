"""Global exception handlers for FastAPI.

Maps all application exceptions (defined in src/core/errors.py)
to standardized JSON responses. Catches unhandled exceptions
with a 500 internal error response.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from src.core.errors import CodeGuardError


def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers on the FastAPI app."""

    @app.exception_handler(CodeGuardError)
    async def codeguard_error_handler(request: Request, exc: CodeGuardError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content=exc.to_dict(),
        )

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "TASK-003",
                    "message": f"Request validation failed: {str(exc)[:500]}",
                    "retryable": False,
                    "detail": {"errors": exc.errors()},
                }
            },
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "TASK-003",
                    "message": str(exc)[:500],
                    "retryable": False,
                    "detail": {},
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL-000",
                    "message": "Internal server error",
                    "retryable": True,
                    "detail": {},
                }
            },
        )
