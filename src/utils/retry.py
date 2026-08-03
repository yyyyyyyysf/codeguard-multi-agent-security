"""Exponential backoff retry utilities.

Usage as decorator:
    @retry(max_attempts=3, backoff=[1, 3, 10])
    def flaky_function():
        ...

Usage as wrapper:
    result = retry_call(flaky_function, max_attempts=3)
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable
from typing import Any, TypeVar

from src.core.errors import CodeGuardError

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_BACKOFF = [1, 3, 10, 30, 60]
DEFAULT_MAX_ATTEMPTS = 5


def retry(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff: list[float] | None = None,
    retryable_exceptions: tuple[type[Exception], ...] = (CodeGuardError,),
) -> Callable[[F], F]:
    """Decorator: retry a function with exponential backoff.

    Only retries if the raised exception has retryable=True
    (for CodeGuardError subclasses) or is in retryable_exceptions.

    Args:
        max_attempts: Maximum number of attempts (including the first).
        backoff: List of delays in seconds between attempts.
        retryable_exceptions: Exception types to retry on.

    Returns:
        Decorated function.
    """
    delays = backoff or DEFAULT_BACKOFF

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception: Exception | None = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    # Check retryable flag for CodeGuardError
                    if isinstance(e, CodeGuardError) and not e.retryable:
                        raise

                    if attempt >= max_attempts:
                        raise

                    delay = delays[min(attempt - 1, len(delays) - 1)]
                    time.sleep(delay)
                except Exception:
                    # Non-retryable exception: re-raise immediately
                    raise

            # Should never reach here, but satisfy type checker
            assert last_exception is not None
            raise last_exception

        return wrapper  # type: ignore[return-value]

    return decorator


def retry_call(
    func: Callable[..., Any],
    *args: Any,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff: list[float] | None = None,
    **kwargs: Any,
) -> Any:
    """Call a function with retry semantics (non-decorator form)."""
    decorated = retry(max_attempts=max_attempts, backoff=backoff)(func)
    return decorated(*args, **kwargs)
