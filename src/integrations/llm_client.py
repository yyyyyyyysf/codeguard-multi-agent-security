"""LLM HTTP client — the ONLY place the agent layer talks to an LLM API.

Architecture rule (PROJECT_RULES): all external HTTP calls must go
through the integrations layer. Agents must never call httpx/requests
directly. This module wraps the OpenAI-compatible chat completions
endpoint (DeepSeek by default) with timeout + error normalization.
"""

from __future__ import annotations

from typing import Any

import httpx

from src.core.errors import LLMTimeoutError


class LLMClient:
    """Thin HTTP wrapper around an OpenAI-compatible chat endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str,
        timeout: int = 30,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    async def complete(self, prompt: str) -> str:
        """Send a chat completion request and return the message content."""
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,  # Low temp for deterministic analysis
            "max_tokens": 4096,
            "stream": False,
        }

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self._timeout)) as client:
                response = await client.post(
                    f"{self._base_url}/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except httpx.TimeoutException as e:
            raise LLMTimeoutError(
                f"LLM analysis timed out after {self._timeout}s",
                retryable=True,
            ) from e
        except httpx.HTTPStatusError as e:
            raise Exception(f"LLM API error {e.response.status_code}") from e
