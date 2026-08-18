"""Tests for the LLM HTTP client (integrations layer)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.errors import LLMTimeoutError
from src.integrations.llm_client import LLMClient


class TestLLMClient:
    def _client(self):
        return LLMClient(
            api_key="sk-test",
            model="deepseek-coder",
            base_url="https://api.deepseek.com",
            timeout=5,
        )

    @pytest.mark.asyncio
    async def test_complete_returns_content(self):
        client = self._client()

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "analysis result"}}]
        }
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client

        with patch("src.integrations.llm_client.httpx.AsyncClient", return_value=mock_client):
            content = await client.complete("analyze this")

        assert content == "analysis result"
        called_url = mock_client.post.await_args.args[0]
        assert called_url == "https://api.deepseek.com/v1/chat/completions"

    @pytest.mark.asyncio
    async def test_timeout_raises_llm_timeout_error(self):
        client = self._client()

        mock_client = AsyncMock()
        mock_client.post.side_effect = __import__("httpx").TimeoutException("slow")
        mock_client.__aenter__.return_value = mock_client

        with patch("src.integrations.llm_client.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(LLMTimeoutError):
                await client.complete("analyze this")
