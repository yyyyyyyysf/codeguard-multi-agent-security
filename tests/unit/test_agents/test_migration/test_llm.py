"""Tests for LLMAnalyzer prompt building and response parsing."""

from unittest.mock import patch

import pytest

from src.agents.migration.llm_analyzer import LLMAnalyzer


class TestLLMAnalyzerPrompt:
    def test_build_prompt_includes_breaking_changes(self):
        analyzer = LLMAnalyzer()
        prompt = analyzer._build_prompt(
            [{"path": "app.py", "content": "x = 1"}],
            [{"id": "BC-1", "description": "test", "deprecated_api": "foo", "affected_patterns": ["foo("], "migration_guide": "use bar"}],
            "fastapi", "0.100.0", "0.110.0",
        )
        assert "BC-1" in prompt
        assert "test" in prompt
        assert "foo(" in prompt
        assert "use bar" in prompt
        assert "app.py" in prompt
        assert "fastapi" in prompt

    def test_build_prompt_truncates_long_files(self):
        analyzer = LLMAnalyzer()
        long_content = "print('hello')\n" * 500
        prompt = analyzer._build_prompt(
            [{"path": "big.py", "content": long_content}],
            [{"id": "BC-1", "description": "x", "deprecated_api": "x", "affected_patterns": ["x"], "migration_guide": ""}],
            "f", "1.0", "2.0",
        )
        # Content should be truncated to 2000 chars
        assert len([line for line in prompt.split("\n") if "print" in line]) < len(long_content.split("\n"))

    def test_build_prompt_handles_diff_lines(self):
        analyzer = LLMAnalyzer()
        prompt = analyzer._build_prompt(
            [{"path": "app.py", "content": None, "diff_lines": "@@ -1 +1 @@\n-old\n+new"}],
            [{"id": "BC-1", "description": "x", "deprecated_api": "x", "affected_patterns": ["x"], "migration_guide": ""}],
            "f", "1.0", "2.0",
        )
        assert "old" in prompt
        assert "new" in prompt

    def test_build_prompt_limited_to_50_files(self):
        analyzer = LLMAnalyzer()
        files = [{"path": f"file{i}.py", "content": f"print({i})"} for i in range(100)]
        bc = [{"id": "BC-1", "description": "x", "deprecated_api": "x", "affected_patterns": ["x"], "migration_guide": ""}]
        prompt = analyzer._build_prompt(files, bc, "f", "1.0", "2.0")
        # Should have at most 50 file references
        assert prompt.count("###") <= 50


class TestLLMAnalyzerParsing:
    def test_parse_valid_json_response(self):
        analyzer = LLMAnalyzer()
        raw = '{"findings": [{"change_id": "BC-1", "affected_files": [{"path": "a.py", "line_number": 42, "impact_level": "breaking"}]}]}'
        results = analyzer._parse_response(raw, [
            {"id": "BC-1", "description": "test", "migration_guide": "fix it", "official_url": "https://x.com"},
        ])
        assert len(results) == 1
        assert results[0]["source"] == "llm_analysis"
        assert results[0]["affected_files"][0]["path"] == "a.py"

    def test_parse_markdown_wrapped_json(self):
        analyzer = LLMAnalyzer()
        raw = '```json\n{"findings": [{"change_id": "BC-1", "affected_files": []}]}\n```'
        results = analyzer._parse_response(raw, [
            {"id": "BC-1", "description": "test", "migration_guide": ""},
        ])
        assert len(results) == 0  # No affected files, so filtered out

    def test_parse_plain_markdown_wrapped(self):
        analyzer = LLMAnalyzer()
        raw = '```\n{"findings": [{"change_id": "BC-1", "affected_files": [{"path": "b.py", "line_number": 1}]}]}\n```'
        results = analyzer._parse_response(raw, [
            {"id": "BC-1", "description": "test", "migration_guide": ""},
        ])
        assert len(results) == 1

    def test_parse_invalid_json_returns_empty(self):
        analyzer = LLMAnalyzer()
        results = analyzer._parse_response("not json", [{"id": "x"}])
        assert results == []

    def test_parse_filters_unknown_change_ids(self):
        """LLM-invented change IDs are discarded."""
        analyzer = LLMAnalyzer()
        raw = '{"findings": [{"change_id": "IMAGINARY-BC", "affected_files": [{"path": "x.py", "line_number": 1}]}]}'
        results = analyzer._parse_response(raw, [
            {"id": "BC-1", "description": "real"},
        ])
        assert results == []  # IMAGINARY-BC not in known list -> discarded

    def test_parse_empty_findings(self):
        analyzer = LLMAnalyzer()
        results = analyzer._parse_response('{"findings": []}', [{"id": "BC-1"}])
        assert results == []


class TestLLMAnalyzerNoKey:
    @pytest.mark.asyncio
    async def test_no_api_key_returns_empty(self):
        """Without API key, analyze() returns empty immediately."""
        analyzer = LLMAnalyzer(api_key="")  # No key
        results = await analyzer.analyze(
            [{"path": "a.py", "content": "x"}],
            [{"id": "BC-1", "description": "test"}],
        )
        assert results == []

    @pytest.mark.asyncio
    async def test_no_breaking_changes_returns_empty(self):
        analyzer = LLMAnalyzer(api_key="sk-test")
        results = await analyzer.analyze(
            [{"path": "a.py", "content": "x"}],
            [],
        )
        assert results == []

    @pytest.mark.asyncio
    async def test_llm_timeout_returns_empty(self):
        """LLM timeout -> degrade gracefully."""
        analyzer = LLMAnalyzer(api_key="sk-test")
        with patch.object(analyzer, "_call_llm", side_effect=Exception("timeout")):
            results = await analyzer.analyze(
                [{"path": "a.py", "content": "x"}],
                [{"id": "BC-1", "description": "test"}],
            )
            assert results == []  # Degrade, not crash
