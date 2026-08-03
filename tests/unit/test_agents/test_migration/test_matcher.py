"""Tests for ChangelogMatcher — deterministic pattern matching."""

import pytest
from src.agents.migration.changelog_matcher import ChangelogMatcher


class TestChangelogMatcher:
    @pytest.fixture
    def matcher(self):
        return ChangelogMatcher()

    def test_match_response_model_pattern(self, matcher):
        """'response_model=' pattern matches code using it."""
        files = [
            {
                "path": "api/user.py",
                "content": "@app.get('/users', response_model=List[User])\n"
                           "async def get_users():\n    return await db.all()\n",
                "language": "python",
            },
        ]
        impacts = matcher.match(files, "fastapi", "0.100.0", "0.110.0")
        assert len(impacts) >= 1
        # Find the response_model impact
        response_impacts = [i for i in impacts if "response_model" in i["change_desc"].lower()]
        assert len(response_impacts) >= 1
        assert response_impacts[0]["source"] == "ast_rule"
        assert len(response_impacts[0]["affected_files"]) >= 1

    def test_match_on_event_pattern(self, matcher):
        files = [
            {
                "path": "main.py",
                "content": "@app.on_event('startup')\nasync def startup():\n    pass\n",
                "language": "python",
            },
        ]
        impacts = matcher.match(files, "fastapi", "0.100.0", "0.110.0")
        on_event_impacts = [i for i in impacts if "on_event" in i["change_desc"].lower()]
        assert len(on_event_impacts) >= 1

    def test_match_get_openapi_import(self, matcher):
        files = [
            {
                "path": "utils/openapi.py",
                "content": "from fastapi.openapi.utils import get_openapi\n\n"
                           "schema = get_openapi(title='My App', version='1.0', routes=[])\n",
                "language": "python",
            },
        ]
        impacts = matcher.match(files, "fastapi", "0.100.0", "0.110.0")
        openapi_impacts = [i for i in impacts if "OpenAPI" in i["change_desc"]]
        assert len(openapi_impacts) >= 1

    def test_no_match_for_unrelated_code(self, matcher):
        files = [
            {
                "path": "utils/helpers.py",
                "content": "def add(a, b):\n    return a + b\n",
                "language": "python",
            },
        ]
        impacts = matcher.match(files, "fastapi", "0.100.0", "0.110.0")
        assert impacts == []

    def test_no_target_version_no_match(self, matcher):
        files = [{"path": "app.py", "content": "@app.get('/')", "language": "python"}]
        impacts = matcher.match(files, "", "", "")
        assert impacts == []

    def test_impact_level_classification(self, matcher):
        """Patterns with decorators/imports are 'breaking', others are 'warning'."""
        assert matcher._determine_impact("@app.get") == "breaking"
        assert matcher._determine_impact("from x import y") == "breaking"
        assert matcher._determine_impact("response_model=") == "breaking"
        assert matcher._determine_impact("some_func(") == "breaking"

    def test_is_code_file(self, matcher):
        assert matcher._is_code_file("src/main.py")
        assert matcher._is_code_file("app.js")
        assert matcher._is_code_file("lib.rs")
        assert not matcher._is_code_file("config.yaml")
        assert not matcher._is_code_file("README.md")
        assert not matcher._is_code_file("Dockerfile")

    def test_multiple_patterns_in_one_file(self, matcher):
        """File with both response_model and on_event -> both detected."""
        files = [
            {
                "path": "api/v1.py",
                "content": (
                    "@app.get('/x', response_model=Item)\n"
                    "async def get_x(): pass\n"
                    "@app.on_event('startup')\n"
                    "async def startup(): pass\n"
                ),
                "language": "python",
            },
        ]
        impacts = matcher.match(files, "fastapi", "0.100.0", "0.110.0")
        assert len(impacts) >= 1  # At least one found

    def test_skip_non_code_files(self, matcher):
        """YAML config files are skipped."""
        files = [
            {
                "path": "config.yaml",
                "content": "response_model: MyModel\n",
                "language": "yaml",
            },
        ]
        impacts = matcher.match(files, "fastapi", "0.100.0", "0.110.0")
        assert impacts == []  # Non-code file skipped
