"""Tests for CVE scanner and code scanner pure logic."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.security.agent import SecurityAuditAgent, _is_dep_manifest
from src.agents.security.code_scanner import CodeScanner
from src.agents.security.cve_scanner import CVEScanner


class TestIsDepManifest:
    """Tests for dependency manifest file detection."""

    def test_python_manifests(self):
        assert _is_dep_manifest("requirements.txt")
        assert _is_dep_manifest("pyproject.toml")
        assert _is_dep_manifest("setup.py")
        assert _is_dep_manifest("setup.cfg")
        assert _is_dep_manifest("poetry.lock")
        assert _is_dep_manifest("Pipfile")
        assert _is_dep_manifest("Pipfile.lock")

    def test_js_manifests(self):
        assert _is_dep_manifest("package.json")
        assert _is_dep_manifest("package-lock.json")
        assert _is_dep_manifest("yarn.lock")

    def test_java_manifests(self):
        assert _is_dep_manifest("pom.xml")
        assert _is_dep_manifest("build.gradle")
        assert _is_dep_manifest("build.gradle.kts")

    def test_non_manifests(self):
        assert not _is_dep_manifest("main.py")
        assert not _is_dep_manifest("app.js")
        assert not _is_dep_manifest("Dockerfile")
        assert not _is_dep_manifest("README.md")

    def test_pathed_manifests(self):
        """Filenames with directory prefixes."""
        assert _is_dep_manifest("subdir/requirements.txt")
        assert _is_dep_manifest("packages/backend/pyproject.toml")
        assert not _is_dep_manifest("src/main.py")


class TestBuildDepsFileMap:
    """Tests for building dependency -> file_location mapping."""

    def test_requirements_txt_mapping(self):
        changed_files = [
            {
                "path": "requirements.txt",
                "content": "fastapi==0.100.0\nrequests>=2.28.0\n# comment\nclick==8.1.0\n",
            },
        ]
        result = SecurityAuditAgent._build_deps_file_map(changed_files)
        assert result["fastapi"] == "requirements.txt:L1"
        assert result["requests"] == "requirements.txt:L2"
        assert result["click"] == "requirements.txt:L4"

    def test_mixed_manifests(self):
        changed_files = [
            {"path": "requirements.txt", "content": "django>=4.2\n"},
            {"path": "src/main.py", "content": "print('hello')"},  # Not a manifest
        ]
        result = SecurityAuditAgent._build_deps_file_map(changed_files)
        assert "django" in result
        assert result["django"] == "requirements.txt:L1"

    def test_empty_files(self):
        result = SecurityAuditAgent._build_deps_file_map([])
        assert result == {}


class TestCodeScannerHelpers:
    """Tests for code scanner static helper methods."""

    def test_should_scan_python(self):
        assert CodeScanner._should_scan("main.py", "python", [])
        assert not CodeScanner._should_scan("app.js", "python", [])
        assert not CodeScanner._should_scan("Dockerfile", "python", [])

    def test_should_scan_with_blacklist(self):
        assert not CodeScanner._should_scan(
            "tests/test_app.py", "python", ["test/", "tests/"]
        )
        assert not CodeScanner._should_scan(
            "src/docs/guide.py", "python", ["docs/"]
        )
        assert CodeScanner._should_scan(
            "src/main.py", "python", ["test/", "tests/"]
        )

    def test_parse_semgrep_output(self):
        scanner = CodeScanner()
        raw = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.detect-sql-injection",
                    "path": "app.py",
                    "start": {"line": 42},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Possible SQL injection",
                        "lines": 'query = f"SELECT * FROM users WHERE id={user_id}"',
                        "fix": "Use parameterized queries",
                    },
                },
            ],
        }
        issues = scanner._parse_semgrep_output(raw)
        assert len(issues) == 1
        assert issues[0]["rule_id"] == "python.lang.security.audit.detect-sql-injection"
        assert issues[0]["severity"] == "high"  # Semgrep ERROR mapped to high (blocking-capable)
        assert issues[0]["file_path"] == "app.py"
        assert issues[0]["line_number"] == 42
        assert issues[0]["confidence"] == "medium"  # Default before classifier

    def test_parse_empty_semgrep_output(self):
        scanner = CodeScanner()
        issues = scanner._parse_semgrep_output({"results": []})
        assert issues == []

    def test_parse_invalid_json(self):
        """Malformed JSON should return empty issues."""
        scanner = CodeScanner()
        issues = scanner._parse_semgrep_output({})
        assert issues == []


class TestCVEScannerAnnotate:
    """Tests for file location annotation on vulnerabilities."""

    def test_annotate_existing_locations(self):
        scanner = CVEScanner()
        vulns = [
            {"cve_id": "CVE-1", "package_name": "fastapi", "file_location": ""},
            {"cve_id": "CVE-2", "package_name": "requests", "file_location": ""},
        ]
        deps_map = {
            "fastapi": "requirements.txt:L1",
            "requests": "requirements.txt:L3",
        }
        result = scanner.annotate_file_locations(vulns, deps_map)
        assert result[0]["file_location"] == "requirements.txt:L1"
        assert result[1]["file_location"] == "requirements.txt:L3"

    def test_annotate_preserves_existing(self):
        """When deps_map has info, it takes priority (source of truth)."""
        scanner = CVEScanner()
        vulns = [
            {"cve_id": "CVE-1", "package_name": "fastapi"},
        ]
        deps_map = {"fastapi": "requirements.txt:L1"}
        result = scanner.annotate_file_locations(vulns, deps_map)
        # Deps map is authoritative - it overrides any pre-existing placeholder
        assert result[0]["file_location"] == "requirements.txt:L1"

    def test_annotate_unknown_package(self):
        """Package not in deps_map gets 'unknown'."""
        scanner = CVEScanner()
        vulns = [
            {"cve_id": "CVE-1", "package_name": "unknown_pkg", "file_location": ""},
        ]
        deps_map = {}
        result = scanner.annotate_file_locations(vulns, deps_map)
        assert result[0]["file_location"] == "unknown"


class TestCVEScannerWithMockCache:
    """CVEScanner tests with mocked cache."""

    @pytest.mark.asyncio
    async def test_scan_with_direct_deps(self):
        """CVE scan classifies direct + high CVSS as blocking."""
        mock_cache = MagicMock()
        mock_cache.lookup_batch = AsyncMock(return_value={
            "fastapi@0.100.0": [{
                "cve_id": "CVE-2024-0001",
                "severity": "high",
                "cvss_score": 8.5,
                "fixed_version": "0.105.0",
                "summary": "RCE in FastAPI",
                "evidence_source": "OSV",
                "evidence_url": "https://osv.dev/CVE-2024-0001",
                "affected_version_range": "<0.105.0",
            }],
            "requests@2.28.0": [],
        })

        scanner = CVEScanner()
        scanner._cache = mock_cache

        vulns, degraded, reason = await scanner.scan(
            [{"name": "fastapi", "version": "0.100.0", "ecosystem": "pypi"},
             {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"}],
        )
        assert len(vulns) == 1
        assert vulns[0]["blocking"]  # direct + high = block
        assert vulns[0]["fixed_version"] == "0.105.0"
        assert not degraded

    @pytest.mark.asyncio
    async def test_transitive_dep_non_blocking(self):
        """Transitive dependency with medium severity is not blocking."""
        mock_cache = MagicMock()
        mock_cache.lookup_batch = AsyncMock(return_value={
            "httpx@0.24.0": [{
                "cve_id": "CVE-2024-0002",
                "severity": "medium",
                "cvss_score": 5.0,
                "summary": "HTTP request smuggling",
                "evidence_source": "OSV",
                "fixed_version": "",
                "affected_version_range": None,
            }],
        })

        scanner = CVEScanner()
        scanner._cache = mock_cache

        vulns, degraded, reason = await scanner.scan(
            [],
            [{"name": "httpx", "version": "0.24.0", "ecosystem": "pypi"}],
        )
        assert len(vulns) == 1
        assert not vulns[0]["blocking"]  # transitive + medium = not blocking
        assert vulns[0]["dependency_type"] == "transitive"

    @pytest.mark.asyncio
    async def test_empty_deps_returns_empty(self):
        scanner = CVEScanner()
        vulns, degraded, reason = await scanner.scan([], [])
        assert vulns == []
        assert not degraded


class TestCodeScannerCLI:
    """CodeScanner tests with mocked CLI execution."""

    def test_scan_no_eligible_files(self, tmp_path):
        """No Python files -> no scan needed."""
        scanner = CodeScanner()
        # Create a temp dir with only non-python files
        (tmp_path / "README.md").write_text("# Readme")

        # Use async helper
        import asyncio
        async def run():
            issues, degraded, reason = await scanner.scan(
                str(tmp_path),
                [{"path": "README.md", "language": "markdown", "file_size": 10}],
                language="python",
            )
            return issues, degraded, reason

        issues, degraded, reason = asyncio.run(run())
        assert issues == []
        assert not degraded

    def test_blacklist_excludes_files(self, tmp_path):
        """Files in blacklisted paths are skipped."""
        scanner = CodeScanner()
        # Only test directories, no real files to scan
        (tmp_path / "tests").mkdir(exist_ok=True)
        (tmp_path / "tests" / "test_app.py").write_text("import os")

        import asyncio
        async def run():
            issues, degraded, reason = await scanner.scan(
                str(tmp_path),
                [{"path": "tests/test_app.py", "language": "python", "file_size": 10}],
                language="python",
                file_blacklist=["test/", "tests/"],
            )
            return issues, degraded, reason

        issues, degraded, reason = asyncio.run(run())
        assert issues == []  # Blacklisted, not scanned
        assert not degraded


class TestCodeScannerWithMockSandbox:
    """CodeScanner tests with mocked sandbox subprocess."""

    @pytest.mark.asyncio
    async def test_cli_scan_with_results(self, tmp_path):
        """Mock sandbox returns valid Semgrep JSON output."""
        (tmp_path / "app.py").write_text("import os\nquery = f'SELECT * FROM {x}'\n")

        scanner = CodeScanner()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"results":[{"check_id":"python.lang.security.audit.detect-sql-string","path":"app.py","start":{"line":2},"extra":{"severity":"ERROR","message":"SQL injection","lines":"query = f\'SELECT * FROM {x}\'","fix":"Use parameters"}}]}'
        mock_result.stderr = ""

        with patch("src.agents.security.code_scanner.run_tool_safely", return_value=(0, mock_result.stdout, "")):
            issues, degraded, reason = await scanner.scan(
                str(tmp_path),
                [{"path": "app.py", "language": "python", "file_size": 50}],
                language="python",
            )
            assert len(issues) == 1
            assert issues[0]["rule_id"] == "python.lang.security.audit.detect-sql-string"
            assert issues[0]["severity"] == "high"  # Semgrep ERROR mapped to high (blocking-capable)
            assert not degraded

    @pytest.mark.asyncio
    async def test_cli_scan_semgrep_failure(self, tmp_path):
        """Semgrep returns non-zero -> degraded."""
        (tmp_path / "app.py").write_text("x = 1")

        scanner = CodeScanner()
        with patch("src.agents.security.code_scanner.run_tool_safely", return_value=(1, "", "semgrep: command not found")):
            issues, degraded, reason = await scanner.scan(
                str(tmp_path),
                [{"path": "app.py", "language": "python", "file_size": 10}],
                language="python",
            )
            assert degraded
            assert "failed" in reason.lower()

    @pytest.mark.asyncio
    async def test_cli_scan_invalid_json(self, tmp_path):
        """Semgrep returns invalid JSON -> degraded."""
        (tmp_path / "app.py").write_text("x = 1")

        scanner = CodeScanner()
        with patch("src.agents.security.code_scanner.run_tool_safely", return_value=(0, "not json", "")):
            issues, degraded, reason = await scanner.scan(
                str(tmp_path),
                [{"path": "app.py", "language": "python", "file_size": 10}],
                language="python",
            )
            assert degraded
