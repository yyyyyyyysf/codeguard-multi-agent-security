"""Tests for API request/response schemas (Pydantic validation)."""

import pytest
from pydantic import ValidationError

from src.api.schemas.request import AnalyzeRequest, AppealRequest


class TestAnalyzeRequest:
    def test_minimal_valid(self):
        req = AnalyzeRequest(repo_url="https://github.com/user/repo")
        assert req.scan_type == "diff"
        assert req.branch == "main"

    def test_rejects_invalid_url(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(repo_url="http://github.com/user/repo")

    def test_rejects_invalid_scan_type(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(repo_url="https://github.com/a/b", scan_type="invalid")

    def test_full_request(self):
        req = AnalyzeRequest(
            repo_url="https://github.com/user/repo",
            branch="develop",
            scan_type="full",
            target={"framework": "fastapi", "from_version": "0.100.0", "to_version": "0.110.0"},
            pr_info={"pr_number": 42, "base_branch": "main"},
            scan_config={"enable_cve_scan": False},
        )
        assert req.target.framework == "fastapi"
        assert req.pr_info.pr_number == 42

    def test_rejects_http_callback(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(
                repo_url="https://github.com/a/b",
                callback_url="http://insecure.com/hook",
            )


class TestAppealRequest:
    def test_valid(self):
        req = AppealRequest(
            finding_id="CVE-2024-0001",
            reason="This CVE requires physical access, not applicable to our deployment",
            evidence_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        )
        assert req.finding_id == "CVE-2024-0001"

    def test_rejects_short_reason(self):
        with pytest.raises(ValidationError):
            AppealRequest(finding_id="CVE-1", reason="short")  # < 10 chars

    def test_rejects_empty_finding_id(self):
        with pytest.raises(ValidationError):
            AppealRequest(finding_id="", reason="This is a valid and long enough reason")
