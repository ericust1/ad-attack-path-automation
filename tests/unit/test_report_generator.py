import pytest
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.modules.report_generator import ADReportGenerator


class TestReportGenerator:

    @pytest.fixture
    def generator(self):
        return ADReportGenerator()

    @pytest.fixture
    def sample_findings(self):
        return {
            "analysis_date": "2024-01-15T10:30:00Z",
            "domain": "TEST.LOCAL",
            "kerberoastable_accounts": [
                {
                    "name": "svc_mssql@TEST.LOCAL",
                    "spn": "MSSQLSvc/dc01.test.local:1433",
                    "enabled": True,
                    "pw_never_expires": True,
                },
                {
                    "name": "svc_webapp@TEST.LOCAL",
                    "spn": "HTTP/intranet.test.local",
                    "enabled": True,
                    "pw_never_expires": False,
                },
            ],
            "asrep_roastable_accounts": [
                {
                    "name": "test_svc01@TEST.LOCAL",
                    "displayname": "Test Service 01",
                    "enabled": True,
                }
            ],
            "domain_admin_vectors": [
                {
                    "user_name": "svc_mssql@TEST.LOCAL",
                    "node_type": "User",
                    "hops": 3,
                    "relationship_chain": ["MemberOf", "GenericAll", "AdminTo"],
                },
            ],
            "high_privilege_groups": [
                {
                    "group_name": "IT ADMINS@TEST.LOCAL",
                    "abuse_right": "GenericAll",
                    "target": "Domain:TEST.LOCAL",
                },
            ],
            "dcsync_candidates": [
                {
                    "principal": "user1@TEST.LOCAL",
                    "right_name": "WriteDacl",
                    "target_domain": "TEST.LOCAL",
                    "attack_technique": "DCSync",
                }
            ],
            "unused_accounts": [
                {
                    "name": "retired_user@TEST.LOCAL",
                    "displayname": "Retired User",
                    "last_logon": "2023-06-01T00:00:00Z",
                },
            ],
            "shortest_paths": [
                {
                    "start": "svc_mssql@TEST.LOCAL",
                    "end": "DOMAIN ADMINS@TEST.LOCAL",
                    "paths": [
                        {
                            "path_length": 3,
                            "node_labels": [
                                "User:svc_mssql@TEST.LOCAL",
                                "Group:Service Accounts@TEST.LOCAL",
                                "Group:IT ADMINS@TEST.LOCAL",
                                "Group:DOMAIN ADMINS@TEST.LOCAL",
                            ],
                        }
                    ],
                }
            ],
            "summary": {
                "kerberoastable_count": 2,
                "asrep_roastable_count": 1,
                "da_vectors_count": 1,
                "over_privileged_groups_count": 1,
                "dcsync_candidates_count": 1,
                "unused_accounts_count": 1,
                "critical_findings": 2,
            },
        }

    def test_report_contains_title(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "AD Attack Path Analysis Report" in content

    def test_report_contains_executive_summary(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "Executive Summary" in content
        assert "Risk Assessment" in content

    def test_report_contains_kerberoastable_section(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "Kerberoastable Accounts" in content
        assert "svc_mssql@TEST.LOCAL" in content

    def test_report_contains_asrep_section(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "AS-REP Roastable" in content
        assert "test_svc01@TEST.LOCAL" in content

    def test_report_contains_domain_info(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "TEST.LOCAL" in content

    def test_report_contains_privilege_escalation_section(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "Domain Admin Escalation" in content
        assert "Over-Privileged Groups" in content

    def test_report_contains_unused_accounts_section(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "Unused Accounts" in content

    def test_report_contains_remediation_section(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "Remediation" in content
        assert "Critical" in content or "High" in content

    def test_report_contains_attack_path_diagram(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "Attack Path Diagrams" in content
        assert "DOMAIN ADMINS@TEST.LOCAL" in content

    def test_report_contains_summary_table(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "Kerberoastable Accounts | 2" in content
        assert "AS-REP Roastable Accounts | 1" in content

    def test_report_risk_assessment_critical(self, generator, sample_findings, tmp_path):
        sample_findings["summary"]["critical_findings"] = 8
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "CRITICAL" in content

    def test_report_risk_assessment_low(self, generator, sample_findings, tmp_path):
        sample_findings["summary"]["critical_findings"] = 0
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "LOW" in content

    def test_report_with_empty_findings(self, generator, tmp_path):
        empty_findings = {
            "domain": "TEST.LOCAL",
            "summary": {
                "kerberoastable_count": 0,
                "asrep_roastable_count": 0,
                "da_vectors_count": 0,
                "over_privileged_groups_count": 0,
                "dcsync_candidates_count": 0,
                "unused_accounts_count": 0,
                "critical_findings": 0,
            },
            "kerberoastable_accounts": [],
            "asrep_roastable_accounts": [],
            "domain_admin_vectors": [],
            "high_privilege_groups": [],
            "dcsync_candidates": [],
            "unused_accounts": [],
            "shortest_paths": [],
        }
        output = generator.generate_markdown_report(empty_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert "No Kerberoastable accounts" in content
        assert "No AS-REP roastable accounts" in content

    def test_report_creates_parent_directories(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(
            sample_findings,
            str(tmp_path / "nested" / "dir" / "report.md")
        )
        assert os.path.exists(output)

    def test_report_is_valid_markdown(self, generator, sample_findings, tmp_path):
        output = generator.generate_markdown_report(sample_findings, str(tmp_path / "report.md"))
        content = Path(output).read_text()
        assert content.startswith("#")
        assert "## " in content
        assert "| " in content
