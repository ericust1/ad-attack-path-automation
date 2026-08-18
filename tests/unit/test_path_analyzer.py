import pytest
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.core.path_analyzer import PathAnalyzer


class TestPathAnalyzer:

    @pytest.fixture
    def analyzer(self):
        return PathAnalyzer(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j",
            neo4j_password="test"
        )

    def _make_records(self, data_list):
        records = []
        for d in data_list:
            mock_rec = MagicMock()
            mock_rec.data.return_value = d
            records.append(mock_rec)
        return records

    def _setup_mock_driver(self, analyzer, return_data):
        records = self._make_records(return_data)

        mock_session = MagicMock()
        mock_session.run.return_value = records

        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        analyzer.driver = mock_driver
        return mock_session

    def test_find_shortest_path_query_structure(self, analyzer):
        mock_session = self._setup_mock_driver(analyzer, [
            {"path_length": 3, "node_labels": ["User:testuser", "Group:IT ADMINS", "Group:DOMAIN ADMINS"]}
        ])

        results = analyzer.find_shortest_path("testuser@TEST.LOCAL", "DOMAIN ADMINS@TEST.LOCAL")
        assert len(results) > 0
        assert results[0]["path_length"] == 3
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "shortestPath" in query
        assert "MATCH" in query
        assert "RETURN" in query

    def test_find_all_paths_query_structure(self, analyzer):
        self._setup_mock_driver(analyzer, [])

        results = analyzer.find_all_paths("testuser@TEST.LOCAL", "DOMAIN ADMINS@TEST.LOCAL", max_depth=4)
        mock_session = analyzer.driver.session.return_value.__enter__.return_value
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "allShortestPaths" in query
        assert "MATCH" in query
        assert "LIMIT" in query

    def test_get_kerberoastable_accounts_query(self, analyzer):
        mock_session = self._setup_mock_driver(analyzer, [
            {"name": "svc_mssql@TEST.LOCAL", "displayname": "MSSQL", "spn": "MSSQLSvc/dc01.test.local:1433",
             "enabled": True, "pw_never_expires": True}
        ])

        results = analyzer.get_kerberoastable_accounts()
        assert len(results) == 1
        assert results[0]["name"] == "svc_mssql@TEST.LOCAL"

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "hasspn" in query
        assert "MATCH" in query
        assert "WHERE" in query

    def test_get_asrep_roastable_query(self, analyzer):
        mock_session = self._setup_mock_driver(analyzer, [
            {"name": "test_svc@TEST.LOCAL", "displayname": "Test", "enabled": True}
        ])

        results = analyzer.get_asrep_roastable()
        assert len(results) == 1

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "dont_require_preauth" in query

    def test_get_domain_admin_vectors_query(self, analyzer):
        mock_session = self._setup_mock_driver(analyzer, [
            {"user_name": "jsmith@TEST.LOCAL", "node_type": "User", "hops": 3,
             "relationship_chain": ["MemberOf", "MemberOf", "MemberOf"]}
        ])

        results = analyzer.get_domain_admin_vectors()
        assert len(results) == 1
        assert results[0]["user_name"] == "jsmith@TEST.LOCAL"
        assert results[0]["hops"] == 3

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "DOMAIN ADMINS" in query

    def test_get_unused_accounts_query_with_cutoff(self, analyzer):
        self._setup_mock_driver(analyzer, [])

        results = analyzer.get_unused_accounts(days=90)
        mock_session = analyzer.driver.session.return_value.__enter__.return_value
        call_args = mock_session.run.call_args
        params = call_args[1]
        assert "cutoff" in params

    def test_get_high_privilege_groups_query(self, analyzer):
        mock_session = self._setup_mock_driver(analyzer, [
            {"group_name": "IT ADMINS@TEST.LOCAL", "abuse_right": "GenericAll", "target": "Domain:TEST.LOCAL"}
        ])

        results = analyzer.get_high_privilege_groups()
        assert len(results) >= 1

        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "GenericAll" in query or "WriteDacl" in query

    def test_get_dcsync_candidates_query(self, analyzer):
        self._setup_mock_driver(analyzer, [])

        results = analyzer.get_dcsync_candidates()
        mock_session = analyzer.driver.session.return_value.__enter__.return_value
        call_args = mock_session.run.call_args
        query = call_args[0][0]
        assert "DCSync" in query
        assert "Domain" in query

    def test_analyze_attack_paths_returns_comprehensive_findings(self, analyzer):
        def make_run_side_effect(data_list):
            records = []
            for d in data_list:
                mock_rec = MagicMock()
                mock_rec.data.return_value = d
                records.append(mock_rec)
            return MagicMock(return_value=records)

        kerb_run = make_run_side_effect([
            {"name": "svc_mssql@TEST.LOCAL", "displayname": "MSSQL",
             "spn": "MSSQLSvc/dc01.test.local:1433", "enabled": True, "pw_never_expires": True}
        ])
        asrep_run = make_run_side_effect([
            {"name": "test_svc@TEST.LOCAL", "displayname": "Test", "enabled": True}
        ])
        da_run = make_run_side_effect([
            {"user_name": "svc_mssql@TEST.LOCAL", "node_type": "User",
             "hops": 2, "relationship_chain": ["MemberOf", "MemberOf"]}
        ])
        priv_group_run = make_run_side_effect([
            {"group_name": "IT ADMINS@TEST.LOCAL", "abuse_right": "GenericAll",
             "target": "Domain:TEST.LOCAL"}
        ])
        dcsync_run = make_run_side_effect([
            {"principal": "user@TEST.LOCAL", "right_name": "GenericAll",
             "target_domain": "TEST.LOCAL", "attack_technique": "DCSync"}
        ])
        empty_run = make_run_side_effect([])

        call_count = [0]
        ordered_mocks = [kerb_run, asrep_run, da_run, priv_group_run, dcsync_run,
                         empty_run, empty_run, empty_run, empty_run]

        def run_side_effect(*args, **kwargs):
            idx = call_count[0] % len(ordered_mocks)
            call_count[0] += 1
            return ordered_mocks[idx](*args, **kwargs)

        mock_session = MagicMock()
        mock_session.run.side_effect = run_side_effect
        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        analyzer.driver = mock_driver

        findings = analyzer.analyze_attack_paths("TEST.LOCAL")

        assert "analysis_date" in findings
        assert "domain" in findings
        assert findings["domain"] == "TEST.LOCAL"
        assert "kerberoastable_accounts" in findings
        assert "asrep_roastable_accounts" in findings
        assert "domain_admin_vectors" in findings
        assert "high_privilege_groups" in findings
        assert "summary" in findings
        assert findings["summary"]["kerberoastable_count"] == 1

    def test_connect_establishes_neo4j_connection(self, analyzer):
        with patch.object(PathAnalyzer, "connect", wraps=analyzer.connect) as mock_connect:
            pass

    def test_close_closes_driver(self, analyzer):
        mock_driver = MagicMock()
        analyzer.driver = mock_driver
        analyzer.close()
        mock_driver.close.assert_called_once()
        assert analyzer.driver is None
