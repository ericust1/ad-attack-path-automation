import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.modules.cypher_queries import CypherQueryLibrary


class TestCypherQueries:

    def test_find_shortest_path_to_da_has_match_return(self):
        query = CypherQueryLibrary.FIND_SHORTEST_PATH_TO_DA
        assert "MATCH" in query
        assert "RETURN" in query
        assert "shortestPath" in query
        assert "$start_node" in query

    def test_find_all_privileged_users_has_match_where(self):
        query = CypherQueryLibrary.FIND_ALL_PRIVILEGED_USERS
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "DOMAIN ADMINS" in query

    def test_find_kerberoastable_has_match_where(self):
        query = CypherQueryLibrary.FIND_KERBEROASTABLE
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "hasspn" in query

    def test_find_asrep_roastable_has_match_where(self):
        query = CypherQueryLibrary.FIND_ASREP_ROASTABLE
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "dont_require_preauth" in query

    def test_find_unused_accounts_has_match_where_and_parameter(self):
        query = CypherQueryLibrary.FIND_UNUSED_ACCOUNTS
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "$days" in query

    def test_find_over_privileged_groups_has_match_where(self):
        query = CypherQueryLibrary.FIND_OVER_PRIVILEGED_GROUPS
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "GenericAll" in query
        assert "WriteDacl" in query

    def test_find_acl_misconfigurations_queries(self):
        query = CypherQueryLibrary.FIND_ACL_MISCONFIGURATIONS
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "isACL" in query

    def test_find_potential_abuse_paths_has_optional_match(self):
        query = CypherQueryLibrary.FIND_POTENTIAL_ABUSE_PATHS
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "hasspn" in query
        assert "dont_require_preauth" in query

    def test_get_domain_stats_has_match_return(self):
        query = CypherQueryLibrary.GET_DOMAIN_STATS
        assert "MATCH" in query
        assert "RETURN" in query
        assert "count" in query.lower()

    def test_find_dcsync_principals_query(self):
        query = CypherQueryLibrary.FIND_DCSYNC_PRINCIPALS
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "DCSync" in query
        assert "GenericAll" in query

    def test_find_gpo_abuse_query(self):
        query = CypherQueryLibrary.FIND_GPO_ABUSE
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "GenericAll" in query
        assert "GPO" in query

    def test_find_session_based_attacks_query(self):
        query = CypherQueryLibrary.FIND_SESSION_BASED_ATTACKS
        assert "MATCH" in query
        assert "WHERE" in query
        assert "RETURN" in query
        assert "HasSession" in query

    def test_execute_query_with_no_parameters(self):
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_record = MagicMock()
        mock_record.data.return_value = {"test": "value"}
        mock_session.run.return_value = [mock_record]
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        results = CypherQueryLibrary.execute_query(
            mock_driver,
            "MATCH (n:User) RETURN n.name as name LIMIT 1"
        )
        assert len(results) == 1
        assert results[0]["test"] == "value"

    def test_execute_query_with_parameters(self):
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_record = MagicMock()
        mock_record.data.return_value = {"name": "testuser"}
        mock_session.run.return_value = [mock_record]
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        results = CypherQueryLibrary.execute_query(
            mock_driver,
            "MATCH (n:User {name: $name}) RETURN n.name as name",
            {"name": "testuser@TEST.LOCAL"}
        )
        assert len(results) == 1

    def test_all_queries_use_match_keyword(self):
        queries = [
            CypherQueryLibrary.FIND_SHORTEST_PATH_TO_DA,
            CypherQueryLibrary.FIND_ALL_PRIVILEGED_USERS,
            CypherQueryLibrary.FIND_KERBEROASTABLE,
            CypherQueryLibrary.FIND_ASREP_ROASTABLE,
            CypherQueryLibrary.FIND_UNUSED_ACCOUNTS,
            CypherQueryLibrary.FIND_OVER_PRIVILEGED_GROUPS,
            CypherQueryLibrary.FIND_ACL_MISCONFIGURATIONS,
            CypherQueryLibrary.FIND_POTENTIAL_ABUSE_PATHS,
            CypherQueryLibrary.GET_DOMAIN_STATS,
            CypherQueryLibrary.FIND_DCSYNC_PRINCIPALS,
            CypherQueryLibrary.FIND_GPO_ABUSE,
            CypherQueryLibrary.FIND_SESSION_BASED_ATTACKS,
        ]
        for query in queries:
            assert "MATCH" in query, f"Query missing MATCH keyword: {query[:50]}..."
            assert "RETURN" in query, f"Query missing RETURN keyword: {query[:50]}..."

    def test_parameter_placeholders_are_dollar_prefixed(self):
        queries_with_params = {
            CypherQueryLibrary.FIND_SHORTEST_PATH_TO_DA: "$start_node",
            CypherQueryLibrary.FIND_UNUSED_ACCOUNTS: "$days",
        }
        for query, expected_param in queries_with_params.items():
            assert expected_param in query


from unittest.mock import MagicMock
