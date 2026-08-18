import pytest
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.core.bloodhound_collector import BloodHoundCollector
from src.core.ad_lab_deployer import ADLabDeployer


class TestBloodHoundCollector:

    @pytest.fixture
    def collector(self):
        return BloodHoundCollector(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j",
            neo4j_password="test"
        )

    @pytest.fixture
    def sample_config(self):
        deployer = ADLabDeployer()
        return deployer.generate_domain_config(
            domain_name="test.local",
            admin_password="TestPass123!",
            n_users=10,
            n_groups=2,
            n_computers=3,
        )

    def test_generate_ad_graph_creates_nodes_with_labels(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        assert len(nodes) > 0

        labels = set(n["label"] for n in nodes)
        assert "User" in labels
        assert "Group" in labels
        assert "Computer" in labels
        assert "Domain" in labels

    def test_generate_ad_graph_creates_nodes_with_properties(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        for node in nodes:
            assert "name" in node
            assert "properties" in node
            assert "objectid" in node["properties"]

    def test_generate_ad_graph_creates_correct_relationship_types(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        edge_types = set(e["type"] for e in edges)
        assert "MemberOf" in edge_types
        assert "AdminTo" in edge_types

    def test_generate_ad_graph_user_nodes_have_kerberoastable_flag(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        user_nodes = [n for n in nodes if n["label"] == "User"]
        kerberoastable = [n for n in user_nodes if n["properties"].get("hasspn")]
        assert len(kerberoastable) > 0
        for node in kerberoastable:
            assert node["properties"]["hasspn"] is True

    def test_generate_ad_graph_kerberoastable_users_have_spn(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        user_nodes = [n for n in nodes if n["label"] == "User"]
        kerberoastable = [n for n in user_nodes if n["properties"].get("hasspn")]
        for node in kerberoastable:
            assert "serviceprincipalname" in node["properties"]

    def test_generate_ad_graph_asrep_users_flagged(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        user_nodes = [n for n in nodes if n["label"] == "User"]
        asrep = [n for n in user_nodes if n["properties"].get("dont_require_preauth")]
        assert len(asrep) > 0

    def test_generate_ad_graph_domain_node_present(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        domain_nodes = [n for n in nodes if n["label"] == "Domain"]
        assert len(domain_nodes) == 1
        assert domain_nodes[0]["name"] == "TEST.LOCAL"

    def test_generate_ad_graph_gpo_nodes_present(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        gpo_nodes = [n for n in nodes if n["label"] == "GPO"]
        assert len(gpo_nodes) > 0
        misconfigured = [n for n in gpo_nodes if n["properties"].get("is_misconfigured")]
        assert len(misconfigured) > 0

    def test_generate_ad_graph_acl_edges(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        acl_edges = [e for e in edges if e.get("properties", {}).get("isACL")]
        assert len(acl_edges) > 0

    def test_generate_ad_graph_ou_nodes(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)
        ou_nodes = [n for n in nodes if n["label"] == "OU"]
        assert len(ou_nodes) > 0

    def test_import_to_neo4j_generates_valid_cypher(self, collector, sample_config):
        nodes, edges = collector.generate_ad_graph(sample_config)

        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        collector.driver = mock_driver

        collector.import_to_neo4j(nodes[:5], edges[:5])

        assert mock_session.run.call_count >= 5

    def test_export_to_json_writes_file(self, collector, sample_config, tmp_path):
        nodes, edges = collector.generate_ad_graph(sample_config)
        output_path = str(tmp_path / "test_graph.json")
        result = collector.export_to_json(nodes, edges, output_path)

        assert os.path.exists(output_path)
        with open(output_path) as f:
            data = json.load(f)
        assert "nodes" in data
        assert "edges" in data
        assert "meta" in data
        assert data["meta"]["node_count"] == len(nodes)

    def test_run_sharphound_returns_data_structure(self, collector):
        data = collector.run_sharphound(collection_methods=["All"])
        assert "meta" in data
        assert "nodes" in data
        assert "edges" in data
        assert data["meta"]["methods"] == ["All"]

    def test_clear_database_calls_detach_delete(self, collector):
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        collector.driver = mock_driver

        result = collector.clear_database()
        mock_session.run.assert_called_once_with("MATCH (n) DETACH DELETE n")
        assert result["status"] == "cleared"
