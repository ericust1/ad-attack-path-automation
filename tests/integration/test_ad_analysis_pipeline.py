import pytest
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.core.ad_lab_deployer import ADLabDeployer
from src.core.bloodhound_collector import BloodHoundCollector
from src.modules.cypher_queries import CypherQueryLibrary


class InMemoryGraph:

    def __init__(self):
        self.nodes = []
        self.edges = []
        self.node_index = {}

    def add_node(self, label, name, properties=None):
        if properties is None:
            properties = {}
        node = {"label": label, "name": name, "properties": properties}
        if name not in self.node_index:
            self.node_index[name] = node
            self.nodes.append(node)
        return node

    def add_edge(self, source, target, rel_type, properties=None):
        if properties is None:
            properties = {}
        self.edges.append({
            "source": source,
            "target": target,
            "type": rel_type,
            "properties": properties,
        })

    def find_nodes_by_property(self, label, prop_name, prop_value):
        return [
            n for n in self.nodes
            if n["label"] == label and n["properties"].get(prop_name) == prop_value
        ]

    def find_edges_from(self, source_name, rel_type=None):
        results = []
        for e in self.edges:
            if e["source"] == source_name:
                if rel_type is None or e["type"] == rel_type:
                    results.append(e)
        return results

    def find_path(self, start, end, visited=None, path=None, max_depth=10):
        if visited is None:
            visited = set()
        if path is None:
            path = []

        visited.add(start)
        path.append(start)

        if start == end:
            return list(path)

        if len(path) >= max_depth:
            return None

        for edge in self.edges:
            if edge["source"] == start and edge["target"] not in visited:
                result = self.find_path(
                    edge["target"], end, visited, path, max_depth
                )
                if result:
                    return result

        path.pop()
        visited.discard(start)
        return None

    def find_all_paths(self, start, end, visited=None, path=None, max_depth=6):
        if visited is None:
            visited = set()
        if path is None:
            path = []

        visited.add(start)
        path.append(start)

        if start == end:
            return [list(path)]

        if len(path) >= max_depth:
            return []

        all_paths = []
        for edge in self.edges:
            if edge["source"] == start and edge["target"] not in visited:
                sub_paths = self.find_all_paths(
                    edge["target"], end, visited, path, max_depth
                )
                for sp in sub_paths:
                    all_paths.append(sp)

        path.pop()
        visited.discard(start)
        return all_paths

    def get_nodes_by_label(self, label):
        return [n for n in self.nodes if n["label"] == label]


class TestADAnalysisPipeline:

    @pytest.fixture
    def lab_config(self):
        deployer = ADLabDeployer()
        return deployer.generate_domain_config(
            domain_name="pipe.local",
            admin_password="PipeTest123!",
            n_users=12,
            n_groups=4,
            n_computers=5,
        )

    @pytest.fixture
    def graph(self, lab_config):
        collector = BloodHoundCollector()
        nodes, edges = collector.generate_ad_graph(lab_config)
        g = InMemoryGraph()
        for node in nodes:
            g.add_node(node["label"], node["name"], node.get("properties", {}))
        for edge in edges:
            g.add_edge(edge["source"], edge["target"], edge["type"], edge.get("properties", {}))
        return g

    def test_pipeline_generates_lab_config(self, lab_config):
        assert lab_config["domain_name"] == "PIPE.LOCAL"
        assert len(lab_config["users"]) == 12
        assert len(lab_config["groups"]) >= 4
        assert len(lab_config["computers"]) == 5

    def test_pipeline_generates_graph_nodes(self, graph, lab_config):
        labels = set(n["label"] for n in graph.nodes)
        assert "User" in labels
        assert "Group" in labels
        assert "Computer" in labels
        assert "Domain" in labels
        assert "GPO" in labels
        assert "OU" in labels
        assert len(graph.nodes) > 0

    def test_pipeline_generates_graph_edges(self, graph):
        edge_types = set(e["type"] for e in graph.edges)
        assert "MemberOf" in edge_types
        assert len(graph.edges) > 0

    def test_pipeline_finds_kerberoastable_accounts(self, graph):
        kerberoastable = graph.find_nodes_by_property("User", "hasspn", True)
        assert len(kerberoastable) > 0
        for acct in kerberoastable:
            assert "serviceprincipalname" in acct["properties"]
            assert acct["properties"]["serviceprincipalname"] != ""

    def test_pipeline_finds_asrep_roastable_accounts(self, graph):
        asrep = graph.find_nodes_by_property("User", "dont_require_preauth", True)
        assert len(asrep) > 0

    def test_pipeline_finds_domain_node(self, graph):
        domain_nodes = graph.get_nodes_by_label("Domain")
        assert len(domain_nodes) == 1
        assert domain_nodes[0]["name"] == "PIPE.LOCAL"

    def test_pipeline_finds_da_group(self, graph):
        da_groups = [n for n in graph.nodes
                     if "DOMAIN ADMINS" in n["name"] and n["label"] == "Group"]
        assert len(da_groups) == 1

    def test_pipeline_finds_attack_paths_to_da(self, graph, lab_config):
        da_group = "DOMAIN ADMINS@PIPE.LOCAL"
        all_users = graph.get_nodes_by_label("User")

        paths_found = 0
        for user in all_users:
            path = graph.find_path(user["name"], da_group, max_depth=10)
            if path:
                paths_found += 1

        assert paths_found > 0, "Expected at least one attack path from a user to DA"

    def test_pipeline_finds_acl_misconfigurations(self, graph):
        acl_edges = [e for e in graph.edges
                     if e.get("properties", {}).get("isACL")]
        assert len(acl_edges) > 0

    def test_pipeline_finds_privileged_groups(self, graph):
        privileged_groups = [n for n in graph.nodes
                             if n["label"] == "Group"
                             and n["properties"].get("isprivileged")]
        assert len(privileged_groups) > 0

    def test_pipeline_finds_misconfigured_gpos(self, graph):
        misconfigured_gpos = graph.find_nodes_by_property("GPO", "is_misconfigured", True)
        assert len(misconfigured_gpos) > 0

    def test_pipeline_cypher_queries_valid(self, graph):
        queries = [
            CypherQueryLibrary.FIND_KERBEROASTABLE,
            CypherQueryLibrary.FIND_ASREP_ROASTABLE,
            CypherQueryLibrary.FIND_ALL_PRIVILEGED_USERS,
            CypherQueryLibrary.FIND_OVER_PRIVILEGED_GROUPS,
            CypherQueryLibrary.FIND_ACL_MISCONFIGURATIONS,
        ]
        for query in queries:
            assert "MATCH" in query
            assert "RETURN" in query

    def test_end_to_end_pipeline_with_report(self, lab_config, tmp_path):
        deployer = ADLabDeployer(lab_dir=str(tmp_path / "pipeline_lab"))
        collector = BloodHoundCollector()

        nodes, edges = collector.generate_ad_graph(lab_config)
        graph_output = collector.export_to_json(nodes, edges, str(tmp_path / "pipeline_graph.json"))
        assert os.path.exists(graph_output)

        kerberoastable = [n for n in nodes if n["label"] == "User" and n["properties"].get("hasspn")]
        asrep = [n for n in nodes if n["label"] == "User" and n["properties"].get("dont_require_preauth")]

        findings = {
            "analysis_date": "2024-01-15T10:30:00Z",
            "domain": "PIPE.LOCAL",
            "kerberoastable_accounts": [
                {"name": n["name"], "spn": n["properties"].get("serviceprincipalname", ""),
                 "enabled": n["properties"].get("enabled", True),
                 "pw_never_expires": n["properties"].get("password_never_expires", False)}
                for n in kerberoastable
            ],
            "asrep_roastable_accounts": [
                {"name": n["name"], "displayname": n["properties"].get("displayname", ""),
                 "enabled": n["properties"].get("enabled", True)}
                for n in asrep
            ],
            "domain_admin_vectors": [
                {"user_name": n["name"], "node_type": "User", "hops": 3,
                 "relationship_chain": ["MemberOf", "MemberOf"]}
                for n in kerberoastable
            ],
            "high_privilege_groups": [],
            "dcsync_candidates": [],
            "unused_accounts": [],
            "shortest_paths": [],
            "summary": {
                "kerberoastable_count": len(kerberoastable),
                "asrep_roastable_count": len(asrep),
                "da_vectors_count": len(kerberoastable),
                "over_privileged_groups_count": 0,
                "dcsync_candidates_count": 0,
                "unused_accounts_count": 0,
                "critical_findings": 0,
            },
        }

        from src.modules.report_generator import ADReportGenerator
        gen = ADReportGenerator()
        report_path = gen.generate_markdown_report(findings, str(tmp_path / "pipeline_report.md"))
        assert os.path.exists(report_path)

        report_content = Path(report_path).read_text()
        assert "PIPE.LOCAL" in report_content
        assert "Kerberoastable" in report_content
        assert "Remediation" in report_content

    def test_all_edge_types_from_lab_config(self, graph):
        edge_types = set(e["type"] for e in graph.edges)
        expected_types = {"MemberOf", "AdminTo", "HasSession", "CanRDP", "Contains", "AppliedGPOs", "GenericAll"}
        assert expected_types.issubset(edge_types)
