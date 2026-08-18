import json
import argparse
import uuid
from pathlib import Path
from datetime import datetime


class BloodHoundCollector:

    def __init__(self, neo4j_uri="bolt://localhost:7687",
                 neo4j_user="neo4j", neo4j_password=""):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.driver = None

    def connect(self):
        from neo4j import GraphDatabase
        self.driver = GraphDatabase.driver(
            self.neo4j_uri,
            auth=(self.neo4j_user, self.neo4j_password) if self.neo4j_password else None
        )
        self.driver.verify_connectivity()
        return self.driver

    def close(self):
        if self.driver:
            self.driver.close()
            self.driver = None

    def run_sharphound(self, collection_methods=None):
        if collection_methods is None:
            collection_methods = ["All"]

        print(f"Simulating SharpHound collection: {', '.join(collection_methods)}")
        data = {
            "meta": {
                "type": "BloodHoundCollection",
                "version": "4.3.0",
                "collected_at": datetime.utcnow().isoformat() + "Z",
                "methods": collection_methods,
            },
            "nodes": [],
            "edges": [],
        }
        return data

    def generate_ad_graph(self, config):
        domain_upper = config["domain_name"]
        domain_lower = config["domain_fqdn"]
        nodes = []
        edges = []

        nodes.append({
            "label": "Domain",
            "name": domain_upper,
            "properties": {
                "name": domain_upper,
                "fqdn": domain_lower,
                "objectid": str(uuid.uuid4()),
            },
        })

        for ou in config.get("ous", []):
            nodes.append({
                "label": "OU",
                "name": ou["name"],
                "properties": {
                    "name": ou["name"],
                    "path": ou["path"],
                    "objectid": str(uuid.uuid4()),
                },
            })
            edges.append({
                "source": ou["name"],
                "target": domain_upper,
                "type": "Contains",
                "properties": {"isACL": False},
            })

        for group in config.get("groups", []):
            group_name = group["name"]
            nodes.append({
                "label": "Group",
                "name": group_name,
                "properties": {
                    "name": group_name,
                    "description": group.get("description", ""),
                    "objectid": str(uuid.uuid4()),
                    "isprivileged": group.get("is_privileged", False),
                },
            })
            edges.append({
                "source": group_name,
                "target": domain_upper,
                "type": "MemberOf",
            })

            for member in group.get("members", []):
                edges.append({
                    "source": member,
                    "target": group_name,
                    "type": "MemberOf",
                })

            for parent in group.get("member_of", []):
                if parent != group_name:
                    edges.append({
                        "source": group_name,
                        "target": parent,
                        "type": "MemberOf",
                    })

            if group.get("acl_rights"):
                edges.append({
                    "source": group_name,
                    "target": domain_upper,
                    "type": group["acl_rights"][0],
                    "properties": {"isACL": True},
                })

        for user in config.get("users", []):
            user_name = user["name"]
            user_node = {
                "label": "User",
                "name": user_name,
                "properties": {
                    "name": user_name,
                    "displayname": user.get("displayname", ""),
                    "username": user.get("username", ""),
                    "objectid": str(uuid.uuid4()),
                    "enabled": user.get("enabled", True),
                    "hasspn": user.get("hasspn", False),
                    "dont_require_preauth": user.get("dont_require_preauth", False),
                    "password_never_expires": user.get("password_never_expires", False),
                    "lastlogondate": datetime.utcnow().isoformat() + "Z",
                },
            }
            if user.get("serviceprincipalname"):
                user_node["properties"]["serviceprincipalname"] = user["serviceprincipalname"]
            nodes.append(user_node)

            for group_name in user.get("member_of", []):
                if group_name != user_name:
                    edges.append({
                        "source": user_name,
                        "target": group_name,
                        "type": "MemberOf",
                    })

            edges.append({
                "source": user_name,
                "target": domain_upper,
                "type": "MemberOf",
            })

        for computer in config.get("computers", []):
            comp_name = computer["name"]
            nodes.append({
                "label": "Computer",
                "name": comp_name,
                "properties": {
                    "name": comp_name,
                    "hostname": computer.get("hostname", ""),
                    "operating_system": computer.get("operating_system", ""),
                    "objectid": str(uuid.uuid4()),
                    "enabled": computer.get("enabled", True),
                },
            })
            edges.append({
                "source": comp_name,
                "target": domain_upper,
                "type": "MemberOf",
            })

            admin_users = [u for u in config.get("users", [])[:3]]
            for u in admin_users:
                edges.append({
                    "source": u["name"],
                    "target": comp_name,
                    "type": "AdminTo",
                })

            edge_types = ["HasSession", "CanRDP", "ExecuteDCOM"]
            for edge_type in edge_types[:2]:
                random_users = config.get("users", [])[:5]
                for u in random_users:
                    edges.append({
                        "source": u["name"],
                        "target": comp_name,
                        "type": edge_type,
                    })

        for gpo in config.get("gpos", []):
            gpo_name = gpo["name"]
            nodes.append({
                "label": "GPO",
                "name": gpo_name,
                "properties": {
                    "name": gpo_name,
                    "gpo_id": gpo.get("gpo_id", ""),
                    "objectid": str(uuid.uuid4()),
                    "is_misconfigured": gpo.get("is_misconfigured", False),
                },
            })
            edges.append({
                "source": gpo_name,
                "target": gpo.get("applies_to", domain_upper),
                "type": "AppliedGPOs",
            })
            for editor in gpo.get("edit_rights", []):
                edges.append({
                    "source": editor,
                    "target": gpo_name,
                    "type": "GenericAll",
                })

        for acl in config.get("acls", []):
            edges.append({
                "source": acl["principal"],
                "target": acl["target"],
                "type": acl["rights"][0] if acl.get("rights") else "WriteDacl",
                "properties": {
                    "isACL": True,
                    "risk": acl.get("risk", "High"),
                },
            })

        return nodes, edges

    def import_to_neo4j(self, nodes, edges):
        if not self.driver:
            self.connect()

        constraint_query = "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Base) REQUIRE n.name IS UNIQUE"

        with self.driver.session() as session:
            try:
                session.run(constraint_query)
            except Exception:
                pass

            for node in nodes:
                label = node["label"]
                name = node["name"]
                props = node.get("properties", {})
                cypher = "MERGE (n:`{label}` {{name: $name}})".format(label=label)
                if props:
                    prop_str = ", ".join(
                        "n.{key} = ${key}".format(key=k) for k in props.keys()
                    )
                    cypher += " SET " + prop_str
                cypher += " RETURN n"
                params = {"name": name}
                params.update(props)
                session.run(cypher, **params)

            for edge in edges:
                source = edge["source"]
                target = edge["target"]
                rel_type = edge["type"]
                props = edge.get("properties", {})
                cypher = (
                    "MATCH (a {name: $source}), (b {name: $target}) "
                    "MERGE (a)-[r:`" + rel_type + "`]->(b)"
                )
                if props:
                    prop_str = ", ".join(
                        "r.{key} = ${key}".format(key=k) for k in props.keys()
                    )
                    cypher += " SET " + prop_str
                params = {"source": source, "target": target}
                params.update(props)
                try:
                    session.run(cypher, **params)
                except Exception:
                    pass

        return {"nodes_imported": len(nodes), "edges_imported": len(edges)}

    def clear_database(self):
        if not self.driver:
            self.connect()

        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

        return {"status": "cleared"}

    def export_to_json(self, nodes, edges, output_path):
        data = {
            "meta": {
                "type": "BloodHoundCollection",
                "version": "4.3.0",
                "collected_at": datetime.utcnow().isoformat() + "Z",
                "node_count": len(nodes),
                "edge_count": len(edges),
            },
            "nodes": nodes,
            "edges": edges,
        }
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return str(path)


def main():
    parser = argparse.ArgumentParser(description="BloodHound Data Collector")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default="")
    parser.add_argument("--config", default="./lab_output/domain_config.json",
                        help="Path to domain config JSON")
    parser.add_argument("--output", default="./lab_output/ad_graph.json",
                        help="Output path for graph data")
    parser.add_argument("--import-to-neo4j", action="store_true",
                        help="Import graph data into Neo4j")
    parser.add_argument("--clear", action="store_true",
                        help="Clear Neo4j database before import")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config file not found: {args.config}")
        return

    with open(config_path) as f:
        config = json.load(f)

    collector = BloodHoundCollector(
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
    )

    nodes, edges = collector.generate_ad_graph(config)
    output = collector.export_to_json(nodes, edges, args.output)
    print(f"Generated {len(nodes)} nodes and {len(edges)} edges")
    print(f"Graph data written to {output}")

    if args.import_to_neo4j:
        try:
            collector.connect()
            if args.clear:
                collector.clear_database()
                print("Database cleared")
            result = collector.import_to_neo4j(nodes, edges)
            print(f"Imported {result['nodes_imported']} nodes, "
                  f"{result['edges_imported']} edges into Neo4j")
        except Exception as e:
            print(f"Neo4j import failed: {e}")
        finally:
            collector.close()


if __name__ == "__main__":
    main()
