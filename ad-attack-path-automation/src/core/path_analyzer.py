import json
import argparse
from datetime import datetime, timedelta


class PathAnalyzer:

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

    def _run_query(self, query, parameters=None):
        if parameters is None:
            parameters = {}
        if not self.driver:
            self.connect()

        with self.driver.session() as session:
            result = session.run(query, **parameters)
            records = [record.data() for record in result]
        return records

    def find_shortest_path(self, start_node, end_node="DOMAIN ADMINS@DOMAIN.LOCAL"):
        query = (
            "MATCH p=shortestPath((a {name: $start})-[*..8]-(b {name: $end})) "
            "RETURN p, length(p) as path_length, "
            "[n IN nodes(p) | labels(n)[0] + ':' + n.name] as node_labels "
            "LIMIT 1"
        )
        params = {"start": start_node, "end": end_node}
        return self._run_query(query, params)

    def find_all_paths(self, start_node, end_node="DOMAIN ADMINS@DOMAIN.LOCAL",
                       max_depth=5):
        query = (
            "MATCH p=allShortestPaths((a {name: $start})-[*.." + str(max_depth) + "]->(b {name: $end})) "
            "RETURN [n IN nodes(p) | labels(n)[0] + ':' + n.name] as path_nodes, "
            "length(p) as path_length "
            "ORDER BY path_length "
            "LIMIT 20"
        )
        params = {"start": start_node, "end": end_node}
        return self._run_query(query, params)

    def get_domain_admin_vectors(self):
        query = (
            "MATCH (u:User)-[r*1..7]->(g:Group) "
            "WHERE g.name STARTS WITH 'DOMAIN ADMINS' "
            "RETURN DISTINCT u.name as user_name, "
            "labels(u)[0] as node_type, "
            "length(r) as hops, "
            "[rel IN relationships(r) | type(rel)] as relationship_chain "
            "ORDER BY hops"
        )
        return self._run_query(query)

    def get_kerberoastable_accounts(self):
        query = (
            "MATCH (u:User) "
            "WHERE u.hasspn = true "
            "RETURN u.name as name, "
            "u.displayname as displayname, "
            "u.serviceprincipalname as spn, "
            "u.enabled as enabled, "
            "u.password_never_expires as pw_never_expires "
            "ORDER BY name"
        )
        return self._run_query(query)

    def get_asrep_roastable(self):
        query = (
            "MATCH (u:User) "
            "WHERE u.dont_require_preauth = true "
            "RETURN u.name as name, "
            "u.displayname as displayname, "
            "u.enabled as enabled "
            "ORDER BY name"
        )
        return self._run_query(query)

    def get_unused_accounts(self, days=90):
        cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query = (
            "MATCH (u:User) "
            "WHERE u.enabled = true "
            "AND (u.lastlogondate IS NULL OR u.lastlogondate < $cutoff) "
            "RETURN u.name as name, "
            "u.displayname as displayname, "
            "u.lastlogondate as last_logon "
            "ORDER BY u.lastlogondate ASC "
            "LIMIT 50"
        )
        params = {"cutoff": cutoff}
        return self._run_query(query, params)

    def get_high_privilege_groups(self):
        query = (
            "MATCH (g:Group)-[r]->(t) "
            "WHERE type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns'] "
            "RETURN DISTINCT g.name as group_name, "
            "type(r) as abuse_right, "
            "labels(t)[0] + ':' + t.name as target "
            "ORDER BY abuse_right, group_name"
        )
        return self._run_query(query)

    def get_dcsync_candidates(self):
        query = (
            "MATCH (u)-[r]->(d:Domain) "
            "WHERE type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'AllExtendedRights'] "
            "RETURN DISTINCT u.name as principal, "
            "type(r) as right_name, "
            "d.name as target_domain, "
            "'DCSync' as attack_technique "
            "ORDER BY attack_technique, right_name"
        )
        return self._run_query(query)

    def get_unconstrained_delegation(self):
        query = (
            "MATCH (c:Computer) "
            "WHERE c.unconstraineddelegation = true "
            "RETURN c.name as computer_name, "
            "c.operating_system as os "
            "ORDER BY computer_name"
        )
        return self._run_query(query)

    def analyze_attack_paths(self, domain):
        findings = {
            "analysis_date": datetime.utcnow().isoformat() + "Z",
            "domain": domain,
            "kerberoastable_accounts": [],
            "asrep_roastable_accounts": [],
            "domain_admin_vectors": [],
            "high_privilege_groups": [],
            "dcsync_candidates": [],
            "unused_accounts": [],
            "unconstrained_delegation": [],
            "shortest_paths": [],
            "summary": {},
        }

        try:
            findings["kerberoastable_accounts"] = self.get_kerberoastable_accounts()
        except Exception:
            findings["kerberoastable_accounts"] = []

        try:
            findings["asrep_roastable_accounts"] = self.get_asrep_roastable()
        except Exception:
            findings["asrep_roastable_accounts"] = []

        try:
            findings["domain_admin_vectors"] = self.get_domain_admin_vectors()
        except Exception:
            findings["domain_admin_vectors"] = []

        try:
            findings["high_privilege_groups"] = self.get_high_privilege_groups()
        except Exception:
            findings["high_privilege_groups"] = []

        try:
            findings["dcsync_candidates"] = self.get_dcsync_candidates()
        except Exception:
            findings["dcsync_candidates"] = []

        try:
            findings["unused_accounts"] = self.get_unused_accounts()
        except Exception:
            findings["unused_accounts"] = []

        try:
            findings["unconstrained_delegation"] = self.get_unconstrained_delegation()
        except Exception:
            findings["unconstrained_delegation"] = []

        da_group = f"DOMAIN ADMINS@{domain.upper()}"
        for vector in findings["domain_admin_vectors"][:3]:
            user = vector.get("user_name", "")
            if user:
                try:
                    paths = self.find_shortest_path(user, da_group)
                    if paths:
                        findings["shortest_paths"].append({
                            "start": user,
                            "end": da_group,
                            "paths": paths,
                        })
                except Exception:
                    pass

        findings["summary"] = {
            "total_users": len(findings["kerberoastable_accounts"]) + len(findings["asrep_roastable_accounts"]),
            "kerberoastable_count": len(findings["kerberoastable_accounts"]),
            "asrep_roastable_count": len(findings["asrep_roastable_accounts"]),
            "da_vectors_count": len(findings["domain_admin_vectors"]),
            "over_privileged_groups_count": len(findings["high_privilege_groups"]),
            "dcsync_candidates_count": len(findings["dcsync_candidates"]),
            "unused_accounts_count": len(findings["unused_accounts"]),
            "critical_findings": (
                len(findings["dcsync_candidates"]) +
                len(findings["high_privilege_groups"])
            ),
        }

        return findings


def main():
    parser = argparse.ArgumentParser(description="AD Attack Path Analyzer")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default="")
    parser.add_argument("--domain", default="LAB.LOCAL", help="Target domain")
    parser.add_argument("--output", default="./findings.json", help="Output file")
    args = parser.parse_args()

    analyzer = PathAnalyzer(
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
    )

    try:
        analyzer.connect()
        findings = analyzer.analyze_attack_paths(args.domain)

        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2)

        summary = findings["summary"]
        print(f"Analysis complete for domain {args.domain}")
        print(f"Kerberoastable accounts: {summary['kerberoastable_count']}")
        print(f"AS-REP roastable accounts: {summary['asrep_roastable_count']}")
        print(f"DA escalation vectors: {summary['da_vectors_count']}")
        print(f"Over-privileged groups: {summary['over_privileged_groups_count']}")
        print(f"DCSync candidates: {summary['dcsync_candidates_count']}")
        print(f"Unused accounts: {summary['unused_accounts_count']}")
        print(f"Critical findings: {summary['critical_findings']}")
        print(f"Results written to {args.output}")

    except Exception as e:
        print(f"Analysis failed: {e}")
        raise
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()
