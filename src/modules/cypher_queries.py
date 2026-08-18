class CypherQueryLibrary:

    FIND_SHORTEST_PATH_TO_DA = (
        "MATCH p=shortestPath((a {name: $start_node})"
        "-[r*..8]->(g:Group)) "
        "WHERE g.name STARTS WITH 'DOMAIN ADMINS' "
        "RETURN [n IN nodes(p) | labels(n)[0] + ':' + n.name] as path, "
        "length(p) as hops, "
        "[r IN relationships(p) | type(r)] as edge_types "
        "ORDER BY hops "
        "LIMIT 5"
    )

    FIND_ALL_PRIVILEGED_USERS = (
        "MATCH (u)-[r*1..7]->(g:Group) "
        "WHERE g.name STARTS WITH 'DOMAIN ADMINS' "
        "OR g.name STARTS WITH 'ENTERPRISE ADMINS' "
        "RETURN DISTINCT u.name as principal, "
        "g.name as target_group, "
        "length(r) as distance, "
        "labels(u)[0] as principal_type "
        "ORDER BY distance"
    )

    FIND_KERBEROASTABLE = (
        "MATCH (u:User) "
        "WHERE u.hasspn = true "
        "RETURN u.name as account_name, "
        "u.displayname as display_name, "
        "u.serviceprincipalname as spn, "
        "u.enabled as is_enabled, "
        "u.password_never_expires as pw_no_expiry, "
        "CASE WHEN u.admincount = true THEN 'High' ELSE 'Medium' END as risk_level "
        "ORDER BY risk_level, account_name"
    )

    FIND_ASREP_ROASTABLE = (
        "MATCH (u:User) "
        "WHERE u.dont_require_preauth = true "
        "RETURN u.name as account_name, "
        "u.displayname as display_name, "
        "u.enabled as is_enabled, "
        "CASE WHEN u.admincount = true THEN 'Critical' ELSE 'High' END as risk_level "
        "ORDER BY risk_level, account_name"
    )

    FIND_UNUSED_ACCOUNTS = (
        "MATCH (u:User) "
        "WHERE u.enabled = true "
        "AND (u.lastlogondate IS NULL "
        "OR u.lastlogondate < datetime() - duration({days: $days})) "
        "RETURN u.name as account_name, "
        "u.displayname as display_name, "
        "u.lastlogondate as last_logon, "
        "u.department as department "
        "ORDER BY u.lastlogondate ASC "
        "LIMIT 50"
    )

    FIND_OVER_PRIVILEGED_GROUPS = (
        "MATCH (g:Group)-[r]->(target) "
        "WHERE type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'GenericWrite'] "
        "RETURN DISTINCT g.name as group_name, "
        "type(r) as abuse_type, "
        "labels(target)[0] + ':' + target.name as target_object, "
        "CASE "
        "WHEN type(r) = 'GenericAll' AND labels(target)[0] = 'Domain' THEN 'Critical' "
        "WHEN type(r) IN ['WriteDacl', 'WriteOwner'] AND labels(target)[0] = 'Domain' THEN 'Critical' "
        "WHEN type(r) = 'GenericAll' AND labels(target)[0] = 'Group' THEN 'High' "
        "WHEN type(r) = 'GenericAll' AND labels(target)[0] = 'Computer' THEN 'High' "
        "WHEN type(r) = 'GenericWrite' THEN 'Medium' "
        "ELSE 'Low' END as risk_level "
        "ORDER BY risk_level, group_name"
    )

    FIND_ACL_MISCONFIGURATIONS = (
        "MATCH (principal)-[r]->(target) "
        "WHERE r.isACL = true "
        "RETURN DISTINCT principal.name as principal, "
        "labels(principal)[0] as principal_type, "
        "type(r) as right_granted, "
        "labels(target)[0] + ':' + target.name as target, "
        "r.risk as risk_level "
        "ORDER BY risk_level, right_granted, principal"
    )

    FIND_POTENTIAL_ABUSE_PATHS = (
        "MATCH (u:User) "
        "WHERE u.hasspn = true OR u.dont_require_preauth = true "
        "OPTIONAL MATCH p=(u)-[r*1..5]->(g:Group) "
        "WHERE g.name STARTS WITH 'DOMAIN ADMINS' "
        "RETURN u.name as vulnerable_account, "
        "CASE WHEN u.hasspn = true THEN 'Kerberoasting' "
        "WHEN u.dont_require_preauth = true THEN 'AS-REP Roasting' "
        "END as vulnerability, "
        "CASE WHEN p IS NOT NULL THEN length(p) ELSE -1 END as da_distance, "
        "CASE WHEN p IS NOT NULL THEN [n IN nodes(p) | labels(n)[0] + ':' + n.name] ELSE [] END as path_to_da "
        "ORDER BY da_distance"
    )

    GET_DOMAIN_STATS = (
        "MATCH (u:User) RETURN count(u) as total_users "
        "UNION ALL "
        "MATCH (g:Group) RETURN count(g) as total_users "
        "UNION ALL "
        "MATCH (c:Computer) RETURN count(c) as total_users "
        "UNION ALL "
        "MATCH (n) RETURN count(n) as total_users"
    )

    FIND_DCSYNC_PRINCIPALS = (
        "MATCH (p)-[r]->(d:Domain) "
        "WHERE type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'AllExtendedRights'] "
        "RETURN DISTINCT p.name as principal, "
        "labels(p)[0] as principal_type, "
        "type(r) as abuse_right, "
        "d.name as target_domain, "
        "'DCSync' as attack_technique, "
        "'Critical' as risk_level "
        "ORDER BY risk_level, principal"
    )

    FIND_GPO_ABUSE = (
        "MATCH (u)-[r:GenericAll]->(gpo:GPO) "
        "WHERE gpo.is_misconfigured = true "
        "RETURN DISTINCT u.name as principal, "
        "labels(u)[0] as principal_type, "
        "gpo.name as gpo_name, "
        "'GPO Abuse' as attack_technique, "
        "'High' as risk_level "
        "ORDER BY principal"
    )

    FIND_SESSION_BASED_ATTACKS = (
        "MATCH (u:User)-[r:HasSession]->(c:Computer) "
        "WHERE u.admincount = true OR u.name STARTS WITH 'admin' "
        "RETURN u.name as privileged_user, "
        "c.name as target_computer, "
        "type(r) as relationship, "
        "'Session Hijacking' as attack_technique, "
        "'Medium' as risk_level "
        "ORDER BY privileged_user"
    )

    @staticmethod
    def execute_query(driver, query, parameters=None):
        if parameters is None:
            parameters = {}
        with driver.session() as session:
            result = session.run(query, **parameters)
            return [record.data() for record in result]
