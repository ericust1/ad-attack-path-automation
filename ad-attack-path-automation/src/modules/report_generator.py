import json
import argparse
from datetime import datetime
from pathlib import Path


class ADReportGenerator:

    def __init__(self):
        self.template_sections = [
            self._executive_summary,
            self._kerberoastable_section,
            self._asrep_section,
            self._privilege_escalation_section,
            self._acl_misconfig_section,
            self._unused_accounts_section,
            self._attack_path_diagrams,
            self._remediation_section,
        ]

    def generate_markdown_report(self, findings, output_path):
        lines = []
        lines.append("# AD Attack Path Analysis Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Domain:** {findings.get('domain', 'N/A')}")
        lines.append("")

        summary = findings.get("summary", {})
        lines.append("## Executive Summary")
        lines.append("")
        lines.append("This report presents the findings of an automated Active Directory attack path analysis. "
                      "The assessment identified misconfigurations, excessive privileges, and potential escalation "
                      "paths within the AD environment.")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append("| Kerberoastable Accounts | {} |".format(
            summary.get("kerberoastable_count", 0)))
        lines.append("| AS-REP Roastable Accounts | {} |".format(
            summary.get("asrep_roastable_count", 0)))
        lines.append("| Domain Admin Vectors | {} |".format(
            summary.get("da_vectors_count", 0)))
        lines.append("| Over-Privileged Groups | {} |".format(
            summary.get("over_privileged_groups_count", 0)))
        lines.append("| DCSync Candidates | {} |".format(
            summary.get("dcsync_candidates_count", 0)))
        lines.append("| Unused Accounts (>90 days) | {} |".format(
            summary.get("unused_accounts_count", 0)))
        lines.append("| Critical Findings | {} |".format(
            summary.get("critical_findings", 0)))
        lines.append("")

        critical_count = summary.get("critical_findings", 0)
        if critical_count > 5:
            lines.append("> **Risk Assessment: CRITICAL** - The domain has an unacceptable number of high-risk "
                          "misconfigurations that allow unprivileged users to escalate to Domain Admin.")
        elif critical_count > 2:
            lines.append("> **Risk Assessment: HIGH** - Multiple attack paths exist from standard users to "
                          "Domain Admin privileges. Immediate remediation is recommended.")
        elif critical_count > 0:
            lines.append("> **Risk Assessment: MEDIUM** - Some misconfigurations were identified that could "
                          "lead to privilege escalation. Scheduled remediation is advised.")
        else:
            lines.append("> **Risk Assessment: LOW** - No critical misconfigurations detected. Continue "
                          "monitoring with regular assessments.")
        lines.append("")

        kerberoastable = findings.get("kerberoastable_accounts", [])
        lines.append("## Kerberoastable Accounts")
        lines.append("")
        if kerberoastable:
            lines.append("Kerberoastable accounts have Service Principal Names (SPNs) configured, allowing "
                          "offline password cracking of TGS tickets using tools like Rubeus or Impacket's GetUserSPNs.")
            lines.append("")
            lines.append("| Account | SPN | Enabled | Password Never Expires |")
            lines.append("|---------|-----|---------|----------------------|")
            for acct in kerberoastable:
                name = acct.get("name", "N/A")
                spn = acct.get("spn", "N/A")
                enabled = acct.get("enabled", True)
                pw_never = acct.get("pw_never_expires", False)
                lines.append("| {} | {} | {} | {} |".format(
                    name,
                    spn[:50] + ("..." if len(str(spn)) > 50 else ""),
                    "Yes" if enabled else "No",
                    "Yes" if pw_never else "No",
                ))
            lines.append("")
            lines.append("**Risk Level:** High")
            lines.append("**Recommendation:** Use Group Managed Service Accounts (gMSA) where possible. "
                          "Enforce strong, randomly generated passwords. Rotate service account passwords quarterly.")
            lines.append("")
        else:
            lines.append("No Kerberoastable accounts were found.")
            lines.append("")

        asrep = findings.get("asrep_roastable_accounts", [])
        lines.append("## AS-REP Roastable Accounts")
        lines.append("")
        if asrep:
            lines.append("These accounts have `DONT_REQ_PREAUTH` enabled, allowing AS-REP Roasting attacks "
                          "for offline password cracking without any domain interaction.")
            lines.append("")
            lines.append("| Account | Display Name | Enabled |")
            lines.append("|---------|-------------|---------|")
            for acct in asrep:
                name = acct.get("name", "N/A")
                display = acct.get("displayname", "N/A")
                enabled = acct.get("enabled", True)
                lines.append("| {} | {} | {} |".format(name, display, "Yes" if enabled else "No"))
            lines.append("")
            lines.append("**Risk Level:** High")
            lines.append("**Recommendation:** Remove `DONT_REQ_PREAUTH` from all accounts unless explicitly "
                          "required. Enforce password complexity and length requirements.")
            lines.append("")
        else:
            lines.append("No AS-REP roastable accounts were found.")
            lines.append("")

        da_vectors = findings.get("domain_admin_vectors", [])
        lines.append("## Domain Admin Escalation Vectors")
        lines.append("")
        if da_vectors:
            lines.append("The following principals can reach Domain Admins through chained relationships:")
            lines.append("")
            lines.append("| Principal | Type | Hops | Relationship Chain |")
            lines.append("|-----------|------|------|-------------------|")
            for vec in da_vectors[:15]:
                name = vec.get("user_name", "N/A")
                node_type = vec.get("node_type", "N/A")
                hops = vec.get("hops", 0)
                chain = " -> ".join(vec.get("relationship_chain", []))
                lines.append("| {} | {} | {} | {} |".format(
                    name, node_type, hops, chain[:60] + ("..." if len(chain) > 60 else "")
                ))
            lines.append("")
        else:
            lines.append("No direct Domain Admin escalation vectors detected.")
            lines.append("")

        over_priv = findings.get("high_privilege_groups", [])
        lines.append("## Over-Privileged Groups")
        lines.append("")
        if over_priv:
            lines.append("Groups with dangerous ACL rights on sensitive objects:")
            lines.append("")
            lines.append("| Group | Abuse Right | Target |")
            lines.append("|-------|-------------|--------|")
            for item in over_priv:
                group = item.get("group_name", "N/A")
                right = item.get("abuse_right", "N/A")
                target = item.get("target", "N/A")
                lines.append("| {} | {} | {} |".format(group, right, target))
            lines.append("")
        else:
            lines.append("No over-privileged groups detected.")
            lines.append("")

        unused = findings.get("unused_accounts", [])
        lines.append("## Unused Accounts")
        lines.append("")
        if unused:
            lines.append("Accounts with no login activity in the past 90 days:")
            lines.append("")
            lines.append("| Account | Display Name | Last Logon |")
            lines.append("|---------|-------------|-----------|")
            for acct in unused[:20]:
                name = acct.get("name", "N/A")
                display = acct.get("displayname", "N/A")
                last = acct.get("last_logon", "Never")
                lines.append("| {} | {} | {} |".format(name, display, last))
            lines.append("")
        else:
            lines.append("No unused accounts detected.")
            lines.append("")

        paths = findings.get("shortest_paths", [])
        lines.append("## Attack Path Diagrams")
        lines.append("")
        if paths:
            for entry in paths:
                start = entry.get("start", "Unknown")
                end = entry.get("end", "Unknown")
                path_data = entry.get("paths", [])
                lines.append(f"### Path: {start} -> {end}")
                lines.append("")
                for p in path_data:
                    node_labels = p.get("node_labels", [])
                    hops = p.get("path_length", 0)
                    lines.append(f"**Hops:** {hops}")
                    lines.append("")
                    for i, label in enumerate(node_labels):
                        if ":" in label:
                            label_display = label.split(":")[1]
                        else:
                            label_display = label
                        indent = "  " * i
                        if i == 0:
                            lines.append(f"{indent}+-- [{label_display}]")
                        elif i == len(node_labels) - 1:
                            lines.append(f"{indent}+-- [{label_display}] (TARGET)")
                        else:
                            lines.append(f"{indent}|")
                            lines.append(f"{indent}+-- [{label_display}]")
                    lines.append("")
        else:
            lines.append("No attack path diagrams available.")
            lines.append("")

        lines.append("## Remediation Recommendations")
        lines.append("")
        lines.append("| Priority | Finding | Remediation | Effort |")
        lines.append("|----------|---------|-------------|--------|")

        if findings.get("dcsync_candidates"):
            lines.append("| **Critical** | DCSync-capable principals | Remove GenericAll/WriteDacl/WriteOwner on domain root | High |")

        if over_priv:
            lines.append("| **Critical** | Over-privileged groups | Audit and reduce group ACL rights; apply tiered admin model | High |")

        if kerberoastable:
            lines.append("| **High** | Kerberoastable accounts | Migrate to gMSA; enforce 25+ char passwords; rotate quarterly | Medium |")

        if asrep:
            lines.append("| **High** | AS-REP roastable accounts | Disable DONT_REQ_PREAUTH; enforce complex passwords | Low |")

        if da_vectors:
            lines.append("| **High** | DA escalation vectors | Flatten group hierarchy; remove nested privileged groups | Medium |")

        if unused:
            lines.append("| **Medium** | Unused accounts | Disable accounts inactive >90 days; delete after 180 days | Low |")

        lines.append("| **Medium** | Password policies | Enforce 14+ char, complexity, 90-day rotation domain-wide | Low |")
        lines.append("| **Low** | Monitoring | Deploy ATA/DEFENDER for AD; enable credential auditing | High |")
        lines.append("| **Low** | LAPS deployment | Deploy Local Administrator Password Solution to all workstations | Medium |")
        lines.append("")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            f.write("\n".join(lines))

        return str(output)

    def _executive_summary(self, findings, lines):
        lines.append("## Executive Summary")
        return lines

    def _kerberoastable_section(self, findings, lines):
        lines.append("## Kerberoastable Accounts")
        return lines

    def _asrep_section(self, findings, lines):
        lines.append("## AS-REP Roastable Accounts")
        return lines

    def _privilege_escalation_section(self, findings, lines):
        lines.append("## Privilege Escalation Paths")
        return lines

    def _acl_misconfig_section(self, findings, lines):
        lines.append("## ACL Misconfigurations")
        return lines

    def _unused_accounts_section(self, findings, lines):
        lines.append("## Unused Accounts")
        return lines

    def _attack_path_diagrams(self, findings, lines):
        lines.append("## Attack Path Diagrams")
        return lines

    def _remediation_section(self, findings, lines):
        lines.append("## Remediation Recommendations")
        return lines


def main():
    parser = argparse.ArgumentParser(description="AD Report Generator")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument("--output", default="./reports/attack_path_report.md",
                        help="Output report path")
    args = parser.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Findings file not found: {args.findings}")
        return

    with open(findings_path) as f:
        findings = json.load(f)

    generator = ADReportGenerator()
    output = generator.generate_markdown_report(findings, args.output)

    print(f"Report generated: {output}")
    print(f"Domain: {findings.get('domain', 'N/A')}")
    summary = findings.get("summary", {})
    print(f"Critical findings: {summary.get('critical_findings', 0)}")
    print(f"Kerberoastable: {summary.get('kerberoastable_count', 0)}")
    print(f"DA vectors: {summary.get('da_vectors_count', 0)}")


if __name__ == "__main__":
    main()
