# AD Attack Path Automation

Automated deployment, data collection, and analysis of Active Directory attack paths using BloodHound methodology.

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│    AD Lab        │────>│ SharpHound       │────>│    Neo4j         │
│  (Docker/ADCS)   │     │  Data Collection │     │  Graph Database  │
│                  │     │                  │     │                  │
│  Domain: LAB     │     │  JSON Nodes/     │     │  Cypher Queries  │
│  Users: 20+      │     │  Edges Output    │     │  Pattern Matching│
│  Misconfigs: ACL │     │                  │     │                  │
└──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                         │
                                                         v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Markdown Report │<────│ Path Analyzer    │<────│ Cypher Query     │
│                  │     │                  │     │ Library          │
│  Executive Summary│    │  Shortest Path   │     │                  │
│  Attack Paths    │     │  Kerberoastable  │     │  FIND_DOMAIN_ADMINS│
│  Remediation     │     │  AS-REP Roast    │     │  FIND_SPNS       │
│  Risk Scoring    │     │  Priv Esc Vectors│     │  FIND_ACL_ABUSE  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

## Features

- Automated AD lab deployment with Docker Compose or AWS Terraform
- Deliberate AD misconfigurations for security testing
- Python-based AD simulator for environments without Windows containers
- BloodHound-compatible data collection and Neo4j import
- Comprehensive Cypher query library for attack path analysis
- Kerberoastable and AS-REP roastable account detection
- ACL misconfiguration enumeration (GenericAll, WriteDacl, WriteOwner)
- Domain admin escalation path mapping
- Markdown report generation with remediation guidance

## Misconfiguration Catalog

| Category | Misconfiguration | Risk Level | Attack Vector |
|----------|-----------------|------------|---------------|
| Kerberoasting | Service accounts with SPNs | High | Crack TGS tickets offline |
| AS-REP Roasting | DONT_REQ_PREAUTH enabled | High | Request AS-REP, crack offline |
| ACL Abuse | GenericAll on domain object | Critical | Grant self DCSync rights |
| ACL Abuse | WriteDacl on domain object | Critical | Modify ACL to grant DCSync |
| ACL Abuse | WriteOwner on domain object | High | Take ownership, modify ACL |
| Group Abuse | Nested group privileges | Medium | Escalate via group chain |
| GPO Abuse | Edit rights on GPOs | High | Push malicious GPO to hosts |
| Session Abuse | Admin sessions on workstations | Medium | Pass-the-ticket attacks |
| Delegation | Unconstrained delegation | Critical | Impersonate any user |
| Shadow Credentials | msDS-KeyCredentialLink write | Critical | Forge Golden Certificates |

## Quick Start

```bash
pip install -r requirements.txt

python -m src.core.ad_lab_deployer --domain lab.local --admin-password P@ssw0rd123!

python -m src.core.bloodhound_collector --neo4j-uri bolt://localhost:7687

python -m src.core.path_analyzer --neo4j-uri bolt://localhost:7687

python -m src.modules.report_generator --findings findings.json --output report.md
```

## Setup

See [docs/setup-guide.md](docs/setup-guide.md) for detailed setup instructions.

## Project Structure

```
ad-attack-path-automation/
├── .github/workflows/ci.yml      # CI pipeline
├── docs/setup-guide.md            # Setup documentation
├── lab/
│   ├── docker-compose.yml        # AD lab Docker setup
│   └── terraform/main.tf         # AWS EC2 deployment
├── src/
│   ├── core/
│   │   ├── ad_lab_deployer.py     # Lab provisioning
│   │   ├── bloodhound_collector.py # Data collection & Neo4j import
│   │   └── path_analyzer.py      # Attack path analysis
│   └── modules/
│       ├── powershell_scripts/    # AD provisioning & collection
│       ├── cypher_queries.py      # BloodHound Cypher library
│       └── report_generator.py    # Report generation
├── tests/                         # Unit & integration tests
├── scripts/
│   ├── setup.sh                   # Environment setup
│   └── package_project.py         # Packaging utility
└── requirements.txt
```

## Requirements

- Python 3.10+
- Docker & Docker Compose
- Neo4j 5.x (lab only)
- PowerShell 7+ (for AD provisioning scripts)

## Disclaimer

This project is for authorized security testing and educational purposes only. Deploy only in isolated lab environments. Unauthorized access to Active Directory environments is illegal.
