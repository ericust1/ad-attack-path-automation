# AD Attack Path Automation - Setup Guide

## Prerequisites

- Docker and Docker Compose installed
- Python 3.10 or higher
- 8GB RAM minimum (16GB recommended for the full lab)
- Git

## 1. Docker AD Lab Deployment

### Option A: Full Windows AD Lab (Requires Windows Containers)

Windows Server Core containers with Active Directory require a Windows host with container support enabled.

```powershell
# On a Windows Server or Windows 10/11 with containers enabled
docker pull mythicagents/adlab-dc:latest

cd lab
docker compose up -d
```

The domain controller will initialize the `LAB.LOCAL` domain with the default admin credentials defined in `docker-compose.yml`. Allow 5-10 minutes for full AD initialization.

### Option B: Python AD Simulator (Any Platform)

The Python AD simulator runs on any platform and generates realistic BloodHound-compatible graph data without requiring Windows containers.

```bash
pip install -r requirements.txt

python -m src.core.ad_lab_deployer --domain lab.local --admin-password Welcome123!

python -m src.core.bloodhound_collector --neo4j-uri bolt://localhost:7687
```

## 2. Neo4j Installation

### Docker (Recommended for Lab)

Neo4j is included in the Docker Compose stack. It runs on port `7474` (browser) and `7687` (bolt).

```bash
cd lab
docker compose up -d neo4j
```

Access the Neo4j browser at `http://localhost:7474`.

### Standalone Installation

```bash
wget https://dist.neo4j.org/neo4j-community-5.15.0-unix.tar.gz
tar -xzf neo4j-community-5.15.0-unix.tar.gz
cd neo4j-community-5.15.0

./bin/neo4j-admin dbms set-initial-password password
./bin/neo4j start
```

### Lab Configuration

For lab environments, disable authentication:

```yaml
# In neo4j.conf
dbms.security.auth_enabled=false
```

## 3. BloodHound Installation

### BloodHound CE (Docker)

```bash
docker pull bloodhoundce/bloodhound:latest
docker run -d \
  --name bloodhound \
  -p 8080:8080 \
  -v bloodhound-data:/data \
  bloodhoundce/bloodhound:latest
```

Access BloodHound at `http://localhost:8080`. Default credentials: `admin:admin`.

### BloodHound Legacy (Requires .NET)

Download from the BloodHound GitHub releases. Requires Neo4j 4.x or 5.x backend.

## 4. Data Collection Pipeline

### Step 1: Deploy the AD Lab

```bash
python -m src.core.ad_lab_deployer \
  --domain lab.local \
  --admin-password Welcome123! \
  --users 25 \
  --groups 6 \
  --computers 12 \
  --output ./lab_output
```

### Step 2: Collect AD Data (Simulated)

The Python simulator generates BloodHound-compatible data:

```bash
python -m src.core.bloodhound_collector \
  --neo4j-uri bolt://localhost:7687 \
  --config ./lab_output/domain_config.json
```

### Step 3: Import into Neo4j

The collector handles Neo4j import automatically. If using real SharpHound on a Windows DC:

```powershell
# On the domain controller or a domain-joined machine
Invoke-SharpHound -CollectionMethod All -OutputDirectory C:\Collection
```

Import the resulting JSON files:

```bash
python -m src.core.bloodhound_collector \
  --neo4j-uri bolt://localhost:7687 \
  --import-file C:\Collection\20240101000000_BloodHound.zip
```

### Step 4: Run Analysis Queries

```bash
python -m src.core.path_analyzer \
  --neo4j-uri bolt://localhost:7687 \
  --domain LAB.LOCAL \
  --output findings.json
```

### Step 5: Generate Report

```bash
python -m src.modules.report_generator \
  --findings findings.json \
  --output reports/attack_path_report.md
```

## 5. Running the Full Pipeline

```bash
bash scripts/setup.sh

python -m src.core.ad_lab_deployer --domain lab.local --admin-password Welcome123!
python -m src.core.bloodhound_collector --neo4j-uri bolt://localhost:7687
python -m src.core.path_analyzer --neo4j-uri bolt://localhost:7687 --output findings.json
python -m src.modules.report_generator --findings findings.json --output reports/report.md
```

## 6. Cypher Query Examples

Run custom queries in Neo4j Browser (`http://localhost:7474`):

```cypher
MATCH (n:User)-[r:MemberOf*1..5]->(g:Group {name:'DOMAIN ADMINS@LAB.LOCAL'})
RETURN n.name, length(r) as depth
ORDER BY depth

MATCH (u:User {hasspn:true})
RETURN u.name, u.displayname

MATCH p=shortestPath((u:User)-[r*1..6]->(g:Group {name:'DOMAIN ADMINS@LAB.LOCAL'}))
RETURN p LIMIT 10
```

## 7. Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## 8. Troubleshooting

| Issue | Solution |
|-------|----------|
| Neo4j won't start | Check Java is installed; verify port 7687 is free |
| Docker compose fails | Ensure Docker daemon is running; check available RAM |
| No attack paths found | Verify data was imported; check domain name case matches |
| Connection refused to Neo4j | Confirm `dbms.connector.bolt.enabled=true` in neo4j.conf |
