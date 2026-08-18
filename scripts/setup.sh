#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[*] AD Attack Path Automation - Environment Setup${NC}"

OS=$(uname -s)
case "$OS" in
    Linux*)  DISTRO="Linux" ;;
    Darwin*) DISTRO="macOS" ;;
    *)       DISTRO="Unknown: $OS" ;;
esac
echo -e "  Detected OS: ${YELLOW}${DISTRO}${NC}"

if command -v docker &> /dev/null; then
    echo -e "  ${GREEN}[+] Docker found: $(docker --version)${NC}"
else
    echo -e "  ${RED}[-] Docker not found. Installing...${NC}"
    if [ "$DISTRO" = "Linux" ]; then
        curl -fsSL https://get.docker.com | sudo sh
        sudo usermod -aG docker "$USER"
    else
        echo -e "  ${YELLOW}[!] Please install Docker manually: https://docs.docker.com/get-docker/${NC}"
    fi
fi

if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    echo -e "  ${GREEN}[+] Docker Compose found${NC}"
else
    echo -e "  ${RED}[-] Docker Compose not found${NC}"
fi

if command -v python3 &> /dev/null; then
    echo -e "  ${GREEN}[+] Python3 found: $(python3 --version)${NC}"
else
    echo -e "  ${RED}[-] Python3 not found. Please install Python 3.10+${NC}"
    exit 1
fi

if command -v pwsh &> /dev/null; then
    echo -e "  ${GREEN}[+] PowerShell found: $(pwsh --version)${NC}"
else
    echo -e "  ${YELLOW}[!] PowerShell not found (optional for AD provisioning)${NC}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "\n${GREEN}[*] Installing Python dependencies...${NC}"
pip3 install -r "${PROJECT_ROOT}/requirements.txt"

echo -e "\n${GREEN}[*] Installing Neo4j (Docker)...${NC}"
if docker ps -a --format '{{.Names}}' | grep -q "ad-lab-neo4j"; then
    echo -e "  ${YELLOW}[!] Neo4j container already exists${NC}"
else
    docker run -d \
        --name ad-lab-neo4j \
        -p 7474:7474 \
        -p 7687:7687 \
        -e NEO4J_AUTH=neo4j/password123 \
        neo4j:5.15
    echo -e "  ${GREEN}[+] Neo4j started on bolt://localhost:7687${NC}"
fi

echo -e "\n${GREEN}[*] Environment setup complete${NC}"
echo -e "  Neo4j Browser: http://localhost:7474"
echo -e "  Neo4j Bolt:    bolt://localhost:7687"
echo -e "  Neo4j Auth:    neo4j / password123"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. python3 -m src.core.ad_lab_deployer --domain lab.local --admin-password Welcome123!"
echo "  2. python3 -m src.core.bloodhound_collector --import-to-neo4j"
echo "  3. python3 -m src.core.path_analyzer --domain LAB.LOCAL"
echo "  4. python3 -m src.modules.report_generator --findings findings.json"
