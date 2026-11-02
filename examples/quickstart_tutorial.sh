#!/usr/bin/env bash
# ==============================================================================
# SecArbiter 60-Second Quickstart Interactive Tutorial
# Walks developers through the dual-interface CLI capabilities hands-on.
# ==============================================================================
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SECARBITER="${REPO_ROOT}/target/release/secarbiter"

if [ ! -f "$SECARBITER" ]; then
    echo -e "${YELLOW}[!] Building release binaries...${NC}"
    cargo build --release -p pentest-mcp
fi

DATA_DIR="/tmp/secarbiter_quickstart_data"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
export PENTEST_DATA_DIR="$DATA_DIR"

clear 2>/dev/null || true
echo -e "${BOLD}${CYAN}======================================================================${NC}"
echo -e "${BOLD}${CYAN}          SECARBITER: 60-SECOND HANDS-ON DEVELOPER QUICKSTART        ${NC}"
echo -e "${BOLD}${CYAN}======================================================================${NC}\n"

echo -e "${BOLD}Welcome! This tutorial demonstrates how SecArbiter provides deterministic${NC}"
echo -e "${BOLD}security verification and zero-hallucination evidence contracts.${NC}\n"

# Step 1: Version and Binary Check
echo -e "${BLUE}▶ STEP 1: Verify SecArbiter Engine Version${NC}"
echo -e "  Command: ${GREEN}secarbiter --version${NC}"
"$SECARBITER" --version
echo ""
sleep 1

# Step 2: Software Composition Analysis (SCA)
echo -e "${BLUE}▶ STEP 2: Scan Dependencies & Manifest for Known CVEs${NC}"
echo -e "  Command: ${GREEN}secarbiter scan --manifest examples/vulnerable_app/requirements.txt${NC}"
"$SECARBITER" scan --manifest "${REPO_ROOT}/examples/vulnerable_app/requirements.txt" || true
echo ""
sleep 1

# Step 3: Scope & Engagement Creation
echo -e "${BLUE}▶ STEP 3: Create Scope-Bounded Security Engagement${NC}"
echo -e "  Command: ${GREEN}secarbiter engagements create --name 'Quickstart Audit' --allowed-hosts 127.0.0.1,localhost --allow-private-ips${NC}"
ENG_JSON=$("$SECARBITER" engagements create --name "Quickstart Audit" --allowed-hosts 127.0.0.1,localhost --allow-private-ips --json)
ENG_ID=$(echo "$ENG_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['engagement_id'])")
echo -e "  ${GREEN}✓${NC} Created Engagement ID: ${BOLD}${ENG_ID}${NC}\n"
sleep 1

# Step 4: List Engagements
echo -e "${BLUE}▶ STEP 4: Inspect Active Security Engagements${NC}"
echo -e "  Command: ${GREEN}secarbiter engagements list${NC}"
"$SECARBITER" engagements list
echo ""
sleep 1

# Step 5: Draft a Suspected Finding
echo -e "${BLUE}▶ STEP 5: Draft a Suspected Vulnerability Finding${NC}"
echo -e "  Command: ${GREEN}secarbiter draft -e ${ENG_ID} -t 'IDOR in Invoices' -c idor -u /api/invoices -s HIGH${NC}"
DRAFT_JSON=$("$SECARBITER" draft -e "$ENG_ID" -t "IDOR in Invoices" -c idor -u /api/invoices -s HIGH --json)
FINDING_ID=$(echo "$DRAFT_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['finding_id'])")
echo -e "  ${GREEN}✓${NC} Finding Drafted in 'suspected' status: ${BOLD}${FINDING_ID}${NC}\n"
sleep 1

# Step 6: Export Sanitized Markdown Report
echo -e "${BLUE}▶ STEP 6: Export Sanitized Developer Security Audit Report${NC}"
REPORT_FILE="${DATA_DIR}/quickstart_audit_report.md"
echo -e "  Command: ${GREEN}secarbiter report -e ${ENG_ID} -f markdown -o ${REPORT_FILE}${NC}"
"$SECARBITER" report -e "$ENG_ID" -f markdown -o "$REPORT_FILE"
echo -e "  ${GREEN}✓${NC} Generated Report: ${REPORT_FILE}\n"

echo -e "${BOLD}${GREEN}======================================================================${NC}"
echo -e "${BOLD}${GREEN}  Quickstart Complete! You are ready to integrate SecArbiter.        ${NC}"
echo -e "${BOLD}${GREEN}  - For AI Agents : Run 'secarbiter-mcp' or 'secarbiter serve'        ${NC}"
echo -e "${BOLD}${GREEN}  - For Developers: Run 'secarbiter --help'                           ${NC}"
echo -e "${BOLD}${GREEN}  - Closed Loop   : Run 'python3 examples/agent_remediation_loop.py'  ${NC}"
echo -e "${BOLD}${GREEN}======================================================================${NC}\n"
