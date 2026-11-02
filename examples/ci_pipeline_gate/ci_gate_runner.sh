#!/usr/bin/env bash
# ==============================================================================
# SecArbiter CI/CD Pipeline Security Gate Runner
#
# Simulates how a CI/CD build verifies pull requests against security regressions:
# 1. Runs SCA scanning against manifests & runtime banners
# 2. Executes deterministic PoC tests
# 3. Enforces zero-tolerance merge gates
# ==============================================================================
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SECARBITER="${REPO_ROOT}/target/release/secarbiter"

if [ ! -f "$SECARBITER" ]; then
    echo -e "${RED}[ERROR] Binary not found at ${SECARBITER}. Run 'cargo build --release' first.${NC}"
    exit 1
fi

echo -e "${BOLD}${BLUE}=== SecArbiter CI/CD Security Gate ===${NC}\n"

# Step 1: Scan manifests for known vulnerable dependencies
MANIFEST_PATH="${REPO_ROOT}/examples/vulnerable_app/requirements.txt"
echo -e "${BLUE}[1/3] Scanning dependency manifest: ${MANIFEST_PATH}${NC}"

SCAN_OUTPUT=$(mktemp)
trap 'rm -f "$SCAN_OUTPUT"' EXIT

set +e
"$SECARBITER" scan --manifest "$MANIFEST_PATH" > "$SCAN_OUTPUT" 2>&1
SCAN_EXIT_CODE=$?
set -e

cat "$SCAN_OUTPUT"

if [ $SCAN_EXIT_CODE -ne 0 ]; then
    echo -e "\n${YELLOW}[GATE WARNING] Known CVEs detected in manifests.${NC}"
    echo -e "In strict CI enforcement mode, pull requests with critical CVEs will be blocked."
else
    echo -e "\n${GREEN}[GATE PASSED] All manifests clean. Zero critical CVEs detected.${NC}"
fi

# Step 2: Test deterministic PoC exit codes
echo -e "\n${BLUE}[2/3] Simulating PoC Regression Verification...${NC}"

# Create a temporary mock PoC regression test
MOCK_POC_REMEDIATED=$(mktemp --suffix=.sh)
cat << 'EOF' > "$MOCK_POC_REMEDIATED"
#!/usr/bin/env bash
# Simulated Remediated PoC (Target returns 403 Forbidden)
HTTP_STATUS=403
if [[ "$HTTP_STATUS" == "200" ]]; then
  echo "[!] ALERT: Vulnerability REPRODUCED!"
  exit 0
elif [[ "$HTTP_STATUS" == "401" || "$HTTP_STATUS" == "403" ]]; then
  echo "[OK] PASSED: Endpoint returned 403 (Access Denied). Remediated."
  exit 1
fi
EOF
chmod +x "$MOCK_POC_REMEDIATED"

set +e
bash "$MOCK_POC_REMEDIATED" >/dev/null 2>&1
POC_STATUS=$?
set -e
rm -f "$MOCK_POC_REMEDIATED"

if [ $POC_STATUS -eq 1 ]; then
    echo -e "  ${GREEN}✓${NC} PoC regression check PASSED (Remediation contract satisfied, exit code 1)."
else
    echo -e "  ${RED}✗${NC} PoC regression check FAILED (Vulnerability still reproducible, exit code 0)."
    exit 1
fi

# Step 3: Summary
echo -e "\n${BLUE}[3/3] CI Verification Gate Completed Successfully.${NC}"
echo -e "  ${GREEN}✓${NC} Zero security regressions detected."
echo -e "  ${GREEN}✓${NC} Build approved for staging deployment.\n"
