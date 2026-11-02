#!/usr/bin/env bash
# ==============================================================================
# SecArbiter MCP Server & Developer CLI Installer
# Supports:
#   1. Local execution: ./install.sh
#   2. Web one-liner: curl -fsSL https://raw.githubusercontent.com/<ORG>/secarbiter/main/install.sh | bash
# ==============================================================================
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

GITHUB_REPO="${SECARBITER_REPO:-https://github.com/arifpambudi242/secarbiter}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Fallback to ~/.cargo/bin if ~/.local/bin is not in PATH but ~/.cargo/bin is
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]] && [[ ":$PATH:" == *":$HOME/.cargo/bin:"* ]]; then
    INSTALL_DIR="$HOME/.cargo/bin"
fi

mkdir -p "$INSTALL_DIR"

echo -e "${BOLD}${BLUE}=== SecArbiter MCP Server & Developer CLI Installer ===${NC}\n"

# 1. Determine running context: Local repository vs Web Pipe (curl | bash)
IS_LOCAL=0
LOCAL_ROOT=""

if [[ -f "crates/pentest-mcp/Cargo.toml" ]]; then
    IS_LOCAL=1
    LOCAL_ROOT="$(pwd)"
elif [[ -n "${BASH_SOURCE[0]:-}" && -f "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/crates/pentest-mcp/Cargo.toml" ]]; then
    IS_LOCAL=1
    LOCAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# 2. Platform Architecture Detection
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo -e "${RED}[ERROR] Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

echo -e "${BLUE}[1/4] Detecting environment...${NC}"
echo -e "  ${GREEN}✓${NC} Target Platform : ${OS}-${ARCH}"
echo -e "  ${GREEN}✓${NC} Install Path    : ${INSTALL_DIR}"

# 3. Binary Installation
echo -e "\n${BLUE}[2/4] Installing 'secarbiter' & 'secarbiter-mcp' binaries...${NC}"

if [[ $IS_LOCAL -eq 1 ]]; then
    echo "  Detected local repository at: ${LOCAL_ROOT}"
    cd "${LOCAL_ROOT}"

    echo "  Compiling release binaries via Cargo..."
    cargo build --release -p pentest-mcp
    cp -f target/release/secarbiter "${INSTALL_DIR}/secarbiter"
    cp -f target/release/secarbiter-mcp "${INSTALL_DIR}/secarbiter-mcp"
    # Backward compatibility aliases
    cp -f target/release/pentest "${INSTALL_DIR}/pentest" 2>/dev/null || ln -sf "${INSTALL_DIR}/secarbiter" "${INSTALL_DIR}/pentest"
    cp -f target/release/pentest-mcp "${INSTALL_DIR}/pentest-mcp" 2>/dev/null || ln -sf "${INSTALL_DIR}/secarbiter-mcp" "${INSTALL_DIR}/pentest-mcp"
else
    echo "  Running via remote web installer..."
    RELEASE_URL="https://github.com/${GITHUB_REPO#*github.com/}/releases/latest/download/secarbiter-${OS}-${ARCH}.tar.gz"

    DOWNLOADED=0
    if command -v curl >/dev/null 2>&1; then
        if curl --output /dev/null --silent --head --fail "$RELEASE_URL" 2>/dev/null; then
            echo "  Downloading pre-compiled release from GitHub..."
            curl -fsSL "$RELEASE_URL" | tar -xz -C "${INSTALL_DIR}"
            DOWNLOADED=1
        fi
    fi

    if [[ $DOWNLOADED -eq 0 ]]; then
        echo "  Prebuilt binary not found on release channel. Building from Git repository..."
        if ! command -v cargo >/dev/null 2>&1; then
            echo -e "${RED}[ERROR] Rust/Cargo is required to build from source. Install from https://rustup.rs${NC}"
            exit 1
        fi

        TMP_DIR="$(mktemp -d)"
        trap 'rm -rf "${TMP_DIR}"' EXIT

        echo "  Cloning repository..."
        git clone --depth 1 "${GITHUB_REPO}" "${TMP_DIR}/repo"
        cd "${TMP_DIR}/repo"
        cargo build --release -p pentest-mcp
        cp -f target/release/secarbiter "${INSTALL_DIR}/secarbiter"
        cp -f target/release/secarbiter-mcp "${INSTALL_DIR}/secarbiter-mcp"
        ln -sf "${INSTALL_DIR}/secarbiter" "${INSTALL_DIR}/pentest"
        ln -sf "${INSTALL_DIR}/secarbiter-mcp" "${INSTALL_DIR}/pentest-mcp"
    fi
fi

chmod +x "${INSTALL_DIR}/secarbiter" "${INSTALL_DIR}/secarbiter-mcp" "${INSTALL_DIR}/pentest" "${INSTALL_DIR}/pentest-mcp"
echo -e "  ${GREEN}✓${NC} Installed 'secarbiter'     -> ${INSTALL_DIR}/secarbiter"
echo -e "  ${GREEN}✓${NC} Installed 'secarbiter-mcp' -> ${INSTALL_DIR}/secarbiter-mcp"
echo -e "  ${GREEN}✓${NC} Aliased 'pentest' & 'pentest-mcp' for backward compatibility"

# 4. Provision Docker Sandbox Image
echo -e "\n${BLUE}[3/4] Checking & provisioning Docker sandbox...${NC}"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if [[ $IS_LOCAL -eq 1 && -f "${LOCAL_ROOT}/docker/executor.Dockerfile" ]]; then
        docker build -t secarbiter-sandbox:latest -t pentest-sandbox:latest -f "${LOCAL_ROOT}/docker/executor.Dockerfile" "${LOCAL_ROOT}/docker/" >/dev/null
        echo -e "  ${GREEN}✓${NC} Built 'secarbiter-sandbox:latest' (and 'pentest-sandbox:latest')."
    else
        echo "  Pulling prebuilt sandbox or building from inline Dockerfile..."
        docker build -t secarbiter-sandbox:latest -t pentest-sandbox:latest - << 'EOF' >/dev/null
FROM alpine:3.20
RUN apk add --no-cache bash curl python3 ca-certificates bind-tools iputils jq && rm -rf /var/cache/apk/* /tmp/*
RUN addgroup -S pentest && adduser -S pentest -G pentest -u 1000 -D
WORKDIR /sandbox
RUN chown -R pentest:pentest /sandbox
USER pentest
CMD ["/bin/bash"]
EOF
        echo -e "  ${GREEN}✓${NC} Provisioned 'secarbiter-sandbox:latest'."
    fi
else
    echo -e "  ${YELLOW}[SKIP] Docker is not active. Sandboxed tool execution will be disabled until Docker is started.${NC}"
fi

# 5. MCP Client Integration Guide
echo -e "\n${BLUE}[4/4] Installation Complete! Configuration Guides:${NC}\n"

echo -e "${BOLD}A. Claude Code (Terminal):${NC}"
echo -e "   Run this one-liner in your terminal:"
echo -e "   ${GREEN}claude mcp add secarbiter -- secarbiter-mcp${NC}\n"

echo -e "${BOLD}B. Claude Desktop:${NC}"
echo -e "   Add to your ${YELLOW}claude_desktop_config.json${NC}:"
cat << 'EOF'
   {
     "mcpServers": {
       "secarbiter": {
         "command": "secarbiter-mcp"
       }
     }
   }
EOF

echo -e "\n${BOLD}C. Cursor IDE:${NC}"
echo -e "   Add to ${YELLOW}.cursor/mcp.json${NC} in your project:"
cat << 'EOF'
   {
     "mcpServers": {
       "secarbiter": {
         "command": "secarbiter-mcp"
       }
     }
   }
EOF

echo -e "\n${BOLD}D. Developer Terminal CLI:${NC}"
echo -e "   Run directly:"
echo -e "   ${GREEN}secarbiter --help${NC}\n"
