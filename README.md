# SecArbiter: Deterministic Security Verification Engine & Agentic Pentest MCP Server

A high-assurance, Rust-based [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server and developer CLI providing sandboxed security testing, traffic capture, deterministic proof-of-concept (PoC) verification, and developer report generation for coding agents (Codex, Claude, Antigravity, and OpenCode).

The core server architecture enforces a strict **zero-LLM-on-server** principle: the host model orchestrates test planning and hypothesis generation, while SecArbiter acts as an independent arbiter that executes and verifies vulnerabilities deterministically in hardened Docker environments without requiring secondary LLM API keys or producing false-positive hallucinations.

---

## Key Capabilities

- **Zero Secondary LLM Keys**: The server executes test workflows, manages target scopes, proxies traffic, and verifies PoC assertions without outbound inference calls or hidden model dependencies.
- **Strict Scope & Network Safety**:
  - Enforces domain/host allowlists and CIDR subnet restrictions.
  - Automatically blocks loopback and private RFC 1918 addresses unless explicitly enabled for dedicated local testbeds.
  - DNS pinning and redirect chain inspection prevent server-side request forgery against unauthorized destinations.
- **Forensic Evidence & Privacy Preservation**:
  - Immutable raw HTTP traffic recording paired with SHA-256 integrity digests.
  - Built-in redaction engine automatically masks JWT tokens, HTTP Authorization headers, session cookies, and sensitive payload parameters in tool outputs and export reports, while raw on-disk forensic records remain intact for verifier grounding.
  - Grounding engine cross-checks assertions against raw HTTP records before confirming findings.
  - Consult [docs/CLAIMS.md](docs/CLAIMS.md) for the complete empirical verification matrix.
- **Tech Stack CVE Intelligence & Software Composition Analysis (SCA)**:
  - Automated component fingerprinting from HTTP banners (`Server`, `X-Powered-By`, `Via`) and dependency manifests (`requirements.txt`, `package.json`, `pom.xml`).
  - Correlates known high-impact CVEs, CVSS scores, affected version ranges, and official remediation paths (Apache HTTP Server, PHP, Werkzeug, Log4j, Spring Boot/Core, jQuery, OpenSSL, etc.).
  - Deterministic `CveVerifier` verifies whether detected versions empirically corroborate the vulnerable range before confirmation.
- **Broad & Extensible PoC Verifier Engine (16+ Classes & Universal Composable Predicates)**:
  - **Universal Generic Assertion Verifier**: Host models can verify **any novel or arbitrary vulnerability class** through multi-predicate contracts: `StatusCodeEquals`, `BodyContains`, `BodyRegexMatches`, `HeaderEquals`, `HeaderContains`, `DifferentialMinLengthDelta`, `TimingMinDelayMs`, and `CallbackCorrelation`.
  - **15+ First-Class Built-in Verifiers**:
    - **IDOR / BOLA**: Verifies unauthorized access across isolated session contexts with object ownership differentials.
    - **Auth Bypass**: Confirms state transitions and access to protected resources despite stripped or forged credentials.
    - **Command Injection / RCE**: Validates command execution via unique mathematical markers, token expressions, or reproducible sleep delays.
    - **Path Traversal / LFI**: Confirms arbitrary file disclosure with signature verification against standard baselines.
    - **XSS**: Requires proof of active JavaScript execution inside the target origin DOM sink (simple string reflection is rejected).
    - **SQL Injection**: Requires repeatable boolean or time-based differentials across multiple runs to rule out network jitter.
    - **SSRF**: Correlates outbound target callbacks against controlled listeners with nonce verification and client loopback filtering.
    - **Open Redirect**: Verifies unvalidated 3xx redirects to external untrusted domains.
    - **CORS Misconfiguration**: Confirms arbitrary origin reflection paired with `Access-Control-Allow-Credentials: true`.
    - **Sensitive Information Disclosure**: Validates regex patterns for exposed secrets, API keys, private keys, or stack traces on unauthenticated endpoints.
    - **Mass Assignment / Broken Property Authorization**: Verifies protected attribute mutation.
    - **CSRF**: Verifies state mutation without CSRF tokens or SameSite origin controls.
    - **Race Condition / Concurrency**: Confirms limit overrun via parallel executions.
    - **Prototype Pollution**: Proves persistent `__proto__` pollution across requests.
    - **Rate Limit Bypass**: Proves missing throttling on sensitive authentication routes.
- **Hardened Docker Sandboxing**:
  - In-memory `tmpfs` RAM execution (`/sandbox` and `/tmp`) with zero host disk I/O and ~390ms latency.
  - Read-only root filesystem (`readonly_rootfs: true`).
  - Unprivileged user execution (`nobody` / UID 1000).
  - Dropped Linux capabilities (`cap-drop=ALL`) and `no-new-privileges`.
  - Strict resource constraints (memory, nano-CPUs, process limits, and execution timeouts).
  - Default network isolation (`network_mode: none`, with opt-in `SECARBITER_SANDBOX_NETWORK=bridge`).
  - Absolute isolation from the host Docker socket (`/var/run/docker.sock`).

---

## Workspace Architecture

The project is structured as a modular Rust Cargo workspace:

```
secarbiter/
├── Cargo.toml                     # Workspace root manifest
├── install.sh                     # Zero-dependency install script (supports web pipe & local repo)
├── Makefile                       # Developer shortcuts (build, test, docker, install)
├── docker/
│   ├── executor.Dockerfile        # Hardened sandbox image (Python 3, curl, jq, bash)
│   └── network-policy.sh          # Network bridge & isolation policy
├── crates/
│   ├── pentest-core/              # Domain entities, ScopeChecker, and SQLite storage
│   ├── pentest-evidence/          # Immutable evidence store, SHA-256 hashing, and secret redactor
│   ├── pentest-executor/          # Docker execution engine (bollard) & forensic HTTP runner
│   ├── pentest-verifier/          # Deterministic PoC verifier engine for 16+ vulnerability classes
│   ├── pentest-report/            # Markdown reports, JSON snapshots, and standalone script generators
│   └── pentest-mcp/               # Dual-Interface binary (secarbiter & secarbiter-mcp)
└── tests/                         # End-to-end integration and acceptance suites
```

---

## The 16 MCP Tool Contracts

| Tool | Responsibility |
|---|---|
| `engagement_create` | Initializes scope allowlists, denied paths, and resource limits. |
| `engagement_get` | Retrieves engagement status, configuration, and vulnerability summary. |
| `session_register` | Securely stores test account auth headers/cookies under an isolated reference ID. |
| `browser_action` | Simulated browser interactions with DOM snapshot emulation (full headless engine in development). |
| `http_send` | Dispatches in-scope HTTP requests, returning status and evidence artifact IDs. |
| `http_replay` | Replays a previous request artifact with specific mutations and returns differentials. |
| `tool_run` | Runs a custom script or external security utility inside a sandboxed Docker container. |
| `job_get` | Reads asynchronous job execution progress, exit code, and stdout/stderr previews. |
| `job_cancel` | Terminates a running execution job. |
| `artifact_read` | Reads forensic evidence chunks with byte offset, length limit, and secret redaction. |
| `finding_draft` | Records a vulnerability hypothesis in `suspected` status. |
| `poc_validate` | Evaluates structured assertions via backend verifiers; only verified PoCs become `confirmed`. |
| `finding_retest` | Evaluates remediation status (`fixed`, `open`, or `inconclusive`) on updated targets. |
| `report_export` | Exports sanitized Markdown assessment reports or full JSON snapshots. |
| `poc_generate_script` | Generates a standalone executable reproduction script (cURL bash or Python 3) with CI/CD exit codes. |
| `cve_scan` | Fingerprints tech stack banners or manifests against known CVEs, drafts findings, and suggests verification assertions. |

---

## Quick Install

### Option A: Web One-Liner (`curl | bash`)
Install directly in one command without manually cloning:

```bash
curl -fsSL https://raw.githubusercontent.com/arifpambudi242/secarbiter/main/install.sh | bash
```

### Option B: Local Repository Installer
If you have already cloned the repository:

```bash
git clone https://github.com/arifpambudi242/secarbiter.git && cd secarbiter
./install.sh
```

### Option C: Cargo Install
```bash
cargo install --path crates/pentest-mcp
# Or directly from Git:
# cargo install --git https://github.com/arifpambudi242/secarbiter
docker build -t secarbiter-sandbox:latest -t pentest-sandbox:latest -f docker/executor.Dockerfile docker/
```

### Option D: Claude Code One-Liner
If you use [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code):
```bash
claude mcp add secarbiter -- secarbiter-mcp
```

---

## Dual-Interface Architecture (MCP + Developer CLI)

SecArbiter builds a unified dual-interface binary (`secarbiter` / `secarbiter-mcp`). It serves both autonomous AI coding agents via stdio JSON-RPC and human engineers / CI-CD pipelines via terminal CLI:

### 1. Mode MCP (Autonomous AI Agents)
Running the binary without subcommands (or passing `--mcp` / `serve`) starts the JSON-RPC stdio server:
```bash
# Started automatically by Claude Desktop, Antigravity, or Cursor
secarbiter-mcp
# or
secarbiter serve
```

### 2. Mode CLI (Developers & CI/CD Pipelines)
Direct terminal subcommands with human-friendly tables or machine-readable `--json` output:

```bash
# Scan target endpoint and lockfile for known CVEs (exits with code 1 if CVEs detected)
secarbiter scan http://127.0.0.1:8765/ --manifest requirements.txt

# Manage engagements and scope boundaries
secarbiter engagements create --name "Q4 Audit" --allowed-hosts 127.0.0.1,localhost --allow-private-ips
secarbiter engagements list

# Draft a suspected finding
secarbiter draft -e <ENGAGEMENT_UUID> -t "IDOR in Invoices" -c idor -u /api/invoices -s HIGH

# Deterministically verify a PoC assertion
secarbiter verify -f <FINDING_UUID> -a assertion.json

# Generate standalone reproduction script for developers (curl or python)
secarbiter poc -f <FINDING_UUID> -t curl -o reproduce_poc.sh
secarbiter poc -f <FINDING_UUID> -t python -o reproduce_poc.py

# Export redacted security assessment report
secarbiter report -e <ENGAGEMENT_UUID> -f markdown -o audit_report.md

# Auto-configure MCP client (Claude Desktop / Cursor IDE)
secarbiter install mcp

# Install Agent operational SKILL.md into local skills directory
secarbiter install skill
```

---

## Getting Started

### Prerequisites

- **Rust**: Version 1.70+ (recommended: Rust 1.80+ stable toolchain).
- **Docker**: Version 20.10+ running with socket access for unprivileged containers.

### 1. Build the Sandbox Docker Image

```bash
make docker
# or
docker build -t secarbiter-sandbox:latest -t pentest-sandbox:latest -f docker/executor.Dockerfile docker/
```

### 2. Compile and Test the Workspace

```bash
# Verify all crates
cargo check --workspace

# Run all unit tests and acceptance suites
cargo test --workspace

# Build the release binary
cargo build --release --workspace
```

The compiled binaries will be located at `target/release/secarbiter` and `target/release/secarbiter-mcp`.

---

## Configuring with MCP Hosts

The server communicates over standard input/output (`stdio`) using JSON-RPC 2.0. Internal diagnostic logs are routed exclusively to `stderr` to maintain clean protocol streams.

### Example MCP Client Configuration

#### Claude Desktop / Claude Code (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "secarbiter": {
      "command": "secarbiter-mcp",
      "env": {
        "SECARBITER_DATA_DIR": "/path/to/data",
        "RUST_LOG": "info"
      }
    }
  }
}
```

#### Cursor IDE (`.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "secarbiter": {
      "command": "secarbiter-mcp"
    }
  }
}
```

#### Antigravity / Codex:
Add the server definition to your toolchain configuration:
```json
{
  "mcpServers": {
    "secarbiter": {
      "command": "secarbiter-mcp"
    }
  }
}
```

---

## Automated OWASP Verification Suite

To verify the deterministic engine against a live OWASP Top 10 mock testbed:

```bash
python3 examples/owasp_top10_suite.py
```

Expected output:
```
========================================================================
                   OWASP TOP 10 SCORECARD SUMMARY                       
========================================================================
Category       | Vulnerability Name           | Status         | PoC Script
----------------------------------------------------------------------------
OWASP A01      | IDOR / BOLA                  | CONFIRMED      | reproduce_poc.sh
OWASP A01      | Path Traversal               | CONFIRMED      | reproduce_poc.sh
OWASP A05      | CORS Misconfig               | CONFIRMED      | reproduce_poc.sh
OWASP A02      | Sensitive Data Leak          | CONFIRMED      | reproduce_poc.py
OWASP A03      | SQL Injection                | CONFIRMED      | reproduce_poc.sh
OWASP A03      | Command Injection            | CONFIRMED      | reproduce_poc.sh
OWASP A03      | Cross-Site Scripting         | INCONCLUSIVE*  | reproduce_poc.sh
OWASP A04      | Rate Limit Bypass            | INCONCLUSIVE*  | reproduce_poc.sh
OWASP A05      | Open Redirect                | CONFIRMED      | reproduce_poc.sh
OWASP A07      | Auth Bypass                  | CONFIRMED      | reproduce_poc.sh
OWASP A10      | SSRF                         | INCONCLUSIVE*  | reproduce_poc.py
TechStack CVE  | CVE-2021-41773 (Apache)      | CONFIRMED      | reproduce_poc.sh
----------------------------------------------------------------------------
Total OWASP Categories Evaluated: 12
Empirically Confirmed (Wire Grounded):  9/12
Inconclusive (Host-Attested Claims):    3/12
  * Inconclusive: Capped safely because forensic wire artifacts alone
    cannot independently prove DOM sinks (XSS), out-of-band hits (SSRF),
    or multi-transaction quotas (Rate Limit) without auxiliary telemetry.
========================================================================
```

For complete empirical verification mapping and test commands across all capabilities, see [docs/CLAIMS.md](docs/CLAIMS.md).

---

## Security Invariants

1. **Zero Hallucination Verification**: A finding cannot transition to `confirmed` without verifiable empirical evidence validated by `pentest-verifier`. Status code 200 alone or AI speculation is strictly insufficient.
2. **Deterministic Reproduction**: Generated reproduction scripts (cURL and Python 3) return exit code 0 when a vulnerability is present, and non-zero when fixed, making them fully automatable in CI/CD pipelines.
3. **Evidence Immutability**: All captured raw payloads and traffic are written to disk with SHA-256 integrity digests before processing.
4. **Credential Redaction**: Authorization tokens, session cookies, and basic auth headers are redacted immediately upon ingestion and masked in all reports.

---

## License

This project is licensed under the [MIT License](LICENSE).
