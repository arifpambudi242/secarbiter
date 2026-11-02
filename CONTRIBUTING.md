# Contributing to SecArbiter

Thank you for your interest in contributing to **SecArbiter** (Deterministic Security Verification Engine & Dual-Interface MCP Server / Developer CLI)! We welcome contributions ranging from new vulnerability verifiers and scanner capabilities to performance improvements and documentation.

This guide outlines our development philosophy, repository structure, coding standards, and pull request workflow.

---

## 1. Core Architectural Invariants

Before writing any code, please familiarize yourself with the 4 core non-negotiable principles of this project:

1. **Zero-LLM on Server**: The MCP server and CLI must never invoke an external LLM API, embed inference models, or request user LLM API keys. The host model (Claude, Codex, Antigravity, Cursor) is the reasoning orchestrator; our server is the deterministic execution, sandboxing, and forensic verification engine.
2. **Deterministic Evidence Contracts**: A finding can only be marked as `confirmed` if a backend verifier in `pentest-verifier` validates empirical forensic proof. HTTP 200 alone, exit code 0 alone, or speculative text descriptions are never sufficient to declare a confirmed vulnerability.
3. **Strict Network & Scope Isolation**: All network operations (`http_send`, `http_replay`, Docker sandbox runs) must strictly validate target URLs against `ScopeChecker`. DNS pinning and redirect inspection are mandatory to prevent unauthorized scans or SSRF against unintended destinations.
4. **Credential Privacy**: Raw authentication tokens, JWTs, cookies, and sensitive payload parameters must be redacted immediately upon receipt by `Redactor` before any output leaves the server or gets saved to reports.

---

## 2. Workspace Structure

The project is structured as a modular Rust Cargo workspace:

```
pentest_tool/
├── crates/
│   ├── pentest-core/       # Domain entities, ScopeChecker, SQLite persistence
│   ├── pentest-evidence/   # Immutable forensic evidence store, SHA-256 digests, secret redactor
│   ├── pentest-executor/   # Hardened Docker sandbox runner (bollard) & scope-enforced HTTP runner
│   ├── pentest-verifier/   # Deterministic PoC verifier engines (16+ classes & universal predicates)
│   ├── pentest-report/     # Markdown audit reports, JSON snapshots, and standalone PoC script generators
│   └── pentest-mcp/        # Dual-interface binary: Stdio JSON-RPC 2.0 MCP server & Developer CLI
├── docker/                 # Hardened Alpine executor Dockerfile and network policies
├── examples/               # Intentionally vulnerable testbed application & live E2E acceptance suites
├── install.sh              # Standalone web & local installer script
└── Makefile                # Developer convenience commands
```

---

## 3. Getting Started & Development Setup

### Prerequisites
- **Rust**: Version 1.70+ (recommended: stable 1.95+).
- **Docker**: Version 20.10+ (for running sandboxed tool executions).
- **Python**: Version 3.10+ (for running the live testbed suite in `examples/`).

### Local Build & Test Commands

```bash
# 1. Clone the repository
git clone https://github.com/arifpambudi242/secarbiter.git
cd secarbiter

# 2. Build the Docker sandbox image
make docker
# or: docker build -t pentest-sandbox:latest -f docker/executor.Dockerfile docker/

# 3. Check code formatting and clippy lints
cargo fmt --check
cargo clippy --workspace -- -D warnings

# 4. Run the full unit and acceptance test suites
cargo test --workspace

# 5. Run the end-to-end live testbed suite
python3 examples/owasp_top10_suite.py
```

---

## 4. How to Add a New Vulnerability Verifier

When introducing a new vulnerability class (e.g. `graphql_injection`, `websocket_smuggling`):

1. **Add to Domain Enum**:
   Update `VulnClass` in `crates/pentest-core/src/domain/mod.rs` if a first-class variant is warranted.
2. **Implement the Verifier Module**:
   Create `crates/pentest-verifier/src/<name>.rs` defining:
   - An evidence assertion struct (e.g., `<Name>EvidenceAssertion`).
   - A verifier struct implementing `verify(&assertion) -> (FindingStatus, String)`.
3. **Write Unit Tests (Mandatory)**:
   Every verifier must include:
   - At least **one positive test case**: Verifies that genuine breach evidence returns `FindingStatus::Confirmed`.
   - At least **one negative control test case**: Verifies that blocked, patched, or harmless responses return `FindingStatus::NotReproduced`.
   - At least **one inconclusive test case**: Verifies that ambiguous or missing corroboration returns `FindingStatus::Inconclusive`.
4. **Wire into Verifier Engine**:
   Register the verifier in `crates/pentest-verifier/src/engine.rs` and re-export in `crates/pentest-verifier/src/lib.rs`.
5. **Update Acceptance Tests**:
   Ensure `crates/pentest-mcp/tests/mcp_acceptance.rs` covers the new verifier flow.

---

## 5. Coding Standards & Best Practices

- **Zero Placeholders**: Never submit code containing placeholders, truncated implementations, or comments like `// TODO: implement later`. Write full, production-ready implementations.
- **Fail-Safe Code Navigation**: If `.codegraph/` exists, use `codegraph explore "<query>"` to trace symbols and blast radius before modifying existing modules.
- **Formatting**: Always format your code with standard Rust formatter:
  ```bash
  cargo fmt
  ```
- **Linter Cleanliness**: Your code must pass with zero clippy warnings:
  ```bash
  cargo clippy --workspace -- -D warnings
  ```
- **Conventional Commits**: Write concise, objective commit messages following the Conventional Commits specification:
  - `feat(scope): short description`
  - `fix(scope): short description`
  - `perf(scope): short description`
  - `docs(scope): short description`
  - `test(scope): short description`
- **Zero Watermarks**: Do not add artificial watermarks, branding, or AI-generated signature trailers (e.g., `Co-authored-by`, `Made with...`) in commit messages or code comments.

---

## 6. Pull Request (PR) Checklist

Before submitting your Pull Request, verify that:

- [ ] All crates compile cleanly with `cargo check --workspace`.
- [ ] Code is formatted with `cargo fmt --check`.
- [ ] Clippy passes with zero warnings: `cargo clippy --workspace -- -D warnings`.
- [ ] Full workspace tests pass: `cargo test --workspace`.
- [ ] MCP acceptance test passes: `cargo test -p pentest-mcp --test mcp_acceptance`.
- [ ] Live suite passes: `python3 examples/owasp_top10_suite.py`.
- [ ] Claims ledger [`docs/CLAIMS.md`](docs/CLAIMS.md) is updated with empirical verification references if capabilities are added or altered.
- [ ] Documentation (`README.md`, `AGENTS.md`) is updated if you added new tools, flags, or verifiers.
- [ ] Your branch is up to date with the latest `main`.

Thank you for helping make automated agentic security testing deterministic, safe, and reliable!
