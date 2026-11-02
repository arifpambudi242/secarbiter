# Agent Guidance & Repository Rules (AGENTS.md)

This document provides operational principles, architecture context, and coding rules for autonomous AI coding agents working on the **SecArbiter** codebase.

---

## 1. Core Architectural Invariants

1. **Zero-LLM on Server**: The server must never invoke an external LLM API, embed inference models, or request user LLM API keys. The host model is the orchestrator; the server is the execution and verification engine.
2. **Deterministic Evidence Contracts**: A vulnerability can only be marked as `confirmed` if backend verifiers (`pentest-verifier`) validate empirical evidence. Exit code 0, HTTP 200 alone, or speculative text descriptions are never sufficient.
3. **Strict Network & Scope Isolation**: All network operations (`http_send`, `http_replay`, Docker sandbox runs) must pass through `ScopeChecker`. DNS pinning and redirect inspection are mandatory to prevent unauthorized destination scans.
4. **Credential Privacy**: Raw authentication tokens, passwords, cookies, and private parameters must be redacted immediately upon receipt and before any output leaves the server.

---

## 2. Codebase Navigation Protocol (FAIL-SAFE)

When locating symbols, tracing call paths, or analyzing blast radius:

1. **Primary Tool**: Use `codegraph_explore` (MCP) or run `codegraph explore "<query>"` in the workspace root. CodeGraph is already indexed (`.codegraph/`).
2. **Fallback**: Use `semble` if CodeGraph returns no match.
3. **Literal Non-Code Search**: Only use `rg` or `grep` for exact raw string literals (e.g. error codes, schema keys). Do not bypass CodeGraph for semantic code analysis.

---

## 3. Rust Cargo Workspace Structure

- [`crates/pentest-core`](crates/pentest-core):
  - Domain entities: `Engagement`, `SessionRef`, `Asset`, `Job`, `Finding`, `ValidationRun`, `RetestRun`.
  - [`ScopeChecker`](crates/pentest-core/src/scope/mod.rs): IP allowlisting, CIDR subnet matching, RFC 1918 blocking, path denylist validation.
  - [`SqliteStore`](crates/pentest-core/src/storage/mod.rs): Schema migrations and CRUD operations.
- [`crates/pentest-evidence`](crates/pentest-evidence):
  - [`EvidenceStore`](crates/pentest-evidence/src/store.rs): Immutable file-based forensic storage with SHA-256 digests and chunked pagination.
  - [`Redactor`](crates/pentest-evidence/src/redaction.rs): Automatic secret masking for Bearer tokens, cookies, and credential payloads.
- [`crates/pentest-executor`](crates/pentest-executor):
  - [`DockerExecutor`](crates/pentest-executor/src/docker.rs): Bollard-backed container runner with unprivileged user, cap-drop, memory, and timeout controls.
  - [`HttpRunner`](crates/pentest-executor/src/http.rs): Scope-enforced HTTP/1.1 transaction runner capturing raw forensic evidence.
- [`crates/pentest-verifier`](crates/pentest-verifier):
  - Dedicated PoC verifiers: `IdorVerifier`, `AuthBypassVerifier`, `XssVerifier`, `SqliVerifier`, `SsrfVerifier`, `RceVerifier`, `PathTraversalVerifier`, `OpenRedirectVerifier`, `CorsVerifier`, `InfoDisclosureVerifier`, `RateLimitVerifier`, `MassAssignmentVerifier`, `CveVerifier`.
  - [`GenericAssertionVerifier`](crates/pentest-verifier/src/generic.rs): Composable multi-predicate engine (`StatusCodeEquals`, `BodyContains`, `BodyRegexMatches`, `HeaderEquals`, `DifferentialMinLengthDelta`, `TimingMinDelayMs`, `CallbackCorrelation`) capable of verifying arbitrary / novel vulnerability PoCs without schema dead-ends.
  - [`VerifierEngine`](crates/pentest-verifier/src/engine.rs): Evaluates assertions against artifacts and updates finding status in SQLite.
- [`crates/pentest-report`](crates/pentest-report):
  - [`MarkdownReportGenerator`](crates/pentest-report/src/markdown.rs): Developer-friendly Markdown reports with secret redaction.
  - [`ReportJsonSnapshot`](crates/pentest-report/src/snapshot.rs): Structured audit logs and replay bundle metadata.
  - [`ScriptGenerator`](crates/pentest-report/src/script_generator.rs): Generates standalone cURL and Python reproduction scripts with exit code semantics.
- [`crates/pentest-mcp`](crates/pentest-mcp):
  - Dual-interface binary (`pentest` / `pentest-mcp`):
    - MCP JSON-RPC 2.0 stdio transport server handling `initialize`, `tools/list`, and `tools/call`.
    - Standalone developer CLI (`scan`, `verify`, `poc`, `report`, `draft`, `engagements`).
  - Implements the 16 tool dispatchers (including `cve_scan` and `poc_generate_script`).

---

## 4. Development & Verification Discipline

### Test-First & No Laziness
- Always implement complete functions. Never use placeholders, truncated blocks, or comments like `// TODO: implement later`.
- Run compiler checks and test suites after every meaningful change:
  ```bash
  cargo check --workspace
  cargo test --workspace
  ```
- Before proposing or committing code changes, run:
  ```bash
  cargo test -p pentest-mcp --test mcp_acceptance
  ```

### Branching & Commit Guidelines
- Always work on a feature branch (e.g. `feat/...` or `fix/...`). Never commit directly to `main`.
- Write concise, objective commit messages describing what changed and why.
- Never add agent watermarks, AI branding, or co-authorship trailers in commit messages or code comments.

---

## 5. Adding New Verifiers or Tools

When introducing a new vulnerability verifier or extending existing tools:
1. Define the verifier logic under `crates/pentest-verifier/src/<class>.rs`.
2. Include at least one **positive test case** (verifies confirmed breach) and one **negative control case** (verifies that blocked or harmless behavior results in `not_reproduced` or `inconclusive`).
3. Wire the verifier into `VerifierEngine::validate_and_record`.
4. Update the tool registry schema in `crates/pentest-mcp/src/tools.rs`.
5. Run full workspace tests to ensure no regressions across existing verifier modules.

---

## 6. Empirical Verification & Claims Ledger

All claimed features and capabilities must be documented in [`docs/CLAIMS.md`](docs/CLAIMS.md) with exact pointers to:
- Implementation file and symbol.
- Automated test command and verification boundary.
- Any capability not directly verifiable from captured raw wire artifacts must be honestly qualified or capped at `inconclusive`. Never invent or inflate verification statistics in docs or pull requests.
