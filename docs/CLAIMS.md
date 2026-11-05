# SecArbiter Capability Claims & Empirical Verification Matrix

SecArbiter operates under an **evidence-based engineering standard**: no capability is claimed in documentation without an accompanying on-disk implementation and an automated verification test.

This document serves as the authoritative claims ledger for SecArbiter. It explicitly details what the system verifies deterministically, what boundaries are enforced, and how each claim is tested.

---

## 1. Capability Verification Ledger

| Feature / Claim | Implementation Source | Test Suite & Command | Empirical Status & Verification Boundary |
| :--- | :--- | :--- | :--- |
| **Strict Scope Enforcement** | [`ScopeChecker`](file:///crates/pentest-core/src/scope/mod.rs#L8) | `cargo test -p pentest-core test_scope_checker` | **Fully Verified**. Blocks RFC 1918 private subnets, loopback, link-local, non-whitelisted domains/IPs, and denied URI prefixes. Resolves DNS at inspection time. |
| **True DNS Pinning** | [`HttpRunner::execute_request`](file:///crates/pentest-executor/src/http.rs#L74) | `cargo test -p pentest-mcp --test mcp_acceptance` | **Fully Verified**. Binds outbound TCP directly to the verified socket IP via `reqwest::ClientBuilder::resolve(host, socket_addr)` while preserving TLS SNI and HTTP `Host` headers, fully mitigating TOCTOU DNS rebinding. |
| **Active Job Cancellation** | [`handle_job_cancel`](file:///crates/pentest-mcp/src/tools.rs#L745), [`DockerExecutor::kill_job_container`](file:///crates/pentest-executor/src/docker.rs#L210) | `cargo test -p pentest-mcp --test mcp_acceptance` | **Fully Verified**. Actively aborts the Tokio async task (`AbortHandle`) and terminates the running container on the Docker daemon (`kill_container` / `remove_container`) rather than merely changing SQLite state. |
| **Forensic Evidence Grounding** | [`ArtifactGrounder`](file:///crates/pentest-verifier/src/grounding.rs#L12), [`VerifierEngine`](file:///crates/pentest-verifier/src/engine.rs#L25) | `cargo test -p pentest-verifier test_artifact_grounder` | **Fully Verified**. Cross-references assertion claims against raw HTTP wire captures (`HttpRecord`). Rejects forged assertions (e.g., claiming 200 when raw response was 401) with `Inconclusive`. |
| **Evidence Type & Engagement Binding** | [`VerifierEngine::ensure_http_evidence`](file:///crates/pentest-verifier/src/engine.rs), [`VerifierEngine::validate_and_record`](file:///crates/pentest-verifier/src/engine.rs), [`handle_finding_retest`](file:///crates/pentest-mcp/src/tools.rs), [`handle_http_replay`](file:///crates/pentest-mcp/src/tools.rs) | `cargo test -p pentest-verifier engine::tests` (`test_tool_output_transcript_is_not_evidence`, `test_tool_output_control_is_not_evidence`, `test_artifact_from_other_engagement_is_rejected`, `test_same_transcript_as_http_transaction_is_confirmed`) | **Fully Verified**. Exploit and control artifacts must have `artifact_type = "http_transaction"` and the finding's `engagement_id`; anything else fails `poc_validate` with `ValidationError` before a validation run is written, leaving the finding status and evidence pointers unchanged. A `tool_output` artifact byte-identical to a real capture is rejected, while the same bytes stored as `http_transaction` still confirm. `finding_retest` does not replay such an artifact (it takes the same manual path as a missing artifact) and `http_replay` refuses it as a base. Boundary: the check trusts the `artifact_type` column, which only the server writes (`HttpRunner` writes `http_transaction`, `tool_run` writes `tool_output`); an actor with direct write access to the SQLite file or evidence directory is outside this model. The manual `is_still_vulnerable` override in `finding_retest` is unchanged and remains host-attested. |
| **Boundary-Capped Assertions** | [`ArtifactGrounder::ground`](file:///crates/pentest-verifier/src/grounding.rs#L40) | `cargo test -p pentest-mcp --test mcp_acceptance` | **Enforced by Design**. Vulnerability types that cannot be verified solely from raw HTTP wire captures (DOM XSS execution, out-of-band SSRF listener nonces, aggregate rate limits) are safely capped at `Inconclusive` with host-attestation notices. |
| **Live Retest Engine** | [`handle_finding_retest`](file:///crates/pentest-mcp/src/tools.rs#L920) | `python3 examples/agent_remediation_loop.py` | **Fully Verified**. Re-executes the saved HTTP transaction against the target URL via `HttpRunner`. If patched (returns 401/403/404), updates status to `Fixed`; if still vulnerable (returns 200), marks as `Open`. |
| **Isolated Docker Sandbox** | [`DockerExecutor`](file:///crates/pentest-executor/src/docker.rs#L24) | `cargo test -p pentest-executor test_docker_executor` | **Fully Verified**. Runs security tools in unprivileged containers (`user: "nobody"`), drops kernel capabilities (`cap_drop: ["ALL"]`), enforces cgroups memory limits (default 512 MB), execution timeouts, and defaults to `network_mode: none` (opt-in `SECARBITER_SANDBOX_NETWORK=bridge`). |
| **SQLite Concurrency & WAL** | [`SqliteStore::run_migrations`](file:///crates/pentest-core/src/storage/mod.rs#L33) | `cargo test -p pentest-core test_sqlite_in_memory_crud` | **Fully Verified**. Configures `PRAGMA journal_mode = WAL`, `PRAGMA busy_timeout = 5000`, and `PRAGMA synchronous = NORMAL`, allowing concurrent CLI operations without database locked errors. |
| **Sensitive Data Redaction** | [`Redactor`](file:///crates/pentest-evidence/src/redaction.rs#L8) | `cargo test -p pentest-evidence test_redactor` | **Fully Verified**. Redacts Bearer tokens, Authorization headers, Cookies, and API keys before output is returned to LLM hosts or written to reports, while preserving raw forensic wire captures on disk. |
| **Deterministic PoC Scripts** | [`ScriptGenerator`](file:///crates/pentest-report/src/script_generator.rs#L9) | `cargo test -p pentest-report test_script_generator` | **Fully Verified**. Generates standalone cURL and Python PoCs adhering to deterministic exit codes: `0` (vulnerability confirmed/reproduced), `1` (remediated / access denied), `2` (network unreachable / connection error). |
| **Tech Stack CVE Scanner** | [`CveScanner`](file:///crates/pentest-verifier/src/cve.rs#L12) | `cargo test -p pentest-verifier test_cve_scanner` | **Fully Verified**. Matches HTTP banners and software manifests against an embedded database of known CVEs, generating draft findings and verifiable assertions. Enforces strict private network protection unless explicit opt-in is provided. |
| **Simulated Browser Action** | [`handle_browser_action`](file:///crates/pentest-mcp/src/tools.rs#L590) | `cargo test -p pentest-mcp --test mcp_acceptance` | **Scope-Enforced Simulation**. Enforces `ScopeChecker` allowlists on target URLs before producing simulated DOM snapshots with notice `mode: "simulated"`. Full Playwright engine integration is currently in development. |

---

## 2. OWASP Top 10 Grounding Breakdown

When tested against the comprehensive testbed (`examples/owasp_top10_suite.py`), SecArbiter evaluates 12 vulnerability scenarios:

| Category | Vulnerability Class | Grounding Method | Wire Evidence Verdict |
| :--- | :--- | :--- | :--- |
| **OWASP A01** | IDOR / BOLA | Direct HTTP Response (Status 200 + victim data) | **CONFIRMED** |
| **OWASP A01** | Path Traversal / LFI | Direct HTTP Response (Body contains `root:x:0:0`) | **CONFIRMED** |
| **OWASP A01** | CORS Misconfiguration | HTTP Response Header (`Access-Control-Allow-Origin: evil.com`) | **CONFIRMED** |
| **OWASP A02** | Sensitive Data Exposure | Direct HTTP Response (Body contains `[core]` config leak) | **CONFIRMED** |
| **OWASP A03** | SQL Injection | Boolean Differential (Length delta between true and false artifacts) | **CONFIRMED** |
| **OWASP A03** | Command Injection / RCE | Direct HTTP Response (Body contains `uid=0(root)`) | **CONFIRMED** |
| **OWASP A03** | Cross-Site Scripting (XSS) | Wire capture verifies reflection; DOM execution requires browser engine | **INCONCLUSIVE\*** |
| **OWASP A04** | Missing Rate Limiting | Wire capture verifies single request; aggregate limit requires session log | **INCONCLUSIVE\*** |
| **OWASP A05** | Open Redirect | HTTP Header (`Location: https://attacker-phish.com`) | **CONFIRMED** |
| **OWASP A07** | Authentication Bypass | Direct HTTP Response (Status 200 without valid credentials) | **CONFIRMED** |
| **OWASP A10** | SSRF | Wire capture verifies relay; callback listener nonce requires out-of-band log | **INCONCLUSIVE\*** |
| **CVE** | Known Tech Stack Flaws | Server Header & Manifest Fingerprint (`CVE-2021-41773`) | **CONFIRMED** |

> **\* Honest Assurance Note on Inconclusive Verdicts:**
> Rather than blindly trusting LLM host claims, SecArbiter caps assertions as `inconclusive` whenever stored wire captures cannot independently confirm the exploit condition. This prevents false positives and ensures every `confirmed` finding is backed by irrefutable proof.
