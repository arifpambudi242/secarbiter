# SecArbiter Integration & Verification Examples

This directory provides enterprise integration examples, automated verification suites, and developer workflows that showcase the core architectural capabilities of **SecArbiter**:

```
examples/
├── agent_remediation_loop.py      # Flagship Autonomous Verify-Fix-Retest closed loop
├── quickstart_tutorial.sh         # 60-second interactive developer terminal walkthrough
├── owasp_top10_suite.py           # Live E2E test suite covering 12 OWASP Top 10 categories
├── ci_pipeline_gate/              # GitHub Actions & CI/CD pull request security gate
│   ├── github_action_security_gate.yml
│   ├── ci_gate_runner.sh
│   └── README.md
├── blueprints/                    # Verifiable JSON Assertion Contracts
│   ├── multi_tenant_idor_contract.json
│   ├── auth_bypass_header_override_contract.json
│   ├── credential_regex_disclosure_contract.json
│   ├── timing_sidechannel_contract.json
│   └── README.md
└── vulnerable_app/                # Self-contained, zero-dependency OWASP mock application
    ├── app.py
    └── requirements.txt
```

---

## 1. Flagship: The Autonomous Closed-Loop Demo (`agent_remediation_loop.py`)

Demonstrates what separates SecArbiter from generic MCP servers:
1. **Strict Scope Safeguards**: Blocks rogue out-of-scope probes (`ScopeViolation`).
2. **Zero-Hallucination Gate**: Evaluates a speculative AI hypothesis and **rejects it** (`NOT_REPRODUCED`), stopping false positive reports before they reach engineers.
3. **Deterministic Breach Verification**: Empirically validates a genuine IDOR vulnerability, writing SHA-256 evidence.
4. **Standalone Script Generation**: Emits an executable reproduction script (`reproduce_poc.sh`) with standardized exit codes (0 = vulnerable, 1 = fixed).
5. **Remediation & Autonomous Retest**: Applies a live patch to the application and validates that `finding_retest` transitions the status to **`FIXED`**.

Run it with:
```bash
python3 examples/agent_remediation_loop.py
```

---

## 2. 60-Second Hands-On Developer Quickstart (`quickstart_tutorial.sh`)

A guided, color-coded walkthrough of the `secarbiter` developer CLI:
```bash
./examples/quickstart_tutorial.sh
```

---

## 3. Full OWASP Top 10 Verification Suite (`owasp_top10_suite.py`)

Executes 12 deterministic verifications against live mock endpoints:
- A01: IDOR / BOLA
- A01: Path Traversal / LFI
- A05: Insecure CORS Reflection
- A02: Secret & Credential Disclosure
- A03: SQL Injection (Boolean & Time Differential)
- A03: OS Command Injection / RCE
- A03: Reflected Cross-Site Scripting (DOM proof)
- A04: Missing Rate Limiting on Authentication
- A05: Open Redirect
- A07: Authentication Bypass via Header Tampering
- A10: Server-Side Request Forgery (Outbound Callback Correlation)
- Supply Chain: Tech Stack CVE Correlation & Version Windowing

Run it with:
```bash
python3 examples/owasp_top10_suite.py
```

---

## 4. CI/CD Merge Gate (`ci_pipeline_gate/`)

Contains scripts and GitHub Actions workflows to fail pull requests when critical security regressions or vulnerable dependencies are detected:
```bash
./examples/ci_pipeline_gate/ci_gate_runner.sh
```

---

## 5. Universal Assertion Blueprints (`blueprints/`)

Reference JSON contracts for composing multi-predicate verifications (`StatusCodeEquals`, `BodyContains`, `TimingMinDelayMs`, `DifferentialMinLengthDelta`).
