# SecArbiter PoC Assertion Blueprints

This directory contains reference assertion contracts illustrating how host AI models and security engineers verify vulnerabilities deterministically in SecArbiter.

## The Problem with LLM-Only Pentesting

LLMs without a deterministic arbiter frequently suffer from **confirmation bias**:
- Seeing HTTP 200 and claiming an exploit succeeded when the endpoint actually returned an error message.
- Claiming SQL injection succeeded based on natural language text without timing or boolean differentials.
- Reporting IDOR when the request only returned public unprivileged data.

## Deterministic Evidence Contracts Architecture

SecArbiter replaces speculative prose with **verifiable JSON contracts**:

| Blueprint | Vulnerability Target | Deterministic Proof Mechanism |
|---|---|---|
| [`multi_tenant_idor_contract.json`](multi_tenant_idor_contract.json) | IDOR / BOLA | Requires cross-tenant session differential and owner-specific data matching. |
| [`auth_bypass_header_override_contract.json`](auth_bypass_header_override_contract.json) | Authentication Bypass | Requires baseline 401/403 proof + bypass 200 proof with secret vault marker. |
| [`credential_regex_disclosure_contract.json`](credential_regex_disclosure_contract.json) | Secret Leakage | Validates regex against real secret entropy patterns while applying automatic masking. |
| [`timing_sidechannel_contract.json`](timing_sidechannel_contract.json) | Blind SQLi / ReDoS | Mathematical delta threshold (`probe_ms - baseline_ms >= min_delay_ms`) to eliminate jitter. |

Use these contracts directly via `poc_validate` in the MCP protocol or via `secarbiter verify -a <contract.json>`.
