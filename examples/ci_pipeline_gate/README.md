# SecArbiter CI/CD Pipeline Security Gate

This directory contains integration examples for embedding SecArbiter as an automated, deterministic security gate in continuous integration and deployment (CI/CD) pipelines.

## Why SecArbiter in CI/CD?

Traditional Dynamic Application Security Testing (DAST) and Software Composition Analysis (SCA) tools suffer from two major problems:
1. **Noisy Speculation & False Positives**: Static tools flag issues without verifying if they are reachable or exploitable in runtime contexts.
2. **Missing Deterministic Regression Testing**: Developers lack automated ways to guarantee that a patched vulnerability does not regress in subsequent pull requests.

SecArbiter solves both problems by providing **Deterministic PoC Contracts** and **Automated Exit Codes**:
- `exit 0`: Vulnerability confirmed / still exploitable (**Blocks merge**).
- `exit 1`: Remediation validated / access denied (**Allows merge**).
- `exit 2`: Inconclusive / target unreachable (**Requires manual review**).

---

## Contents

- [`github_action_security_gate.yml`](github_action_security_gate.yml): Ready-to-use GitHub Actions workflow file. Copy to `.github/workflows/security-gate.yml` in your repository.
- [`ci_gate_runner.sh`](ci_gate_runner.sh): Standalone pipeline gate script supporting GitLab CI, Jenkins, Bitbucket Pipelines, and local git pre-push hooks.

---

## Running Locally

```bash
# Ensure release binary is compiled
cargo build --release

# Run the CI pipeline gate simulation
./examples/ci_pipeline_gate/ci_gate_runner.sh
```
