#!/usr/bin/env python3
"""
Complete OWASP Top 10 PoC Verification & Replay Suite.
Tests all 11 distinct OWASP categories against the running testbed application using the compiled MCP Server.
"""
import json
import os
import subprocess
import sys
import time

TARGET_PORT = 8765
MCP_BIN = os.path.join(os.path.dirname(__file__), "..", "target", "release", "pentest-mcp")

class OwaspMcpDriver:
    def __init__(self, bin_path):
        env = os.environ.copy()
        env["PENTEST_DATA_DIR"] = "/tmp/owasp_suite_data"
        env["RUST_LOG"] = "warn"
        self.proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
            env=env
        )
        self.msg_id = 0

    def call_tool(self, name, args):
        self.msg_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self.msg_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        }
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP process terminated")
        resp = json.loads(line)
        if "error" in resp:
            raise RuntimeError(f"Tool {name} error: {resp['error']}")
        result = resp.get("result", {})
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            try:
                return json.loads(content[0]["text"])
            except Exception:
                return content[0]["text"]
        return result

    def close(self):
        self.proc.terminate()
        self.proc.wait()

def main():
    print("========================================================================")
    print("          OWASP TOP 10 COMPLETE POC VERIFICATION & REPLAY SUITE         ")
    print("========================================================================")

    # 1. Start App
    app_script = os.path.join(os.path.dirname(__file__), "vulnerable_app", "app.py")
    print(f"\n[INIT] Starting target app on 127.0.0.1:{TARGET_PORT}...")
    app_proc = subprocess.Popen([sys.executable, app_script])
    time.sleep(1)

    driver = None
    results = []

    try:
        driver = OwaspMcpDriver(MCP_BIN)
        print(f"[INIT] Connected to Release MCP Binary: {MCP_BIN}\n")

        # Create Engagement
        eng = driver.call_tool("engagement_create", {
            "name": "OWASP Top 10 Benchmark Audit",
            "allowed_hosts": ["127.0.0.1", "localhost"],
            "allow_private_ips": True
        })
        eng_id = eng["engagement_id"]

        # -------------------------------------------------------------
        # 1. OWASP A01: IDOR / BOLA
        # -------------------------------------------------------------
        print("[1/11] Testing OWASP A01: IDOR / BOLA...")
        tx1 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/invoices?id=101"
        })
        draft1 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A01: Insecure Direct Object Reference (BOLA)",
            "vuln_class": "idor",
            "endpoint": "/api/invoices?id=101",
            "severity": "HIGH",
            "hypothesis": "Tenant invoice access without ownership validation"
        })
        val1 = driver.call_tool("poc_validate", {
            "finding_id": draft1["finding_id"],
            "exploit_artifact_id": tx1["artifact_id"],
            "assertion_json": json.dumps({
                "resource_owner_session": "Alice",
                "unauthorized_session": "Bob",
                "target_resource_id": "101",
                "expected_unauthorized_status": 403,
                "observed_unauthorized_status": tx1["status_code"],
                "expected_data_substring": "Confidential Security Audit Fee",
                "observed_body": tx1["body_preview"]
            })
        })
        poc1 = driver.call_tool("poc_generate_script", {"finding_id": draft1["finding_id"], "script_type": "curl"})
        results.append(("OWASP A01", "IDOR / BOLA", val1["status"], poc1["filename"]))
        print(f"       -> Verdict: {val1['status'].upper()} | Generated PoC: {poc1['filename']}")

        # -------------------------------------------------------------
        # 2. OWASP A01: Path Traversal / LFI
        # -------------------------------------------------------------
        print("\n[2/11] Testing OWASP A01: Path Traversal / LFI...")
        tx2 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/view?file=../../../../../../etc/passwd"
        })
        draft2 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A01: Arbitrary File Read (Path Traversal)",
            "vuln_class": "path_traversal",
            "endpoint": "/api/view",
            "severity": "HIGH",
            "hypothesis": "Directory climbing allows accessing /etc/passwd"
        })
        val2 = driver.call_tool("poc_validate", {
            "finding_id": draft2["finding_id"],
            "exploit_artifact_id": tx2["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/view",
                "traversal_payload": "../../../../../../etc/passwd",
                "target_file_signature": "root:x:0:0",
                "observed_status_code": tx2["status_code"],
                "observed_body": tx2["body_preview"],
                "baseline_body": "{\"error\":\"Missing file parameter\"}"
            })
        })
        poc2 = driver.call_tool("poc_generate_script", {"finding_id": draft2["finding_id"], "script_type": "curl"})
        results.append(("OWASP A01", "Path Traversal", val2["status"], poc2["filename"]))
        print(f"       -> Verdict: {val2['status'].upper()} | Generated PoC: {poc2['filename']}")

        # -------------------------------------------------------------
        # 3. OWASP A01 / A05: Insecure CORS
        # -------------------------------------------------------------
        print("\n[3/11] Testing OWASP A01/A05: CORS Misconfiguration...")
        tx3 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/user/private",
            "headers": {"Origin": "https://attacker.evil"}
        })
        draft3 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A05: Insecure CORS Origin Reflection with Credentials",
            "vuln_class": "cors_misconfig",
            "endpoint": "/api/user/private",
            "severity": "HIGH",
            "hypothesis": "Arbitrary origin reflected with Access-Control-Allow-Credentials: true"
        })
        val3 = driver.call_tool("poc_validate", {
            "finding_id": draft3["finding_id"],
            "exploit_artifact_id": tx3["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/user/private",
                "injected_origin": "https://attacker.evil",
                "observed_headers": tx3["headers"],
                "endpoint_exposes_authenticated_data": True
            })
        })
        poc3 = driver.call_tool("poc_generate_script", {"finding_id": draft3["finding_id"], "script_type": "curl"})
        results.append(("OWASP A05", "CORS Misconfig", val3["status"], poc3["filename"]))
        print(f"       -> Verdict: {val3['status'].upper()} | Generated PoC: {poc3['filename']}")

        # -------------------------------------------------------------
        # 4. OWASP A02: Sensitive Information Disclosure
        # -------------------------------------------------------------
        print("\n[4/11] Testing OWASP A02: Sensitive Data Exposure...")
        tx4 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/config/backup"
        })
        draft4 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A02: Production AWS & Database Secrets Leaked in Backup",
            "vuln_class": "info_disclosure",
            "endpoint": "/api/config/backup",
            "severity": "CRITICAL",
            "hypothesis": "Config backup route discloses AWS keys and DB credentials"
        })
        val4 = driver.call_tool("poc_validate", {
            "finding_id": draft4["finding_id"],
            "exploit_artifact_id": tx4["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/config/backup",
                "disclosure_category": "aws_api_key",
                "regex_pattern": "AKIA[0-9A-Z]{16}",
                "observed_body": tx4["body_preview"],
                "is_unauthenticated_endpoint": True
            })
        })
        poc4 = driver.call_tool("poc_generate_script", {"finding_id": draft4["finding_id"], "script_type": "python"})
        results.append(("OWASP A02", "Sensitive Data Leak", val4["status"], poc4["filename"]))
        print(f"       -> Verdict: {val4['status'].upper()} | Generated PoC: {poc4['filename']}")

        # -------------------------------------------------------------
        # 5. OWASP A03: SQL Injection (Boolean Differential)
        # -------------------------------------------------------------
        print("\n[5/11] Testing OWASP A03: SQL Injection (Boolean Differential)...")
        tx5_true = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/search/users?q=admin%27%20AND%201=1--"
        })
        tx5_false = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/search/users?q=admin%27%20AND%201=2--"
        })
        draft5 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A03: SQL Injection in User Search Parameter",
            "vuln_class": "sqli",
            "endpoint": "/api/search/users",
            "severity": "CRITICAL",
            "hypothesis": "Boolean differential proves SQL injection query tampering"
        })
        val5 = driver.call_tool("poc_validate", {
            "finding_id": draft5["finding_id"],
            "exploit_artifact_id": tx5_true["artifact_id"],
            "control_artifact_id": tx5_false["artifact_id"],
            "assertion_json": json.dumps({
                "endpoint": "/api/search/users",
                "sqli_type": {
                    "BooleanDifferential": {
                        "baseline_body_len": 180,
                        "true_condition_body_len": tx5_true["body_length"],
                        "false_condition_body_len": tx5_false["body_length"],
                        "repetitions_consistent": 2
                    }
                }
            })
        })
        poc5 = driver.call_tool("poc_generate_script", {"finding_id": draft5["finding_id"], "script_type": "curl"})
        results.append(("OWASP A03", "SQL Injection", val5["status"], poc5["filename"]))
        print(f"       -> Verdict: {val5['status'].upper()} | Generated PoC: {poc5['filename']}")

        # -------------------------------------------------------------
        # 6. OWASP A03: OS Command Injection (RCE)
        # -------------------------------------------------------------
        print("\n[6/11] Testing OWASP A03: OS Command Injection / RCE...")
        tx6 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/ping?host=id"
        })
        draft6 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A03: OS Command Injection in Ping Tool",
            "vuln_class": "command_injection",
            "endpoint": "/api/ping",
            "severity": "CRITICAL",
            "hypothesis": "Host parameter concatenated directly into subshell"
        })
        val6 = driver.call_tool("poc_validate", {
            "finding_id": draft6["finding_id"],
            "exploit_artifact_id": tx6["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/ping",
                "proof_type": {
                    "OutputMarker": {
                        "command_injected": "id",
                        "expected_output_token": "uid=",
                        "baseline_body": "PING probe to:",
                        "observed_body": tx6["body_preview"]
                    }
                }
            })
        })
        poc6 = driver.call_tool("poc_generate_script", {"finding_id": draft6["finding_id"], "script_type": "curl"})
        results.append(("OWASP A03", "Command Injection", val6["status"], poc6["filename"]))
        print(f"       -> Verdict: {val6['status'].upper()} | Generated PoC: {poc6['filename']}")

        # -------------------------------------------------------------
        # 7. OWASP A03: Cross-Site Scripting (XSS)
        # -------------------------------------------------------------
        print("\n[7/11] Testing OWASP A03: Cross-Site Scripting (XSS)...")
        tx7 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/comments?msg=%3Cscript%3Ewindow.__poc=1%3C/script%3E"
        })
        draft7 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A03: Reflected Cross-Site Scripting in Comments",
            "vuln_class": "xss",
            "endpoint": "/api/comments",
            "severity": "MEDIUM",
            "hypothesis": "Unencoded script tags reflected into HTML body"
        })
        val7 = driver.call_tool("poc_validate", {
            "finding_id": draft7["finding_id"],
            "exploit_artifact_id": tx7["artifact_id"],
            "assertion_json": json.dumps({
                "target_url": f"http://127.0.0.1:{TARGET_PORT}/api/comments",
                "payload_submitted": "<script>window.__poc=1</script>",
                "execution_token": "window.__poc=1",
                "origin_context": "http://127.0.0.1:8765",
                "executed_in_browser": True,
                "dom_sink_type": "innerHTML",
                "console_or_alert_intercepted": True
            })
        })
        poc7 = driver.call_tool("poc_generate_script", {"finding_id": draft7["finding_id"], "script_type": "curl"})
        results.append(("OWASP A03", "Cross-Site Scripting", val7["status"], poc7["filename"]))
        print(f"       -> Verdict: {val7['status'].upper()} | Generated PoC: {poc7['filename']}")

        # -------------------------------------------------------------
        # 8. OWASP A04: Rate Limit Bypass
        # -------------------------------------------------------------
        print("\n[8/11] Testing OWASP A04: Missing Rate Limiting / Anti-Automation...")
        for _ in range(15):
            tx8 = driver.call_tool("http_send", {
                "engagement_id": eng_id,
                "method": "GET",
                "url": f"http://127.0.0.1:{TARGET_PORT}/api/auth/otp_verify"
            })
        draft8 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A04: Missing Rate Limiting on OTP Authentication Endpoint",
            "vuln_class": "rate_limit_bypass",
            "endpoint": "/api/auth/otp_verify",
            "severity": "HIGH",
            "hypothesis": "Rapid consecutive OTP verification attempts permitted without HTTP 429 throttling"
        })
        val8 = driver.call_tool("poc_validate", {
            "finding_id": draft8["finding_id"],
            "exploit_artifact_id": tx8["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/auth/otp_verify",
                "total_requests_sent": 25,
                "successful_status_count": 25,
                "rate_limited_status_count": 0,
                "max_allowed_threshold": 5
            })
        })
        poc8 = driver.call_tool("poc_generate_script", {"finding_id": draft8["finding_id"], "script_type": "curl"})
        results.append(("OWASP A04", "Rate Limit Bypass", val8["status"], poc8["filename"]))
        print(f"       -> Verdict: {val8['status'].upper()} | Generated PoC: {poc8['filename']}")

        # -------------------------------------------------------------
        # 9. OWASP A05: Open Redirect
        # -------------------------------------------------------------
        print("\n[9/11] Testing OWASP A05: Open Redirect...")
        tx9 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/auth/redirect?url=https://attacker.evil/phishing"
        })
        draft9 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A05: Unvalidated Redirects and Forwards",
            "vuln_class": "open_redirect",
            "endpoint": "/api/auth/redirect",
            "severity": "MEDIUM",
            "hypothesis": "Server forwards users to external arbitrary URLs"
        })
        val9 = driver.call_tool("poc_validate", {
            "finding_id": draft9["finding_id"],
            "exploit_artifact_id": tx9["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/auth/redirect",
                "injected_redirect_target": "https://attacker.evil/phishing",
                "observed_status_code": tx9["status_code"],
                "observed_location_header": tx9["headers"].get("location")
            })
        })
        poc9 = driver.call_tool("poc_generate_script", {"finding_id": draft9["finding_id"], "script_type": "curl"})
        results.append(("OWASP A05", "Open Redirect", val9["status"], poc9["filename"]))
        print(f"       -> Verdict: {val9['status'].upper()} | Generated PoC: {poc9['filename']}")

        # -------------------------------------------------------------
        # 10. OWASP A07: Authentication Bypass
        # -------------------------------------------------------------
        print("\n[10/11] Testing OWASP A07: Authentication Bypass...")
        tx10 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/admin/secrets",
            "headers": {"X-Original-URL": "/api/admin/secrets"}
        })
        draft10 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A07: Authentication Bypass via Header Tampering",
            "vuln_class": "auth_bypass",
            "endpoint": "/api/admin/secrets",
            "severity": "CRITICAL",
            "hypothesis": "X-Original-URL overrides administrative authentication check"
        })
        val10 = driver.call_tool("poc_validate", {
            "finding_id": draft10["finding_id"],
            "exploit_artifact_id": tx10["artifact_id"],
            "assertion_json": json.dumps({
                "protected_endpoint": "/api/admin/secrets",
                "unauthenticated_status": 401,
                "legitimate_auth_status": 200,
                "bypass_attempt_status": tx10["status_code"],
                "bypass_technique": "X-Original-URL Header Tampering",
                "sensitive_action_executed": True
            })
        })
        poc10 = driver.call_tool("poc_generate_script", {"finding_id": draft10["finding_id"], "script_type": "curl"})
        results.append(("OWASP A07", "Auth Bypass", val10["status"], poc10["filename"]))
        print(f"       -> Verdict: {val10['status'].upper()} | Generated PoC: {poc10['filename']}")

        # -------------------------------------------------------------
        # 11. OWASP A10: Server-Side Request Forgery (SSRF)
        # -------------------------------------------------------------
        print("\n[11/11] Testing OWASP A10: SSRF (Outbound Callback Correlation)...")
        tx11 = driver.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/fetch_avatar?url=http://collab.internal/token99"
        })
        draft11 = driver.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "A10: Server-Side Request Forgery via Avatar Import",
            "vuln_class": "ssrf",
            "endpoint": "/api/fetch_avatar",
            "severity": "HIGH",
            "hypothesis": "Backend fetches arbitrary intranet endpoints"
        })
        val11 = driver.call_tool("poc_validate", {
            "finding_id": draft11["finding_id"],
            "exploit_artifact_id": tx11["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/fetch_avatar",
                "callback_nonce": "token99",
                "controlled_listener_url": "http://collab.internal/token99",
                "observed_callback_nonce": "token99",
                "callback_source_ip": "127.0.0.1",
                "target_server_ip": "127.0.0.1",
                "is_pentester_client_ip": False
            })
        })
        poc11 = driver.call_tool("poc_generate_script", {"finding_id": draft11["finding_id"], "script_type": "python"})
        results.append(("OWASP A10", "SSRF", val11["status"], poc11["filename"]))
        print(f"       -> Verdict: {val11['status'].upper()} | Generated PoC: {poc11['filename']}")

        # 12. Tech Stack Known CVEs (Fingerprinting + Deterministic CVE Verification)
        print("\n[+] 12. Tech Stack CVEs: Fingerprinting server headers & manifest...")
        cve_scan_res = driver.call_tool("cve_scan", {
            "engagement_id": eng_id,
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/techstack",
            "manifest_content": "werkzeug==0.14.1\nlog4j-core==2.14.1\n"
        })
        cve_count = cve_scan_res.get("cves_detected_count", 0)
        print(f"       -> Detected CVEs: {cve_count}")
        matches = cve_scan_res.get("matches", [])
        apache_cve = next((m for m in matches if m["cve_id"] == "CVE-2021-41773"), matches[0])
        val12 = driver.call_tool("poc_validate", {
            "finding_id": apache_cve["draft_finding_id"],
            "exploit_artifact_id": cve_scan_res["raw_evidence_artifact_id"],
            "assertion_json": json.dumps(apache_cve["suggested_assertion"])
        })
        poc12 = driver.call_tool("poc_generate_script", {"finding_id": apache_cve["draft_finding_id"], "script_type": "curl"})
        results.append(("TechStack CVE", f"{apache_cve['cve_id']} ({apache_cve['component']})", val12["status"], poc12["filename"]))
        print(f"       -> Verdict: {val12['status'].upper()} | CVSS: {apache_cve['cvss_score']} | Generated PoC: {poc12['filename']}")

        # Print Scorecard
        print("\n========================================================================")
        print("                   OWASP TOP 10 SCORECARD SUMMARY                       ")
        print("========================================================================")
        print(f"{'Category':<14} | {'Vulnerability Name':<28} | {'Status':<14} | {'PoC Script'}")
        print("-" * 76)
        confirmed_count = 0
        inconclusive_count = 0
        for cat, name, status, poc in results:
            if status == "confirmed":
                confirmed_count += 1
                status_label = "CONFIRMED"
            elif status == "inconclusive":
                inconclusive_count += 1
                status_label = "INCONCLUSIVE*"
            else:
                status_label = status.upper()
            print(f"{cat:<14} | {name:<28} | {status_label:<14} | {poc}")

        print("-" * 76)
        print(f"Total OWASP Categories Evaluated: {len(results)}")
        print(f"Empirically Confirmed (Wire Grounded):  {confirmed_count}/{len(results)}")
        print(f"Inconclusive (Host-Attested Claims):    {inconclusive_count}/{len(results)}")
        print("  * Inconclusive: Capped safely because forensic wire artifacts alone")
        print("    cannot independently prove DOM sinks (XSS), out-of-band hits (SSRF),")
        print("    or multi-transaction quotas (Rate Limit) without auxiliary telemetry.")
        print("========================================================================")

        assert confirmed_count == 9, f"Expected 9 empirically confirmed, got {confirmed_count}"
        assert inconclusive_count == 3, f"Expected 3 host-attested inconclusive, got {inconclusive_count}"
        assert confirmed_count + inconclusive_count == len(results)

    finally:
        if driver:
            driver.close()
        app_proc.terminate()
        app_proc.wait()

if __name__ == "__main__":
    main()
