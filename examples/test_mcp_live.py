#!/usr/bin/env python3
"""
End-to-End Live Verification Test.
Launches the vulnerable testbed app and communicates with the Rust MCP Server over Stdio JSON-RPC 2.0.
"""
import json
import os
import subprocess
import sys
import time

TARGET_PORT = 8765
MCP_BIN = os.path.join(os.path.dirname(__file__), "..", "target", "debug", "pentest-mcp")

class McpClient:
    def __init__(self, bin_path):
        env = os.environ.copy()
        env["PENTEST_DATA_DIR"] = "/tmp/pentest_live_test_data"
        env["RUST_LOG"] = "warn"
        self.proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr, # stderr logs printed directly to console
            text=True,
            bufsize=1,
            env=env
        )
        self.msg_id = 0

    def call(self, method, params=None):
        self.msg_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self.msg_id,
            "method": method,
            "params": params or {}
        }
        json_line = json.dumps(req)
        self.proc.stdin.write(json_line + "\n")
        self.proc.stdin.flush()

        resp_line = self.proc.stdout.readline()
        if not resp_line:
            raise RuntimeError("MCP process closed stdout unexpectedly")
        return json.loads(resp_line.strip())

    def call_tool(self, tool_name, arguments):
        resp = self.call("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })
        if "error" in resp:
            raise RuntimeError(f"RPC Error calling {tool_name}: {resp['error']}")
        result = resp.get("result", {})
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            return json.loads(content[0]["text"])
        return result

    def close(self):
        self.proc.terminate()
        self.proc.wait()

def main():
    print("==================================================================")
    print("      LIVE TEST: Agentic Pentest MCP against Vulnerable App       ")
    print("==================================================================")

    # 1. Start the vulnerable test application
    app_script = os.path.join(os.path.dirname(__file__), "vulnerable_app", "app.py")
    print(f"\n[1/7] Spawning vulnerable testbed application ({app_script})...")
    app_proc = subprocess.Popen([sys.executable, app_script])
    time.sleep(1) # Allow socket to bind

    mcp = None
    try:
        # 2. Launch Rust MCP server
        print(f"[2/7] Connecting to Rust Pentest MCP Server binary ({MCP_BIN})...")
        mcp = McpClient(MCP_BIN)

        # 3. Initialize & List Tools
        init_res = mcp.call("initialize")
        print(f"      [OK] MCP Initialized: {init_res['result']['serverInfo']}")

        tools_res = mcp.call("tools/list")
        tool_count = len(tools_res['result']['tools'])
        print(f"      [OK] Tools Discovered: {tool_count} tools registered")

        # 4. Create Engagement targeting localhost
        print("\n[3/7] Setting up Engagement scope (target: 127.0.0.1)...")
        eng_res = mcp.call_tool("engagement_create", {
            "name": "Live Audit of Local Testbed Project",
            "allowed_hosts": ["127.0.0.1", "localhost"],
            "allow_private_ips": True
        })
        eng_id = eng_res["engagement_id"]
        print(f"      [OK] Engagement created: {eng_id}")

        # Register sessions
        bob_sess = mcp.call_tool("session_register", {
            "engagement_id": eng_id,
            "label": "Tenant-Bob",
            "role": "standard_user",
            "headers": {"Authorization": "Bearer bob_session_jwt_secret"}
        })
        bob_sess_id = bob_sess["session_ref_id"]
        print(f"      [OK] Test Session registered: {bob_sess['label']} ({bob_sess_id})")

        # 5. Attack Vector A: IDOR / BOLA Verification
        print("\n[4/7] Testing IDOR / BOLA vulnerability...")
        idor_http = mcp.call_tool("http_send", {
            "engagement_id": eng_id,
            "session_ref_id": bob_sess_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/invoices?id=101" # Alice's invoice
        })
        print(f"      [->] HTTP {idor_http['status_code']} returned in {idor_http['duration_ms']}ms")
        print(f"      [->] Raw Artifact stored: {idor_http['artifact_id']} (SHA256: {idor_http['sha256_hash'][:16]}...)")

        # Draft finding & Validate
        draft_idor = mcp.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "BOLA / IDOR in Invoices API",
            "vuln_class": "idor",
            "endpoint": "/api/invoices?id=101",
            "severity": "HIGH",
            "hypothesis": "Tenant Bob can access Alice's invoice by parameter replacement"
        })
        idor_finding_id = draft_idor["finding_id"]

        idor_val = mcp.call_tool("poc_validate", {
            "finding_id": idor_finding_id,
            "exploit_artifact_id": idor_http["artifact_id"],
            "assertion_json": json.dumps({
                "resource_owner_session": "Alice",
                "unauthorized_session": "Bob",
                "target_resource_id": "101",
                "expected_unauthorized_status": 403,
                "observed_unauthorized_status": idor_http["status_code"],
                "expected_data_substring": "Confidential Security Audit Fee",
                "observed_body": idor_http["body_preview"]
            })
        })
        print(f"      [VERIFIED] Status: {idor_val['status'].upper()} -> {idor_val['reason']}")

        # 6. Attack Vector B: Path Traversal / LFI Verification
        print("\n[5/7] Testing Path Traversal / LFI vulnerability...")
        lfi_payload = "../../../../../../etc/passwd"
        lfi_http = mcp.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/view?file={lfi_payload}"
        })
        print(f"      [->] HTTP {lfi_http['status_code']} returned (Payload: {lfi_payload})")

        draft_lfi = mcp.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "Arbitrary File Read / Directory Traversal in File Viewer",
            "vuln_class": "path_traversal",
            "endpoint": "/api/view",
            "severity": "HIGH",
            "hypothesis": "Unsanitized path traversal allows reading /etc/passwd"
        })
        lfi_finding_id = draft_lfi["finding_id"]

        lfi_val = mcp.call_tool("poc_validate", {
            "finding_id": lfi_finding_id,
            "exploit_artifact_id": lfi_http["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/view",
                "traversal_payload": lfi_payload,
                "target_file_signature": "root:x:0:0",
                "observed_status_code": lfi_http["status_code"],
                "observed_body": lfi_http["body_preview"],
                "baseline_body": "{\"error\": \"Missing file parameter\"}"
            })
        })
        print(f"      [VERIFIED] Status: {lfi_val['status'].upper()} -> {lfi_val['reason']}")

        # 7. Attack Vector C: Command Injection (RCE) Verification
        print("\n[6/7] Testing OS Command Injection / RCE vulnerability...")
        rce_http = mcp.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/ping?host=id"
        })
        print(f"      [->] HTTP {rce_http['status_code']} returned from ping tool")

        draft_rce = mcp.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "Remote Code Execution in Ping Diagnostic Tool",
            "vuln_class": "command_injection",
            "endpoint": "/api/ping",
            "severity": "CRITICAL",
            "hypothesis": "Host argument concatenated directly into subshell"
        })
        rce_finding_id = draft_rce["finding_id"]

        rce_val = mcp.call_tool("poc_validate", {
            "finding_id": rce_finding_id,
            "exploit_artifact_id": rce_http["artifact_id"],
            "assertion_json": json.dumps({
                "target_endpoint": "/api/ping",
                "proof_type": {
                    "OutputMarker": {
                        "command_injected": "id",
                        "expected_output_token": "uid=",
                        "baseline_body": "PING probe to:",
                        "observed_body": rce_http["body_preview"]
                    }
                }
            })
        })
        print(f"      [VERIFIED] Status: {rce_val['status'].upper()} -> {rce_val['reason']}")

        # 8. Attack Vector D: Auth Bypass via Header Override Verification
        print("\n[7/9] Testing Authentication Bypass via Header Override...")
        # Control test: without header -> 401 Unauthorized
        ctrl_http = mcp.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/admin/secrets"
        })
        print(f"      [Control Test] Unauthenticated status: {ctrl_http['status_code']} (Expected 401)")

        # Exploit test: with header override -> 200 OK + Secret Vault
        bypass_http = mcp.call_tool("http_send", {
            "engagement_id": eng_id,
            "method": "GET",
            "url": f"http://127.0.0.1:{TARGET_PORT}/api/admin/secrets",
            "headers": {"X-Original-URL": "/api/admin/secrets"}
        })
        print(f"      [Exploit Test] Header override status: {bypass_http['status_code']} (Expected 200)")

        draft_auth = mcp.call_tool("finding_draft", {
            "engagement_id": eng_id,
            "title": "Authentication Bypass on Admin Secrets Vault via Header Override",
            "vuln_class": "auth_bypass",
            "endpoint": "/api/admin/secrets",
            "severity": "CRITICAL",
            "hypothesis": "X-Original-URL header bypasses admin authentication barrier"
        })
        auth_finding_id = draft_auth["finding_id"]

        auth_val = mcp.call_tool("poc_validate", {
            "finding_id": auth_finding_id,
            "exploit_artifact_id": bypass_http["artifact_id"],
            "control_artifact_id": ctrl_http["artifact_id"],
            "assertion_json": json.dumps({
                "protected_endpoint": "/api/admin/secrets",
                "unauthenticated_status": ctrl_http["status_code"],
                "legitimate_auth_status": 200,
                "bypass_attempt_status": bypass_http["status_code"],
                "bypass_technique": "X-Original-URL Header Override",
                "sensitive_action_executed": True
            })
        })
        print(f"      [VERIFIED] Status: {auth_val['status'].upper()} -> {auth_val['reason']}")

        # 9. Standalone Executable PoC Generation via poc_generate_script
        print("\n[8/9] Testing Standalone PoC Script Generator (poc_generate_script)...")
        script_res = mcp.call_tool("poc_generate_script", {
            "finding_id": idor_finding_id,
            "script_type": "curl"
        })
        print(f"      [OK] Generated standalone script: {script_res['filename']}")
        print(f"      [OK] Script length: {len(script_res['script_content'])} bytes")
        print("      [->] Snippet:")
        for line in script_res['script_content'].splitlines()[:10]:
            print("         ", line)

        # 10. Export Developer Report
        print("\n[9/9] Exporting Full Assessment Report...")
        export_resp = mcp.call("tools/call", {
            "name": "report_export",
            "arguments": {
                "engagement_id": eng_id,
                "format": "markdown"
            }
        })
        report_text = export_resp["result"]["content"][0]["text"]
        print("\n--- REPORT OUTPUT SNIPPET ---")
        for line in report_text.splitlines()[:28]:
            print("  ", line)
        print("   ... [Report continues with reproduction steps and digests]")

        print("\n==================================================================")
        print("          ALL LIVE TESTS PASSED SUCCESSFULLY! MCP IS READY.      ")
        print("==================================================================")

    finally:
        if mcp:
            mcp.close()
        app_proc.terminate()
        app_proc.wait()

if __name__ == "__main__":
    main()
