#!/usr/bin/env python3
"""
Comprehensive OWASP Top 10 Testbed Application.
Contains 11 distinct intentionally vulnerable endpoints for automated MCP PoC verification.
Uses standard Python library only (http.server, json, urllib, subprocess).
"""
import http.server
import json
import os
import subprocess
import sys
import urllib.parse

PORT = int(os.environ.get("TARGET_PORT", "8765"))

INVOICES = {
    "101": {"id": "101", "owner": "Alice", "amount": 12500, "description": "Confidential Security Audit Fee"},
    "102": {"id": "102", "owner": "Bob", "amount": 450, "description": "Cloud Hosting Monthly"},
}

USERS_DB = [
    {"id": 1, "username": "admin", "role": "superadmin", "bio": "Master of Systems"},
    {"id": 2, "username": "alice", "role": "developer", "bio": "Security enthusiast"},
    {"id": 3, "username": "bob", "role": "viewer", "bio": "Regular visitor"},
]

OTP_ATTEMPTS = 0
SECURITY_PATCH_ACTIVE = os.environ.get("ENABLE_SECURITY_PATCH", "0") == "1"

class OwaspTestbedHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, status_code, data, extra_headers=None):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "Apache/2.4.49 (Unix)")
        self.send_header("X-Powered-By", "PHP/8.1.0-dev")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        global OTP_ATTEMPTS, SECURITY_PATCH_ACTIVE
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # 0. Health & Tech Stack
        if parsed.path == "/health":
            self.send_json(200, {"status": "ok", "categories": 11, "cve_enabled": True, "patch_active": SECURITY_PATCH_ACTIVE})
            return

        if parsed.path == "/api/admin/toggle_patch":
            enable_val = params.get("enable", ["1"])[0]
            SECURITY_PATCH_ACTIVE = enable_val in ("1", "true", "True")
            self.send_json(200, {"status": "ok", "security_patch_active": SECURITY_PATCH_ACTIVE})
            return

        if parsed.path == "/api/techstack":
            self.send_json(200, {
                "server": "Apache/2.4.49",
                "runtime": "PHP/8.1.0-dev",
                "dependencies": {
                    "werkzeug": "0.14.1",
                    "log4j-core": "2.14.1",
                    "jquery": "1.12.4"
                }
            })
            return

        # 1. OWASP A01: Broken Access Control (IDOR / BOLA)
        if parsed.path == "/api/invoices":
            inv_id = params.get("id", [""])[0]
            if SECURITY_PATCH_ACTIVE:
                # Patch: Validate token and enforce tenant ownership
                auth_header = self.headers.get("Authorization", "")
                if not auth_header or "Bearer" not in auth_header:
                    self.send_json(401, {"error": "Unauthorized: Bearer token required"})
                    return
                # Alice owns 101, Bob owns 102
                token = auth_header.split()[-1]
                expected_user = "Alice" if token == "alice_secret_token" else ("Bob" if token == "bob_secret_token" else None)
                if not expected_user:
                    self.send_json(403, {"error": "Forbidden: Invalid token"})
                    return
                if inv_id in INVOICES and INVOICES[inv_id]["owner"] != expected_user:
                    self.send_json(403, {"error": f"Forbidden: You do not own invoice {inv_id}"})
                    return

            if inv_id in INVOICES:
                self.send_json(200, INVOICES[inv_id])
            else:
                self.send_json(404, {"error": "Invoice not found"})
            return

        # 2. OWASP A01: Broken Access Control (Path Traversal / LFI)
        if parsed.path == "/api/view":
            file_param = params.get("file", [""])[0]
            if not file_param:
                self.send_json(400, {"error": "Missing file parameter"})
                return
            try:
                target_path = os.path.abspath(os.path.join(os.getcwd(), file_param))
                with open(target_path, "r", errors="ignore") as f:
                    content = f.read(4096)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            except Exception as e:
                self.send_json(500, {"error": str(e)})
            return

        # 3. OWASP A01 / A05: Security Misconfiguration (CORS Insecure Reflection)
        if parsed.path == "/api/user/private":
            origin = self.headers.get("Origin", "")
            extra = {}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            self.send_json(200, {
                "account": "Alice Private Banking",
                "balance": 95000,
                "secret_ssn": "999-00-1234"
            }, extra_headers=extra)
            return

        # 4. OWASP A02: Cryptographic Failures / Sensitive Information Disclosure
        if parsed.path == "/api/config/backup":
            self.send_json(200, {
                "environment": "production",
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "DB_PASSWORD": "DatabaseSuperSecretPassword2026!",
                "JWT_SECRET": "c2VjcmV0LWtleS1mb3Itand0LXZlcmlmaWNhdGlvbg=="
            })
            return

        # 5. OWASP A03: Injection (SQL Injection - Boolean Differential)
        if parsed.path == "/api/search/users":
            query = params.get("q", [""])[0]
            # Simulating SQL boolean logic:
            # If query contains "AND 1=1" or standard name -> returns full results (large body)
            # If query contains "AND 1=2" -> returns empty list (small body)
            if "1=2" in query:
                self.send_json(200, {"results": [], "query": query, "count": 0})
            elif "1=1" in query or "admin" in query:
                self.send_json(200, {"results": USERS_DB, "query": query, "count": len(USERS_DB), "note": "Database query executed"})
            else:
                self.send_json(200, {"results": [USERS_DB[0]], "query": query, "count": 1})
            return

        # 6. OWASP A03: Injection (OS Command Injection / RCE)
        if parsed.path == "/api/ping":
            host = params.get("host", [""])[0]
            if not host:
                self.send_json(400, {"error": "Host parameter required"})
                return
            try:
                cmd = f"echo 'PING probe to:'; {host}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(output)
            except Exception as e:
                self.send_json(500, {"error": f"Execution error: {e}"})
            return

        # 7. OWASP A03: Injection (Cross-Site Scripting / XSS reflection)
        if parsed.path == "/api/comments":
            msg = params.get("msg", [""])[0]
            html = f"<html><body><div id='comment-box'>{msg}</div></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        # 8. OWASP A04: Insecure Design (Missing Rate Limiting on sensitive OTP)
        if parsed.path == "/api/auth/otp_verify":
            OTP_ATTEMPTS += 1
            # Never returns 429 Too Many Requests even after dozens of requests!
            self.send_json(200, {"verified": False, "attempts": OTP_ATTEMPTS, "message": "Incorrect OTP"})
            return

        # 9. OWASP A05: Security Misconfiguration (Open Redirect)
        if parsed.path == "/api/auth/redirect":
            dest = params.get("url", ["/dashboard"])[0]
            self.send_response(302)
            self.send_header("Location", dest)
            self.end_headers()
            return

        # 10. OWASP A07: Identification and Authentication Failures (Auth Bypass)
        if parsed.path == "/api/admin/secrets":
            auth_header = self.headers.get("Authorization", "")
            override_header = self.headers.get("X-Original-URL", "")

            if override_header == "/api/admin/secrets" or "admin_token" in auth_header:
                self.send_json(200, {
                    "admin_vault": "TOP_SECRET_MASTER_DATABASE_KEY_9921",
                    "status": "unlocked"
                })
            else:
                self.send_json(401, {"error": "Unauthorized: Admin privileges required"})
            return

        # 11. OWASP A10: Server-Side Request Forgery (SSRF)
        if parsed.path == "/api/fetch_avatar":
            target_url = params.get("url", [""])[0]
            # Server triggers outbound HTTP request
            self.send_json(200, {
                "status": "fetching",
                "target": target_url,
                "simulated_outbound_request": True
            })
            return

        # Negative Control / Secure endpoint
        if parsed.path == "/api/secure/profile":
            auth_header = self.headers.get("Authorization", "")
            if auth_header == "Bearer alice_valid_token":
                self.send_json(200, {"user": "Alice", "role": "admin"})
            elif auth_header:
                self.send_json(403, {"error": "Forbidden: Access denied to Alice profile"})
            else:
                self.send_json(401, {"error": "Unauthorized"})
            return

        self.send_json(404, {"error": "Not Found"})

    # 12. OWASP API3: Mass Assignment (POST)
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/user/profile":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                data = json.loads(post_body)
            except Exception:
                data = {}
            profile = {
                "id": 10,
                "username": data.get("username", "bob"),
                "role": data.get("role", "user"), # Blindly sets privileged "role"!
                "email": data.get("email", "bob@example.com")
            }
            self.send_json(200, profile)
            return

        self.send_json(404, {"error": "Not Found"})

def run_server():
    server_address = ("127.0.0.1", PORT)
    httpd = http.server.HTTPServer(server_address, OwaspTestbedHandler)
    print(f"[TESTBED] OWASP Top 10 Testbed running on http://127.0.0.1:{PORT}")
    sys.stdout.flush()
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
