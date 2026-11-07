"""
End-to-End integration test using a real in-process Python HTTP test server
Developer: Isha Sonaria
"""

import unittest
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from websentry.core.config import ScanConfig
from websentry.core.engine import ScanEngine
from websentry.core.finding import Severity

class VulnerableTestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress standard logging during tests
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE, PUT")
        self.send_header("Public", "GET, POST, OPTIONS, TRACE, PUT")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(b"TRACE / HTTP/1.1\r\nUser-Agent: WebSentry\r\n\r\n")

    def do_GET(self):
        path = self.path

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.send_header("Set-Cookie", "sessionid=xyz123; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Test App</title></head><body><h1>Welcome</h1></body></html>")

        elif path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")

        elif path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"APP_KEY=base64:abcd\nDB_PASSWORD=secret123\n")

        elif path == "/backup.sql":
            self.send_response(200)
            self.send_header("Content-Type", "application/sql")
            self.end_headers()
            self.wfile.write(b"CREATE TABLE users (id INT, password VARCHAR(255));\n")

        elif path == "/uploads/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Index of /uploads/</title></head><body>Directory listing</body></html>")

        elif path == "/phpmyadmin/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>phpMyAdmin Database Manager</body></html>")

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>404 Not Found</body></html>")

class TestEndToEndLocalServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Bind to 127.0.0.1 on ephemeral port (port 0)
        cls.server = HTTPServer(("127.0.0.1", 0), VulnerableTestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_full_scan_against_local_test_server(self):
        target_url = f"http://127.0.0.1:{self.port}/"
        config = ScanConfig(
            url=target_url,
            mode="standard",
            modules=["headers", "methods", "server_info", "sensitive_files", "misconfigs", "nikto"],
            timeout=4.0,
            threads=4,
            delay=0.01,
            allow_public=False,
            verbose=False
        )

        engine = ScanEngine(config)
        findings = engine.run()

        finding_ids = [f.id for f in findings]
        finding_titles = [f.title for f in findings]

        # 1. Verify Missing Security Headers detected
        self.assertTrue(any("CSP" in t or "Content-Security-Policy" in t for t in finding_titles))

        # 2. Verify Server info disclosure detected
        self.assertTrue(any("Apache" in t for t in finding_titles))

        # 3. Verify Dangerous TRACE and PUT methods detected
        self.assertTrue(any("TRACE" in t for t in finding_titles))

        # 4. Verify Exposed .git/HEAD and .env detected
        self.assertTrue(any(".git/HEAD" in t for t in finding_titles))
        self.assertTrue(any(".env" in t for t in finding_titles))

        # 5. Verify Insecure Cookie flags detected
        self.assertTrue(any("HttpOnly" in t for t in finding_titles))

        # 6. Verify Critical and High severity findings exist
        severities = {f.severity for f in findings}
        self.assertIn(Severity.CRITICAL, severities)
        self.assertIn(Severity.HIGH, severities)

if __name__ == "__main__":
    unittest.main()
