"""
Unit tests for WebSentry Reporting Subsystem
Developer: Isha Sonaria
"""

import json
import unittest
from websentry.core.finding import Finding, Severity
from websentry.reports.generator import ReportGenerator

class TestReports(unittest.TestCase):
    def setUp(self):
        self.findings = [
            Finding(
                id="WS-TEST-CRIT",
                title="Exposed Database Secrets",
                severity=Severity.CRITICAL,
                url="http://127.0.0.1/.env",
                status_code=200,
                evidence="DB_PASSWORD=secret",
                description="Database password exposed in .env",
                remediation="Move .env outside web root.",
                category="Sensitive Files"
            ),
            Finding(
                id="WS-TEST-MED",
                title="Missing CSP Header",
                severity=Severity.MEDIUM,
                url="http://127.0.0.1/",
                status_code=200,
                description="No Content-Security-Policy.",
                remediation="Deploy CSP.",
                category="HTTP Headers"
            )
        ]
        self.reporter = ReportGenerator(
            target_url="http://127.0.0.1:8080",
            findings=self.findings,
            duration_seconds=2.45,
            total_requests=42
        )

    def test_json_report(self):
        json_str = self.reporter.generate_json()
        data = json.loads(json_str)
        self.assertEqual(data["scan_meta"]["tool"], "WebSentry")
        self.assertEqual(data["scan_meta"]["author"], "Isha Sonaria")
        self.assertEqual(data["scan_meta"]["total_findings"], 2)
        self.assertEqual(data["scan_meta"]["summary"]["CRITICAL"], 1)
        self.assertEqual(data["scan_meta"]["summary"]["MEDIUM"], 1)
        self.assertEqual(len(data["findings"]), 2)

    def test_txt_report(self):
        txt = self.reporter.generate_txt()
        self.assertIn("WEBSENTRY — WEB SERVER SECURITY ASSESSMENT REPORT", txt)
        self.assertIn("Developer: Isha Sonaria", txt)
        self.assertIn("Exposed Database Secrets", txt)
        self.assertIn("CRITICAL", txt)

    def test_html_report(self):
        html_content = self.reporter.generate_html()
        self.assertIn("<!DOCTYPE html>", html_content)
        self.assertIn("BUILT BY Isha Sonaria", html_content)
        self.assertIn("WebSentry Security Assessment Report", html_content)
        self.assertIn("Exposed Database Secrets", html_content)
        self.assertIn("https://github.com/ishasonaria568-prog", html_content)

if __name__ == "__main__":
    unittest.main()
