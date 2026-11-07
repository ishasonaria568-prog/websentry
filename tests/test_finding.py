"""
Unit tests for WebSentry Finding and Risk Classification
Developer: Isha Sonaria
"""

import unittest
from websentry.core.finding import Finding, Severity

class TestFinding(unittest.TestCase):
    def test_severity_parsing(self):
        self.assertEqual(Severity.from_string("critical"), Severity.CRITICAL)
        self.assertEqual(Severity.from_string("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.from_string("medium"), Severity.MEDIUM)
        self.assertEqual(Severity.from_string("low"), Severity.LOW)
        self.assertEqual(Severity.from_string("info"), Severity.INFORMATIONAL)
        self.assertEqual(Severity.from_string("unknown"), Severity.INFORMATIONAL)

    def test_severity_ordering(self):
        self.assertGreater(Severity.CRITICAL.score, Severity.HIGH.score)
        self.assertGreater(Severity.HIGH.score, Severity.MEDIUM.score)
        self.assertGreater(Severity.MEDIUM.score, Severity.LOW.score)
        self.assertGreater(Severity.LOW.score, Severity.INFORMATIONAL.score)

    def test_finding_to_dict(self):
        f = Finding(
            id="WS-TEST-001",
            title="Test Finding",
            severity=Severity.HIGH,
            url="http://127.0.0.1:8080/test",
            status_code=200,
            evidence="Matched test pattern",
            description="Test vulnerability description.",
            remediation="Apply test fix.",
            category="Test Category"
        )
        d = f.to_dict()
        self.assertEqual(d["id"], "WS-TEST-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["status_code"], 200)

    def test_cli_format(self):
        f = Finding(
            id="WS-TEST-002",
            title="Clickjacking Exposure",
            severity=Severity.LOW,
            url="http://127.0.0.1/",
            description="Missing X-Frame-Options header.",
            remediation="Set X-Frame-Options: DENY",
            category="HTTP Headers"
        )
        cli_text = f.format_cli()
        self.assertIn("Clickjacking Exposure", cli_text)
        self.assertIn("Missing X-Frame-Options", cli_text)

if __name__ == "__main__":
    unittest.main()
