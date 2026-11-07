"""
Unit tests for WebSentry Safety and Authorization Guardrails
Developer: Isha Sonaria
"""

import unittest
from websentry.core.safety import (
    is_private_or_local_ip,
    normalize_target_url,
    validate_target_safety,
    TargetSafetyRefusalError,
    InvalidTargetURLError
)

class TestSafetyGuardrails(unittest.TestCase):
    def test_private_ips(self):
        self.assertTrue(is_private_or_local_ip("127.0.0.1"))
        self.assertTrue(is_private_or_local_ip("10.0.0.1"))
        self.assertTrue(is_private_or_local_ip("192.168.1.50"))
        self.assertTrue(is_private_or_local_ip("172.16.0.10"))
        self.assertTrue(is_private_or_local_ip("::1"))

    def test_public_ips(self):
        self.assertFalse(is_private_or_local_ip("8.8.8.8"))
        self.assertFalse(is_private_or_local_ip("1.1.1.1"))
        self.assertFalse(is_private_or_local_ip("93.184.216.34"))

    def test_url_normalization(self):
        self.assertEqual(normalize_target_url("http://127.0.0.1:8080/"), "http://127.0.0.1:8080")
        self.assertEqual(normalize_target_url("127.0.0.1:9000"), "http://127.0.0.1:9000")
        self.assertEqual(normalize_target_url("https://localhost/app/"), "https://localhost/app")

    def test_invalid_scheme(self):
        with self.assertRaises(InvalidTargetURLError):
            validate_target_safety("ftp://127.0.0.1")

    def test_localhost_scan_allowed_without_flag(self):
        url, ips, is_private = validate_target_safety("http://127.0.0.1:8080", allow_public=False)
        self.assertEqual(url, "http://127.0.0.1:8080")
        self.assertTrue(is_private)

    def test_public_target_refusal(self):
        # 8.8.8.8 is a known public IP
        with self.assertRaises(TargetSafetyRefusalError):
            validate_target_safety("http://8.8.8.8", allow_public=False)

    def test_public_target_explicitly_allowed(self):
        url, ips, is_private = validate_target_safety("http://8.8.8.8", allow_public=True)
        self.assertIn("8.8.8.8", ips)
        self.assertFalse(is_private)

if __name__ == "__main__":
    unittest.main()
