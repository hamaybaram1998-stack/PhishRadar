import unittest
from scanner import scan_url

class ScannerTests(unittest.TestCase):
    def test_http_ip_host(self):
        result = scan_url("http://192.0.2.1/login")
        self.assertGreaterEqual(result["risk_score"], 50)
    def test_simple_https(self):
        result = scan_url("https://example.org/")
        self.assertEqual(result["risk_level"], "low")
    def test_at_sign(self):
        result = scan_url("https://example.org@evil.example/")
        self.assertEqual(result["hostname"], "evil.example")
        self.assertGreaterEqual(result["risk_score"], 30)
    def test_invalid(self):
        with self.assertRaises(ValueError):
            scan_url("")

if __name__ == "__main__":
    unittest.main()
