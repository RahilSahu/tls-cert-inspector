import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tls_inspect import parse_cert

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)

BASE_CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example CA Root"),)),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Dec 31 23:59:59 2026 GMT",
    "serialNumber": "ABC123",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
}


class ParseCertTests(unittest.TestCase):
    def test_valid_cert_has_no_problems(self):
        parsed = parse_cert(BASE_CERT, now=NOW)
        self.assertEqual(parsed["problems"], [])
        self.assertIn("example.com", parsed["sans"])
        self.assertGreater(parsed["days_remaining"], 200)

    def test_expired_cert_is_a_problem(self):
        cert = dict(BASE_CERT, notAfter="Jan 31 23:59:59 2026 GMT")
        parsed = parse_cert(cert, now=NOW)
        self.assertTrue(any("expired" in p for p in parsed["problems"]))

    def test_expiring_soon_warns(self):
        cert = dict(BASE_CERT, notAfter="Jun 20 23:59:59 2026 GMT")
        parsed = parse_cert(cert, now=NOW)
        self.assertTrue(any("expires in" in w for w in parsed["warnings"]))

    def test_self_signed_is_a_problem(self):
        cert = dict(BASE_CERT)
        cert["issuer"] = cert["subject"]
        parsed = parse_cert(cert, now=NOW)
        self.assertTrue(any("self-signed" in p for p in parsed["problems"]))


if __name__ == "__main__":
    unittest.main()
