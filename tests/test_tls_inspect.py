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

    def test_custom_warn_days_threshold(self):
        # 60 days out: silent at the default 30-day threshold, but
        # warns when the caller asks for a 90-day horizon.
        cert = dict(BASE_CERT, notAfter="Jul 31 23:59:59 2026 GMT")
        self.assertEqual(parse_cert(cert, now=NOW)["warnings"], [])
        parsed = parse_cert(cert, now=NOW, warn_days=90)
        self.assertTrue(any("expires in" in w for w in parsed["warnings"]))

    def test_short_warn_days_stays_quiet(self):
        # 19 days out: warns by default, but not with a 7-day horizon.
        cert = dict(BASE_CERT, notAfter="Jun 20 23:59:59 2026 GMT")
        parsed = parse_cert(cert, now=NOW, warn_days=7)
        self.assertEqual(parsed["warnings"], [])

    def test_self_signed_is_a_problem(self):
        cert = dict(BASE_CERT)
        cert["issuer"] = cert["subject"]
        parsed = parse_cert(cert, now=NOW)
        self.assertTrue(any("self-signed" in p for p in parsed["problems"]))


if __name__ == "__main__":
    unittest.main()
