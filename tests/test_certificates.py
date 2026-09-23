import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cbom_analyzer.certificates import scan_certificates

CERT_TEXT="""-----BEGIN CERTIFICATE-----
TEST
-----END CERTIFICATE-----
"""

class CertificateTests(unittest.TestCase):
    def test_normalizes_validity_dates(self):
        decoded={
            "subject":((("commonName","device.example"),),),
            "issuer":((("commonName","Example CA"),),),
            "serialNumber":"01AB",
            "notBefore":"Jan  2 03:04:05 2026 GMT",
            "notAfter":"Jan  2 03:04:05 2030 GMT",
        }
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"device.crt"; p.write_text(CERT_TEXT)
            with patch("cbom_analyzer.certificates._decode_pem",return_value=decoded):
                asset=scan_certificates(Path(d))[0]
        self.assertEqual(asset.not_before,"2026-01-02T03:04:05Z")
        self.assertEqual(asset.not_after,"2030-01-02T03:04:05Z")
        self.assertFalse(asset.expired)

    def test_invalid_certificate_is_reported_without_claimed_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"broken.pem"; p.write_text(CERT_TEXT)
            with patch("cbom_analyzer.certificates._decode_pem",return_value=None):
                asset=scan_certificates(Path(d))[0]
        self.assertEqual(asset.confidence,"medium")
        self.assertIsNone(asset.subject)
        self.assertIsNone(asset.not_after)

if __name__=="__main__":
    unittest.main()
