import tempfile
import unittest
from pathlib import Path
from cbom_analyzer.scanner import scan

class ScannerTests(unittest.TestCase):
    def scan_text(self, text):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.c"; p.write_text(text)
            return scan(Path(d))

    def test_detects_key_size_and_pqc_review(self):
        findings=self.scan_text('const char *a="RSA-3072"; const char *b="AES-256";')
        rsa=next(x for x in findings if x.name=="RSA")
        aes=next(x for x in findings if x.name=="AES")
        self.assertEqual(rsa.key_size,3072)
        self.assertTrue(rsa.quantum_vulnerable)
        self.assertEqual(aes.key_size,256)
        self.assertFalse(aes.quantum_vulnerable)

    def test_detects_legacy_crypto(self):
        findings=self.scan_text('const char *digest="SHA-1"; const char *old="MD5";')
        statuses={x.name:x.status for x in findings}
        self.assertEqual(statuses["SHA-1"],"legacy")
        self.assertEqual(statuses["MD5"],"deprecated")

    def test_detects_openssl_api_with_high_confidence(self):
        findings=self.scan_text('#include <openssl/evp.h>\nEVP_sha256();')
        self.assertTrue(any(x.name=="OpenSSL" and x.confidence=="high" for x in findings))
        self.assertTrue(any(x.name=="SHA-2" for x in findings))

    def test_infers_signature_purpose_for_nearby_rsa(self):
        findings=self.scan_text('const char *key="RSA-3072";\nEVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);')
        rsa=next(x for x in findings if x.name=="RSA")
        self.assertEqual(rsa.purpose,"digital-signature")
        self.assertEqual(rsa.migration_family,"ML-DSA / SLH-DSA")

if __name__=="__main__":
    unittest.main()
