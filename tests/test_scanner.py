import tempfile, unittest
from pathlib import Path
from cbom_analyzer.scanner import scan

class ScannerTests(unittest.TestCase):
    def test_detects_crypto_and_pqc_review(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.c"; p.write_text('const char *a="RSA-3072"; const char *b="AES-256";')
            findings=scan(Path(d)); names={x.algorithm for x in findings}
            self.assertIn("RSA", names); self.assertIn("AES", names)
            self.assertTrue(any(x.algorithm=="RSA" and x.pqc_migration_review for x in findings))

if __name__=="__main__": unittest.main()
