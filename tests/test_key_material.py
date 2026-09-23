import tempfile
import unittest
from pathlib import Path
from cbom_analyzer.key_material import scan_key_material

class KeyMaterialTests(unittest.TestCase):
    def test_detects_private_key_material_without_parsing_secret(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"device.key"
            p.write_text("-----BEGIN RSA PRIVATE KEY-----\nFAKE-TEST-DATA\n-----END RSA PRIVATE KEY-----\n")
            assets=scan_key_material(Path(d))
            self.assertEqual(len(assets),1)
            self.assertEqual(assets[0].material_type,"private-key")
            self.assertEqual(assets[0].algorithm_hint,"RSA")
            self.assertEqual(assets[0].exposure,"private-key-material")

if __name__=="__main__":
    unittest.main()
