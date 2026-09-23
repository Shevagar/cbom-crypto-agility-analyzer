import tempfile
import unittest
from pathlib import Path
from cbom_analyzer.hardware import scan_hardware_crypto

class HardwareCryptoTests(unittest.TestCase):
    def scan_text(self,text):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"crypto.c"; p.write_text(text)
            return scan_hardware_crypto(Path(d))

    def test_tpm_signing_detection(self):
        assets=self.scan_text("TSS2_RC rc = Esys_Sign(esys, keyHandle, ESYS_TR_PASSWORD, 0, 0, &digest, &scheme, &validation, &sig);")
        self.assertEqual(assets[0].backend,"TPM2")
        self.assertEqual(assets[0].operation,"sign")
        self.assertEqual(assets[0].key_location,"hardware-backed")

    def test_pkcs11_key_generation(self):
        assets=self.scan_text("rv = C_GenerateKeyPair(session, &mechanism, pub, 2, priv, 2, &pubkey, &privkey);")
        self.assertEqual(assets[0].backend,"PKCS#11")
        self.assertEqual(assets[0].operation,"key-generation")

if __name__=="__main__":
    unittest.main()
