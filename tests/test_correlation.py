import unittest
from cbom_analyzer.correlation import correlate, migration_constraints
from cbom_analyzer.hardware import HardwareCryptoAsset
from cbom_analyzer.scanner import CryptoAsset

class CorrelationTests(unittest.TestCase):
    def test_correlates_algorithm_and_tpm_in_same_context(self):
        asset=CryptoAsset("RSA","public-key","identity.c",10,"RSA-3072",3072,"migration-review",True,True,"ML-DSA / ML-KEM","high","digital-signature","high","medium","quantum","planned")
        hw=HardwareCryptoAsset("TPM2","identity.c",14,"Esys_Sign(...);","sign","hardware-backed","unknown","high")
        rel=correlate([asset],[],[],[hw])
        self.assertTrue(any(x.relationship=="implemented-via" and x.target.startswith("TPM2@") for x in rel))
        constraints=migration_constraints([asset],[hw],rel)
        self.assertEqual(constraints[0]["backend"],"TPM2")
        self.assertIn("provisioning",constraints[0]["constraint"])

    def test_does_not_claim_certificate_key_match(self):
        from cbom_analyzer.certificates import CertificateAsset
        from cbom_analyzer.key_material import KeyMaterialAsset
        cert=CertificateAsset("keys/device.crt",None,None,None,None,None,None,None,None,None)
        key=KeyMaterialAsset("keys/device.key","private-key",False,"RSA","private-key-material")
        rel=correlate([], [cert], [key], [])
        self.assertEqual(rel[0].relationship,"potential-key-association")
        self.assertEqual(rel[0].confidence,"low")

if __name__=="__main__":
    unittest.main()
