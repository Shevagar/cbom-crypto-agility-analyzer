import unittest
from cbom_analyzer.cyclonedx import build_cyclonedx
from cbom_analyzer.scanner import CryptoAsset

class CycloneDXTests(unittest.TestCase):
    def test_algorithm_component(self):
        asset=CryptoAsset(name="RSA",category="public-key",file="sign.c",line=10,evidence="RSA-3072",
            key_size=3072,status="migration-review",quantum_vulnerable=True,pqc_migration_review=True,
            migration_family="ML-DSA / SLH-DSA",confidence="high",purpose="digital-signature",
            purpose_confidence="high",severity="medium",policy_reason="quantum review",migration_priority="planned")
        bom=build_cyclonedx([asset],"firmware")
        self.assertEqual(bom["bomFormat"],"CycloneDX")
        self.assertEqual(bom["specVersion"],"1.7")
        component=bom["components"][0]
        self.assertEqual(component["type"],"cryptographic-asset")
        self.assertEqual(component["cryptoProperties"]["assetType"],"algorithm")
        self.assertEqual(component["cryptoProperties"]["algorithmProperties"]["primitive"],"signature")
        self.assertEqual(component["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"],"3072")
        self.assertNotIn("algorithmFamily",component["cryptoProperties"]["algorithmProperties"])

    def test_registered_family_is_emitted(self):
        asset=CryptoAsset(name="AES",category="symmetric",file="enc.c",line=2,evidence="AES-256",
            key_size=256,status="acceptable",quantum_vulnerable=False,pqc_migration_review=False,
            migration_family=None,confidence="high",purpose="encryption",purpose_confidence="high",
            severity="info",policy_reason="ok",migration_priority="none")
        props=build_cyclonedx([asset])["components"][0]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(props["algorithmFamily"],"AES")
        self.assertEqual(props["parameterSetIdentifier"],"256")

if __name__=="__main__":
    unittest.main()
