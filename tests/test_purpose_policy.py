import unittest
from cbom_analyzer.policy import evaluate
from cbom_analyzer.purpose import infer_purpose, pqc_family_for

class PurposePolicyTests(unittest.TestCase):
    def test_signature_maps_to_signature_pqc_family(self):
        match=infer_purpose("EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);")
        self.assertEqual(match.purpose, "digital-signature")
        self.assertEqual(pqc_family_for(match.purpose), "ML-DSA / SLH-DSA")

    def test_key_derivation_maps_to_ml_kem(self):
        match=infer_purpose("EVP_PKEY_derive(ctx, secret, &secret_len);")
        self.assertEqual(match.purpose, "key-establishment")
        self.assertEqual(pqc_family_for(match.purpose), "ML-KEM")

    def test_weak_rsa_is_critical(self):
        result=evaluate("RSA","migration-review",1024,True,"digital-signature")
        self.assertEqual(result.severity,"critical")
        self.assertEqual(result.migration_priority,"immediate")

if __name__=="__main__":
    unittest.main()
