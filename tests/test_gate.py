import unittest
from cbom_analyzer.gate import DEFAULT_POLICY, evaluate_gate, gate_passed
from cbom_analyzer.key_material import KeyMaterialAsset
from cbom_analyzer.scanner import CryptoAsset

class GateTests(unittest.TestCase):
    def asset(self,name="MD5",severity="high",quantum=False):
        return CryptoAsset(name,"hash","a.c",1,name,None,"deprecated",quantum,quantum,None,"high","hashing","high",severity,"test","immediate")

    def test_denied_algorithm_fails(self):
        violations=evaluate_gate([self.asset()],[],DEFAULT_POLICY)
        self.assertFalse(gate_passed(violations))
        self.assertEqual(violations[0].rule,"algorithm")

    def test_private_key_fails(self):
        key=KeyMaterialAsset("device.key","private-key",False,"RSA","private-key-material")
        violations=evaluate_gate([], [key], DEFAULT_POLICY)
        self.assertFalse(gate_passed(violations))

    def test_quantum_asset_warns_without_failing_default_gate(self):
        violations=evaluate_gate([self.asset("RSA","medium",True)],[],DEFAULT_POLICY)
        self.assertTrue(gate_passed(violations))
        self.assertEqual(violations[0].level,"warn")

if __name__=="__main__":
    unittest.main()
