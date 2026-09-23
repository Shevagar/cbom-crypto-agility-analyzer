import unittest
from cbom_analyzer.agility import assess_migration, build_roadmap
from cbom_analyzer.correlation import CryptoRelationship
from cbom_analyzer.scanner import CryptoAsset

class AgilityTests(unittest.TestCase):
    def asset(self,name="RSA",purpose="digital-signature",priority="planned"):
        return CryptoAsset(name,"public-key","sign.c",10,"RSA-3072",3072,"migration-review",True,True,
            "ML-DSA / SLH-DSA","high",purpose,"high","medium","quantum",priority)

    def test_hardware_dependency_increases_complexity(self):
        a=self.asset()
        r=CryptoRelationship("algorithm","RSA@sign.c:10","implemented-via","crypto-backend","TPM2@sign.c:12","high","nearby")
        assessment=assess_migration([a],[r])[0]
        self.assertEqual(assessment.backend,"TPM2")
        self.assertEqual(assessment.complexity,"high")
        self.assertTrue(any("firmware images" in x for x in assessment.actions))

    def test_roadmap_prioritizes_immediate(self):
        immediate=self.asset("RSA",None,"immediate")
        planned=self.asset("ECC","key-establishment","planned")
        roadmap=build_roadmap(assess_migration([planned,immediate],[]))
        self.assertEqual(roadmap[0]["migration_priority"],"immediate")

if __name__=="__main__":
    unittest.main()
