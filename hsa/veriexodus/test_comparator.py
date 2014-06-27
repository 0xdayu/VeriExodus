import unittest

from cisco_translator import *
from openflow_translator import *
from headerspace.hs import *
from utils.wildcard import *
from comparator import *

class Test(unittest.TestCase):
    
    @staticmethod
    def rule_is_equal(r1, r2):
        
        return set(r1["in_ports"]) == set(r2["in_ports"]) and       \
                wildcard_is_equal(r1["match"], r2["match"]) and      \
                wildcard_is_equal(r1["mask"], r2["mask"]) and        \
                wildcard_is_equal(r1["rewrite"], r2["rewrite"]) and  \
                set(r1["out_ports"]) == set(r2["out_ports"])
    
    def testDecopuleRules(self):
        tf = TF(1)
        w1 = wildcard_create_from_string("11111111")
        w2 = wildcard_create_from_string("11111100")
        w3 = wildcard_create_from_string("111111xx")
        w4 = wildcard_create_from_string("xxxxxxxx")
        w5 = wildcard_create_from_string("11111110")
        w6 = wildcard_create_from_string("11111101")
        
        tf.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                w4, w4))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w3, [4], \
                                                w4, w4))
        c = Comparator()
        d = c.TestDictGen(tf.rules)
        result = c.decoupleRules(d[1])
        self.assertEqual(len(result), 4)
        self.assert_(Test.rule_is_equal(result[0], TF.create_standard_rule([1], w1, [2], w4, w4)))
        self.assert_(Test.rule_is_equal(result[1], TF.create_standard_rule([1], w2, [3], w4, w4)))
        self.assert_(Test.rule_is_equal(result[2], TF.create_standard_rule([1], w5, [4], w4, w4)))
        self.assert_(Test.rule_is_equal(result[3], TF.create_standard_rule([1], w6, [4], w4, w4)))
        
    def testDecoupleRules_with_multiple_bits(self):
        tf = TF(1)
        w1 = wildcard_create_from_string("1111111x")
        w2 = wildcard_create_from_string("111111x1")
        w3 = wildcard_create_from_string("111111xx")
        w4 = wildcard_create_from_string("xxxxxxxx")
        
        w5 = wildcard_create_from_string("11111101")
        w6 = wildcard_create_from_string("11111100")
        
        tf.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                w4, w4))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w3, [4], \
                                                w4, w4))
        
        c = Comparator()
        d = c.TestDictGen(tf.rules)
        result = c.decoupleRules(d[1])
        self.assertEqual(len(result), 3)
        self.assert_(Test.rule_is_equal(result[0], TF.create_standard_rule([1], w1, [2], w4, w4)))
        self.assert_(Test.rule_is_equal(result[1], TF.create_standard_rule([1], w5, [3], w4, w4)))
        self.assert_(Test.rule_is_equal(result[2], TF.create_standard_rule([1], w6, [4], w4, w4)))
        
        
    def testComparison_non_equal(self):
        tf1 = TF(1)
        tf2 = TF(1)
        w1 = wildcard_create_from_string("11111111")
        w2 = wildcard_create_from_string("1111111x")
        w3 = wildcard_create_from_string("11111110")
        w4 = wildcard_create_from_string("xxxxxxxx")
        
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                w4, w4))
        
        c = Comparator()
        d1 = c.TestDictGen(tf1.rules)
        d2 = c.TestDictGen(tf2.rules)
        nfr1 = c.compare(d1, d2)
        nfr2 = c.compare(d2, d1)
        self.assertEqual(len(nfr1), 0)
        self.assertEqual(len(nfr2), 1)
        self.assert_(Test.rule_is_equal(nfr2[0], TF.create_standard_rule([1], w3, [3], w4, w4)))
        
    def testComparison_equal(self):
        
        tf1 = TF(1)
        tf2 = TF(1)
        w1 = wildcard_create_from_string("11111111")
        w2 = wildcard_create_from_string("1111111x")
        w3 = wildcard_create_from_string("11111110")
        w4 = wildcard_create_from_string("xxxxxxxx")
        
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                w4, w4))
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w3, [3], \
                                                w4, w4))
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        
        c = Comparator()
        d1 = c.TestDictGen(tf1.rules)
        d2 = c.TestDictGen(tf2.rules)
        nfr1 = c.compare(d1, d2)
        nfr2 = c.compare(d2, d1)
        self.assertEqual(len(nfr1), 0)
        self.assertEqual(len(nfr2), 0)
        
if __name__ == "__main__":
    import sys;
    sys.argv = ['', 'Test.testComparison_equal', 'Test.testComparison_non_equal', \
                'Test.testDecopuleRules', 'Test.testDecoupleRules_with_multiple_bits']
    unittest.main()