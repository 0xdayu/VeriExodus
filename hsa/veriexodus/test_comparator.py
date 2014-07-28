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

        # pt1, 11111111 -> pt2, no mod
        # pt1, 11111100 -> pt3, no mod
        # pt1, 111111xx -> pt4, no mod
        tf.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                w4, w4))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w3, [4], \
                                                w4, w4))
        c = Comparator()
        d = c.TestDictGen(tf.rules)
        result = c.decoupleRules(d[1])
        print "testDecoupleRules"
        for r in result:
            print r['match'], r['out_ports']

# Order of final 2 rules may vary
#D253 [4]
#D254 [4]

        print "~~~~~"
        self.assertEqual(len(result), 4)
        self.assert_(Test.rule_is_equal(result[0], TF.create_standard_rule([1], w1, [2], w4, w4)))
        self.assert_(Test.rule_is_equal(result[1], TF.create_standard_rule([1], w2, [3], w4, w4)))
        self.assert_(Test.rule_is_equal(result[2], TF.create_standard_rule([1], w6, [4], w4, w4)))
        self.assert_(Test.rule_is_equal(result[3], TF.create_standard_rule([1], w5, [4], w4, w4)))

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

        w3b = wildcard_create_from_string("1111111x")
        w4 = wildcard_create_from_string("xxxxxxxx")

        # 11111111 -> 2
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        # 11111111 -> 2
        # 1111111x -> 2
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w2, [2], \
                                                w4, w4))
        # Expect: 11111110 -> 2 not found in tf1
        c = Comparator()
        d1 = c.TestDictGen(tf1.rules)
        d2 = c.TestDictGen(tf2.rules)

        # MUST NOW EXPLICITLY DECORRELATE BEFORE CALLING COMPARE
        c.decompleTF(d2)

        nfr1 = c.compare(d1, d2)
        nfr2 = c.compare(d2, d1)

        # NOTE: use w3b for resulting match if using the "unshadowed by same-action" optimization
        self.assertEqual(len(nfr1), 0)
        self.assertEqual(len(nfr2), 1)
        if(c.opt_no_shadow_same_action):
            self.assert_(Test.rule_is_equal(nfr2[0], TF.create_standard_rule([1], w3b, [2], w4, w4)))
        else:
            self.assert_(Test.rule_is_equal(nfr2[0], TF.create_standard_rule([1], w3, [2], w4, w4)))

    def testComparison_non_equal_2(self):

        tf1 = TF(1)
        tf2 = TF(1)
        w1 = wildcard_create_from_string("11111111")
        w2 = wildcard_create_from_string("1111111x")
        w3 = wildcard_create_from_string("11111110")
        w4 = wildcard_create_from_string("xxxxxxxx")

        # 11111111 -> 2
        # 1111111x -> 3
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                w4, w4))
        # 11111110 -> 3
        # xxxxxxxx -> 2
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w3, [3], \
                                                w4, w4))
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                w4, w4))
        # EXPECTED RESULT:
        # 1111111x -> [3] not found in 2 to match 1
        c = Comparator()
        d1 = c.TestDictGen(tf1.rules)
        d2 = c.TestDictGen(tf2.rules)
        nfr1 = c.compare(d1, d2)
        nfr2 = c.compare(d2, d1)
        self.assertEqual(len(nfr1), 1)
        self.assertEqual(len(nfr2), 0)

    def testComparison_equal(self):

        tf1 = TF(1)
        tf2 = TF(1)
        w1 = wildcard_create_from_string("11111111")
        w2 = wildcard_create_from_string("1111111x")
        w3 = wildcard_create_from_string("11111110")
        w4 = wildcard_create_from_string("xxxxxxxx")

        # 11111111 -> 3
        # 1111111x -> 3
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w1, [3], \
                                                w4, w4))
        tf1.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                w4, w4))
        # 11111110 -> 3
        # xxxxxxxx -> 3
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w3, [3], \
                                                w4, w4))
        tf2.add_rewrite_rule(TF.create_standard_rule([1], w1, [3], \
                                                w4, w4))
        # EXPECTED RESULT: [empty]
        c = Comparator()
        d1 = c.TestDictGen(tf1.rules)
        d2 = c.TestDictGen(tf2.rules)
        nfr1 = c.compare(d1, d2)
        nfr2 = c.compare(d2, d1)
        self.assertEqual(len(nfr1), 0)
        self.assertEqual(len(nfr2), 0)


    # Decorrelation needs to pass over each rule in order
    # and *for each* it passes over each higher-priority rule.
    # This second pass must accumulate a list of fragments produced,
    #  since each higher-priority rule may split the original more and more.
    # This test detects some errors with that inner list of fragments.
    def testDecorr_NoIntersect(self):
        tf = TF(1)
        w1 = wildcard_create_from_string("11xxxxxx")
        #w2 = wildcard_create_from_string("00000000")
        w2 = wildcard_create_from_string("01xxxxx1")
        # force a bunch of non-intersects in the same pass
        # Need one of the later splits to intersect the 2nd rule
        w3 = wildcard_create_from_string("xxxxxxx1")

        allwc = wildcard_create_from_string("xxxxxxxx")

        tf.add_rewrite_rule(TF.create_standard_rule([1], w1, [2], \
                                                allwc, allwc))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w2, [3], \
                                                allwc, allwc))
        tf.add_rewrite_rule(TF.create_standard_rule([1], w3, [4], \
                                                allwc, allwc))

        # BUG:
        # 11xxxxxx
        # 01xxxxx1
        # x0xxxxx1
        # 0xxxxxx1
        # R2 still overlaps R4.
        # R4 should be 00xxxxx1

#11xxxxxx
#01xxxxx1
#x0xxxxx1
#00xxxxx1


        c = Comparator()
        d = c.TestDictGen(tf.rules)
        result = c.decoupleRules(d[1])

        # The affected by etc. fields lead to very expensive string construction
        print "results: "
        for r in result:
            print r['match']

        if(c.opt_no_shadow_same_action):
            self.assertEqual(len(result), 3)
            w4 = wildcard_create_from_string("x0xxxxx1")
            self.assert_(Test.rule_is_equal(result[2], TF.create_standard_rule([1], w4, [4], allwc, allwc)))
        else:
            self.assertEqual(len(result), 4)
            w4 = wildcard_create_from_string("00xxxxx1")
            self.assert_(Test.rule_is_equal(result[3], TF.create_standard_rule([1], w4, [4], allwc, allwc)))


if __name__ == "__main__":
    import sys;
    sys.argv = ['', 'Test.testComparison_equal', 'Test.testComparison_non_equal_2', 'Test.testComparison_non_equal', \
                'Test.testDecopuleRules', 'Test.testDecoupleRules_with_multiple_bits', 'Test.testDecorr_NoIntersect']
    #sys.argv = ['', 'Test.testDecorr_NoIntersect']
    unittest.main()