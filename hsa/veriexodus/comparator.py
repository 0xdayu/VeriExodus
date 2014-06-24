from cisco_translator import *
from openflow_translator import *
from headerspace.hs import *
from utils.wildcard import *


class Comparator:
    
    def __init__(self):
        
        # key, value -> inports number, [rules]
        self.ios_hs = {}
        self.of_hs = {}

    def compare(self, hs1, hs2):
        #isEqual = True
        not_found_rules = []
        for key, value in hs1.iteritems():
            if key == "controller_rules":
                print "======Ignore Rules sent to the Controller====="
                continue
            if key in hs2.keys():
                #isEqual = isEqual and self.compareRules(self.decoupleRules(value), self.decoupleRules(hs2[key]))
                not_found_rules += self.compareRules(self.decoupleRules(value), self.decoupleRules(hs2[key]))
            else:
                #isEqual = isEqual and False
                not_found_rules += value
        return not_found_rules
            
    def compareRules(self, rules1, rules2):
        not_found_rules = []
        #isEqual = True
        for r1 in rules1:
            r2 = self.getHeaderSpaceWithSameFourTuples(r1, rules2)
            if len(r2) == 0:
                #isEqual = False
                not_found_rules.append(r1)
                break
            
            temp = []
            temp.append(r1)
            for _r2 in r2:
                for i in range(len(temp)):
                    _r1 = temp.pop(0)
                    intersect_part = wildcard_intersect(_r1["match"], _r2["match"])
                    if len(intersect_part) == 0: #no overlap headerspace
                        temp.insert(0, _r1)
                        continue
                    
                    substracted_match = wildcard_diff(_r1["match"], intersect_part)
                    for sm in substracted_match:
                        if sm is None:
                            continue
                        t = _r1.copy()
                        t["match"] = sm
                        temp.append(t)
            
            if len(temp) != 0:
                not_found_rules.append(r1)
                #isEqual = False
        
        #print "----", isEqual
        return not_found_rules
                             
    def getHeaderSpaceWithSameFourTuples(self, r1, rule_set): # get rules from rule_set with same inports, mask, rewrite and outports
        result = []
        for r2 in rule_set:
            if wildcard_is_equal(r1["mask"], r2["mask"]) and \
            wildcard_is_equal(r1["rewrite"], r2["rewrite"]) and \
            set(r1["out_ports"]) == set(r2["out_ports"]):
                result.append(r2)
                
        return result
        
    def importIOS(self):
        example_folder = '../examples/Exodus_toy_example/'
        ios = cisco_router(1)
        ios.read_inputs(example_folder + 'ext_mac_table.txt',\
        example_folder + 'ext_config.txt', \
        example_folder + 'ext_route.txt', \
        example_folder + 'ext_arp_table.txt')
        ios_tf = ios.generate_transfer_function()
        
        port_map = {1:3, 2:1}
        ios_ports = lambda n: port_map[n]
        
        for rule in ios_tf.rules:
            #drop rules
            #if len(rule["out_ports"]) == 0:
            #    continue
            
            #map the port number to OF
            rule["in_ports"] = map(ios_ports, rule["in_ports"])
            rule["out_ports"] = map(ios_ports, rule["out_ports"])
            
            for inports in rule["in_ports"]:
                if inports in self.ios_hs.keys():
                    self.ios_hs[inports] += [rule]
                else:
                    self.ios_hs[inports] = [rule]
        
    def importOF(self):
        
        of_tf = generate_ext()

        ign_ports = lambda n: n % 2 == 0

        # filter OpenFlow rules
        self.of_hs["controller_rules"] = []
        for rule in of_tf.rules:
            for inports in rule["in_ports"]:
                #if len(rule["out_ports"]) == 0 or ign_ports(inports) :
                if ign_ports(inports): 
                    continue
                
                if len(rule['out_ports']) > 0 and rule["out_ports"][0] == 65535:
                    self.of_hs["controller_rules"] += [rule]
                    #break
                
                if inports in self.of_hs.keys():
                    self.of_hs[inports] += [rule]
                else:
                    self.of_hs[inports] = [rule]
            
            '''if reduce(lambda result, n: result and not ign_ports(n), rule["in_ports"], True):
                if len(rule["out_ports"]) == 0:
                    continue
                
                if rule["out_ports"][0] == 65535:
                    self.of_hs["controller_rules"] += [rule]
                    continue
                for inports in rule["in_ports"]:
                    if inports in self.of_hs.keys():
                        self.of_hs[inports] += [rule]
                    else:
                        self.of_hs[inports] = [rule]'''
    
    def decoupleRules(self, rules):
        _results = []
        results = []
        for rule in rules:
            temp = []
            temp.append(rule)
            for result in results:
                size = len(temp)
                for i in range(size): #every decomposed headerspaces
                    currentRule = temp.pop(0)
                    intersectPart = wildcard_intersect(currentRule['match'], result['match'])

                    #no intersect parts
                    if (len(intersectPart) == 0):
                        temp.insert(0, currentRule)
                        continue
                    tempWildcard = wildcard_diff(currentRule['match'], intersectPart)
                    for tw in tempWildcard:
                        if tw is None:
                            continue
                        t = currentRule.copy()
                        t['match'] = tw
                        temp.append(t)
            results += temp
            
            
        #remove drop and controller rules
        for r in results:
            if not (len(r['out_ports']) == 0 or (65535 in r['out_ports'])):
                _results.append(r) 
        return _results
    
    @staticmethod
    def printRules(rules):
        for rule in rules:
            print "in_ports: %s, match: %s => ((h & %s) | %s, %s)" % \
                (rule['in_ports'], rule['match'], rule['mask'], \
                 rule['rewrite'], rule['out_ports'])
                        
    # Just for Test                        
    def TestDictGen(self, rules):
        d = {}
        for rule in rules:
            for ports in rule["in_ports"]:
                if ports in d.keys():
                    '''r = rule.copy()
                    r["in_ports"] = [ports]
                    d[ports] += [r]'''
                    d[ports] += [rule]
                else:
                    '''r = rule.copy()
                    r["in_ports"] = [ports]
                    d[ports] = [r]'''
                    d[ports] = [rule]
        return d

if __name__ == "__main__":
    c = Comparator()
    c.importOF()
    c.importIOS()
    print "===================IOS-FWD-Rules:==========================="
    for key, value in c.ios_hs.iteritems():
        print '----Bucket: %s -----' % key
        c.printRules(value)
    print "===================OF-FWD-Rules:==========================="
    for key, value in c.of_hs.iteritems():
        print '----Bucket: %s -----' % key
        c.printRules(value)
        
    nfr = c.compare(c.ios_hs, c.of_hs)
    _nfr = c.compare(c.of_hs, c.ios_hs)
    
    print '--------Not Found in TF1:------'
    c.printRules(nfr)
    print '--------Not Found in TF2:------'
    c.printRules(_nfr)
    '''
    print "===================After Decomposition:==================="
    print "===================IOS-FWD-Rules:==========================="
    for key, value in c.ios_hs.iteritems():
        print '----Bucket: %s -----' % key
        c.printRules(c.decoupleRules(value))
    print "===================IOS-FWD-Rules:==========================="
    for key, value in c.of_hs.iteritems():
        if key == 'controller_rules':
            continue
        print '----Bucket: %s -----' % key
        c.printRules(c.decoupleRules(value))'''
        
    
    '''
    #Test Case
    w1 = wildcard_create_from_string("11111111")
    w2 = wildcard_create_from_string("11111110")
    w3 = wildcard_create_from_string("1111111x")
    w4 = wildcard_create_from_string("11111xxx")
    
    w5 = wildcard_create_from_string("xxxxxxxx")
    
    r1 = TF(1)
    #r1.add_rewrite_rule(TF.create_standard_rule([1], w1, [6], w5, w5))
    r1.add_rewrite_rule(TF.create_standard_rule([1], w2, [6], w5, w5))
    r1.add_rewrite_rule(TF.create_standard_rule([1], w4, [7], w5, w5))
    #r1.add_rewrite_rule(TF.create_standard_rule([3,1], w2, [4], w5, w5))
    
    r2 = TF(1)
    r2.add_rewrite_rule(TF.create_standard_rule([1], w3, [6], w5, w5))
    r2.add_rewrite_rule(TF.create_standard_rule([1], w4, [7], w5, w5))
    r2.add_rewrite_rule(TF.create_standard_rule([3], w2, [4], w5, w5))
    
    c = Comparator()
    r1 = c.TestDictGen(r1.rules)
    r2 = c.TestDictGen(r2.rules)
    print "========TF1========="
    for key, value in r1.iteritems():
        print '----Bucket: %s -----' % key
        c.printRules(value)
    print "========TF2========="
    for key, value in r2.iteritems():
        print '----Bucket: %s -----' % key
        c.printRules(value)
    
    nfr = c.compare(r1, r2)
    _nfr = c.compare(r2, r1)
    
    print '--------Not Found in TF1:------'
    c.printRules(nfr)
    print '--------Not Found in TF2:------'
    c.printRules(_nfr)
    '''