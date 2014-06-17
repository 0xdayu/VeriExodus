from cisco_translator import *
from openflow_translator import *
from headerspace.hs import *
from utils.wildcard import *


class Comparator:
    
    def __init__(self):
        
        self.ios_hs = {}
        self.of_hs = {}

    def compare(self, ios_tf, of_tf):
        pass

                
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
            if len(rule["out_ports"]) == 0:
                continue
            
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
                if len(rule["out_ports"]) == 0 or ign_ports(inports) : 
                    continue
                
                if rule["out_ports"][0] == 65535:
                    self.of_hs["controller_rules"] += [rule]
                    break
                
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
    
    @staticmethod
    def decoupleRules(rules):
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
                        temp.append(currentRule)
                        continue
                    tempWildcard = wildcard_diff(currentRule['match'], intersectPart)
                    for tw in tempWildcard:
                        if tw is None:
                            continue
                        t = currentRule.copy()
                        t['match'] = tw
                        temp.append(t)
            results += temp
        return results
    
    @staticmethod
    def printRules(rules):
        for key,value in rules.iteritems():
            print "============%s====================="% key
            for rule in value:
                if (rule['action'] == 'rw'):
                    print "in_ports: %s, match: %s => ((h & %s) | %s, %s)" % \
                        (rule['in_ports'], rule['match'], rule['mask'], \
                         rule['rewrite'], rule['out_ports'])
    
                if (rule['action'] == 'fwd'):
                    print "in_ports: %s, match: %s => (h , %s)" % \
                        (rule['in_ports'], rule['match'], rule['out_ports'])
    
                if (rule['action'] == 'link'):
                    print "in_ports: %s => out_ports: %s" % \
                        (rule['in_ports'], rule['out_ports'])
    
                if (rule['action'] == 'custom'):
                    print "match: %s , transform: %s" % \
                        (rule['match'].__name__, rule['transform'].__name__)

if __name__ == "__main__":
    c = Comparator()
    c.importOF()
    c.importIOS()
    print "===================IOS-FWD-Rules:==========================="
    c.printRules(c.ios_hs)
    print "===================OF-FWD-Rules:==========================="
    c.printRules(c.of_hs)
    #print "===================OF-Controller-Rules:==========================="
    #Comparator.printRules(of_tf.controller_rules)
    
    #decomposed
    
    '''ios_tf.rules = Comparator.decoupleRules(ios_tf.rules)
    of_tf.rules = Comparator.decoupleRules(of_tf.rules)
    
    print "================decomposed-IOS-FWD-Rules:===================="
    print ios_tf
    print "================decomposed-OF-FWD-Rules:===================="
    print of_tf'''
    
    '''w1 = wildcard_create_from_string("11111111")
    w3 = wildcard_create_from_string("11111110")
    w2 = wildcard_create_from_string("11111xxx")
    
    print wildcard_and(w3,w1)
    print wildcard_or(w3,w1)
    
    w4 = wildcard_create_from_string("xxxxxxxx")
    
    rules = TF(1)
    rules.add_rewrite_rule(TF.create_standard_rule([5], w1, [6], w4, w4))
    rules.add_rewrite_rule(TF.create_standard_rule([1], w3, [2], w4, w4))
    rules.add_rewrite_rule(TF.create_standard_rule([3], w2, [4], w4, w4))
    
    Comparator.printRules(rules.rules)
    
    rules.rules = Comparator.decoupleRules(rules.rules)
    print "====after====="
    Comparator.printRules(rules.rules)'''
