from cisco_translator import *
from openflow_translator import *
from headerspace.hs import *
from utils.wildcard import *


class Comparator:

    def __init__(self):

        # key, value -> inports number, [rules]
        self.ios_hs = {}
        self.of_hs = {}
        
    def decompleTF(self, tf):
        for key, value in tf.iteritems():
            if key == "controller_rules":
                continue
            tf[key] = self.decoupleRules(value)

    def compare(self, tf1, tf2):
        '''
        #decouple two header spaces
        for key, value in tf1.iteritems():
            if key == "controller_rules":
                continue
            tf1[key] = self.decoupleRules(value)

        for key, value in tf2.iteritems():
            if key == "controller_rules":
                continue
            tf2[key] = self.decoupleRules(value)
        '''
        
        not_found_rules = []
        for key, value in tf1.iteritems():
            if key == "controller_rules":
                print "======Ignore Rules sent to the Controller====="
                continue
            if key in tf2.keys():
                #for r1 in value:
                #    print str(r1['match'])
                not_found_rules += self.compareRules(value, tf2[key])
            else:
                not_found_rules += value
        return not_found_rules

    def compareRules(self, rules1, rules2):
        not_found_rules = []

        for r1 in rules1:
            r2 = self.getHeaderSpaceWithSameActions(r1, rules2)
            if len(r2) == 0:
                not_found_rules.append(r1)
                continue

            temp = []
            temp.append(r1)
            for _r2 in r2:
                size = len(temp)
                for i in range(size):
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

        return not_found_rules

    def getHeaderSpaceWithSameActions(self, r1, rule_set): # get rules from rule_set with same inports, mask, rewrite and outports
        result = []
        for r2 in rule_set:
            if wildcard_is_equal(r1["mask"], r2["mask"]) and \
            wildcard_is_equal(r1["rewrite"], r2["rewrite"]) and \
            set(r1["out_ports"]) == set(r2["out_ports"]):

                result.append(r2)

        return result

    def importIOS(self, table_folder):
        ios = cisco_router(1)
        ios.read_inputs(table_folder + 'mac_table.txt',\
        table_folder + 'config.txt', \
        table_folder + 'route.txt', \
        table_folder + 'arp_table.txt')
        ios_tf = ios.generate_transfer_function()

        #port_map = {1:3, 2:1}
        #ios_ports = lambda n: port_map[n]

        inport_map = {1:3, 2:1}
        inport_mapper = lambda n: inport_map[n]
        outport_map = {1:3, 2:1}
        outport_mapper = lambda n: outport_map[n]

        for rule in ios_tf.rules:

            #map the port number to OF
            rule["in_ports"] = map(inport_mapper, rule["in_ports"])
            rule["out_ports"] = map(outport_mapper, rule["out_ports"])

            for inports in rule["in_ports"]:
                if inports in self.ios_hs.keys():
                    self.ios_hs[inports] += [rule]
                    #print str(rule['match'])
                else:
                    self.ios_hs[inports] = [rule]
                    #print str(rule['match'])

    def importOF(self, route_name, dump_file):

        of_tf = generate_of_tfs(route_name, dump_file)

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
                #print result['match']
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
                        #for debugging use
                        t['generated'] = rule
                        if 'shadowed' in t.keys():
                            t['shadowed'].append(result)
                        else:
                            t['shadowed'] = [result]

                        temp.append(t)
            results += temp

        #remove drop and controller rules
        for r in results:
            if not (len(r['out_ports']) == 0 or (65535 in r['out_ports'])):
                _results.append(r)
                #print str(r['match'])
        return _results

    @staticmethod
    def printRules(rules):
        for rule in rules:
            print "in_ports: %s, match: %s => ((h & %s) | %s, %s)" % \
                (rule['in_ports'], rule['match'], rule['mask'], \
                 rule['rewrite'], rule['out_ports'])
            
            '''
            print "in_ports: %s\n, match: %s\n, mask: %s\n, rewrite: %s\n, out_ports: %s\n" % \
                (rule['in_ports'], Comparator.parseWildcard(rule['match']), Comparator.parseWildcard(rule['mask']), \
                 Comparator.parseWildcard(rule['rewrite']), rule['out_ports'])
            print "--------------------"
            '''


            '''            
            #for debugging
            if 'generated' in rule.keys():
                print '---------Generated By-----------'
                r = rule['generated']
                print "in_ports: %s\n, match: %s\n, mask: %s\n, rewrite: %s\n, out_ports: %s\n" % \
                (r['in_ports'], Comparator.parseWildcard(r['match']), Comparator.parseWildcard(r['mask']), \
                 Comparator.parseWildcard(r['rewrite']), r['out_ports'])
                print '----------------------------'
            if 'shadowed' in rule.keys():
                print '---------Shadowed By-----------'
                s = rule['shadowed']
                for r in s:
                    print "in_ports: %s\n, match: %s\n, mask: %s\n, rewrite: %s\n, out_ports: %s\n" % \
                    (r['in_ports'], Comparator.parseWildcard(r['match']), Comparator.parseWildcard(r['mask']), \
                     Comparator.parseWildcard(r['rewrite']), r['out_ports'])
                print '----------------------------'
            print '********************************************************'
            '''
        


    @staticmethod
    def parseWildcard(w):

        format = {}
        format["vlan_pos"] = 0
        format["ip_src_pos"] = 2
        format["ip_dst_pos"] = 6
        format["ip_proto_pos"] = 10
        format["transport_src_pos"] = 11
        format["transport_dst_pos"] = 13
        format["transport_ctrl_pos"] = 15
        format["dl_src_pos"] = 16
        format["dl_dst_pos"] = 22
        format["dl_proto_pos"] = 28
        format["vlan_len"] = 2
        format["ip_src_len"] = 4
        format["ip_dst_len"] = 4
        format["ip_proto_len"] = 1
        format["transport_src_len"] = 2
        format["transport_dst_len"] = 2
        format["transport_ctrl_len"] = 1
        format["dl_src_len"] = 6
        format["dl_dst_len"] = 6
        format["dl_proto_len"] = 2
        format["length"] = 30

        fields = ["vlan","dl_src","dl_dst","dl_proto","ip_src","ip_dst","ip_proto","transport_src",\
          "transport_dst"]
        return wc_header_to_parsed_string(format, fields, w)



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
    c.importOF('int','/home/dyu/veriExodus/VeriExodus/hsa/examples/Exodus_toy_example/int/of-sat.txt')
    c.importIOS('/home/dyu/veriExodus/VeriExodus/hsa/examples/Exodus_toy_example/int/')
    
    c.decompleTF(c.ios_hs)
    c.decompleTF(c.of_hs)
    
    '''
    print "===================IOS-FWD-Rules:==========================="
    for key, value in c.ios_hs.iteritems():
        print '----Bucket: %s -----' % key
        c.printRules(value)
    '''
    
    '''
    print "===================OF-FWD-Rules:==========================="
    for key, value in c.of_hs.iteritems():
        print '----Bucket: %s -----' % key
        c.printRules(value)

    
    
    '''
    nfr = c.compare(c.ios_hs, c.of_hs)
    _nfr = c.compare(c.of_hs, c.ios_hs)

    print '--------Not Found in TF1:------'
    c.printRules(nfr)

    
    print '--------Not Found in TF2:------'
    c.printRules(_nfr)