from cisco_translator import *
from openflow_translator import *
from headerspace.hs import *
from utils.wildcard import *
from hsa_pretty_print import *

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

        inport_map = {1:1, 2:3}
        inport_mapper = lambda n: inport_map[n]
        outport_map = {1:1, 2:3}
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

# "temp", "results", "result" "_result", ... ?
    def decoupleRules(self, rules):
        print "In decoupleRules... size=", len(rules)
        filtered_results = []
        results = [] # build up decorrelated rule-set

        ruleCount = 0
        for rule in rules:
            print "Processing rule #", ruleCount
            ruleCount += 1


            temp = [] # fragments of original rule that survive shadowing. really a *set*, not a list
            temp.append(rule)
            print "Results had", len(results), " rule fragments to compute intersections for."
            for higher in results:
                newfragments = [] # result of this stage of splitting

                # same rule result? (mask, mod, and outport)
                # then ignore; don't split under the same rule
                # (possible side-effect: duplicate output for comparison)
                if(higher['out_ports'] == rule['out_ports'] and
                   wildcard_is_equal(higher['mask'],rule['mask']) and
                   wildcard_is_equal(higher['rewrite'],rule['rewrite'])):
                    #print "\nignoring higher rule; same result. keeping lower rule fully intact."
                    #printRules([higher, rule])
                    continue;

                    # remove shadowed by etc. since that is ALREADY IN THE LIBRARY

                for i in range(len(temp)): # for every fragment generated as of last iteration, check for shadowing
                    #print "i = ", i, " in temp... len = ", len(temp)
                    #print "temp[0]['match'] = ", str(temp[0]['match'])
                    currentRule = temp[i]
                    #if(len(temp) > 0):
                    #    print "mod temp[0]['match'] = ", str(temp[0]['match'])
                    intersectParts = wildcard_intersect(currentRule['match'], higher['match'])

                    # no intersect parts
                    if (len(intersectParts) == 0):
                        newfragments.append(currentRule) # no modifications to this element of temp
                        continue # move to next element of temp

                    newWildcards = wildcard_diff(currentRule['match'], intersectParts)
                    for tw in newWildcards:
                        if tw is None:
                            continue

                        t = currentRule.copy()
                        t['match'] = tw
                        #for debugging use
                        t['generated'] = rule
                        if 'shadowed' in t.keys():
                            t['shadowed'].append(higher)
                        else:
                            t['shadowed'] = [higher]
                        # new decorrelated piece of header-space
                        newfragments.append(t)

                # done looping: newfragments now holds the latest results
                temp = newfragments
                #print "Finished a higher rule split; newfragments size = ", len(newfragments)
            # done splitting this rule
            results += temp
            print "Finished splitting rule", ruleCount-1, "; temp size = ", len(temp)

        #remove drop and controller rules --> filtered_results
        for r in results:
            if not (len(r['out_ports']) == 0 or (65535 in r['out_ports'])):
                filtered_results.append(r)
                #print str(r['match'])

        return filtered_results



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
    ''' TODO: -i and -o options '''
    c.importOF('int','../examples/Exodus_toy_example/int/of-sat.txt')
    c.importIOS('../examples/Exodus_toy_example/int/')

    print "===================OF-FWD-Rules (Before decorr):==========================="
    for key, value in c.of_hs.iteritems():
        print '----Bucket: %s -----' % key
        printRules(value)

    print "Starting to decorrelate..."

    c.decompleTF(c.ios_hs)
    c.decompleTF(c.of_hs)

    sys.exit()

    print "Done decorrelating..."

    '''
    print "===================IOS-FWD-Rules:==========================="
    for key, value in c.ios_hs.iteritems():
        print '----Bucket: %s -----' % key
        printRules(value)
    '''


    print "===================OF-FWD-Rules (post-decorr):==========================="
    for key, value in c.of_hs.iteritems():
        print '----Bucket: %s -----' % key
        printRules(value)




    nfr = c.compare(c.ios_hs, c.of_hs)
    _nfr = c.compare(c.of_hs, c.ios_hs)

    print '--------Not Found in TF1 (present in IOS; not present in OF):------'
    printRules(nfr)


    print '--------Not Found in TF2 (present in OF; not present in IOS):------'
    printRules(_nfr)