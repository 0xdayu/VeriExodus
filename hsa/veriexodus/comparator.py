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
        # adjust this to turn the optimization on and off
        self.opt_no_shadow_same_action = True

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

    def decoupleRules(self, rules):
        print "In decoupleRules... size=", len(rules)
        filtered_results = []
        results = [] # build up decorrelated rule-set
        higher_rules = []
        ruleCount = 0
        for rule in rules:
            print "Processing rule #", ruleCount
            ruleCount += 1

            # Don't do anything to the first rule
            if(ruleCount == 1):
                results.append(rule)
                higher_rules.append(rule)
                continue;

            intersectionWCs = []
            # Use the original higher-priority rules, NOT results (avoid early exponential factor)
            priorCount = 0
            for higher in higher_rules:
                print "Processing higher rule #", priorCount
                priorCount += 1

                # same rule result? (mask, mod, and outport)
                # then ignore; don't split under the same rule
                # (possible side-effect: duplicate output for comparison)
                if(self.opt_no_shadow_same_action and
                   higher['out_ports'] == rule['out_ports'] and
                   wildcard_is_equal(higher['mask'],rule['mask']) and
                   wildcard_is_equal(higher['rewrite'],rule['rewrite'])):
                    print "ignoring higher rule; same result, so not including it in the intersection to subtract"
                    #printRules([higher, rule])
                    continue;

                # TODO: remove shadowed by etc. since that is ALREADY IN THE LIBRARY
                # (under different field names. see 'affected_by')

                # Get intersection w/ higher rule and add to list
                print "intersecting with ", higher['match']
                intersectParts = wildcard_intersect(rule['match'], higher['match'])
                #print "intersecting ", rule['match'], higher['match']
                print "intersect parts: ", intersectParts, intersectParts.length
                if(intersectParts.length > 0):
                    # don't blindly append. is this intersectParts *fully* shadowed by anything else in intersectWC?
                    # TODO: what if the new thing shadows the old thing?
                    shadowed = False
                    for otherint in intersectionWCs:
                        if(wildcard_is_subset(intersectParts, otherint)):
                            print "[][][][][][] intersect parts is shadowed; ignoring it"
                            shadowed = True
                            break;
                    if(not shadowed):
                        intersectionWCs.append(intersectParts)
                        # NOT wildcard_or; that will bitwise-or the wildcards

            higher_rules.append(rule)

            # No intersections. still need to save the (fully intact) rule
            if(len(intersectionWCs) == 0):
                results.append(rule)
                continue

            #wildcard_or(intersectionWC,intersectParts)
            #newWildcards = wildcard_diff(rule['match'], intersectionWCs)
            hsRuleMatch = headerspace(rule['match'].length)
            # copy the WC, prevent reference overlap
            hsRuleMatch.add_hs(wildcard_copy(rule['match']))
            # *lazy* diff
            hsRuleMatch.diff_hs_list(intersectionWCs)
            # resolve lazy diff (EXPENSIVE!)
            print hsRuleMatch
            hsRuleMatch.self_diff()
            # ASSUMPTION: at this point, hsRuleMatch.hs_diff should contain only empty-lists
            # Given that, it is safe to take the union of hsRuleMatch.hs_list
            print "new match size", len(hsRuleMatch.hs_list)

            newFragments = []
            for tw in hsRuleMatch.hs_list:
                if tw is None:
                    continue

                # HS library may still give fully-shadowed wildcards in the union, here.
                # Check that a new fragment we added doesn't overshadow this one:
                shadowed = False
                for arule in newFragments:
                    if wildcard_is_subset(tw, arule['match']):
                        shadowed = True
                        #print "shadowed in diff'd union. ignoring"
                        break
                if(shadowed):
                    continue

                t = rule.copy()
                t['match'] = tw
                newFragments.append(t)

            # done looping
            results.extend(newFragments)
            print "Finished splitting rule", ruleCount-1, "; newFragments size = ", len(newFragments)


        print "pre-Filtered results size: ", len(results)
        #remove drop and controller rules --> filtered_results
        for r in results:
            if not (len(r['out_ports']) == 0 or (65535 in r['out_ports'])):
                filtered_results.append(r)
                #print r['match']

        print "Filtered results size: ", len(filtered_results)
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