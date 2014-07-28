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

        # VERY expensive optimization
        self.opt_minimize_shadowing_per_cycle = True

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

    def numWildcardBits(self, wc):
        # Kludgey speed-hack to avoid figuring out the right bit-shifting for wildcards
        strwc = str(wc)
        return strwc.count("x")

    def decoupleRules(self, rules):
        print "\n\nIn decoupleRules... size=", len(rules)
        filtered_results = []
        results = [] # build up decorrelated rule-set
        higher_rules = [] # needs to be a list (see below)
        ruleCount = 0
        for rule in rules:
            print "Processing rule #", ruleCount
            #print "Rule match is: \n", parseWildcard(rule['match'])
            ruleCount += 1

            # Don't do anything to the first rule
            if(ruleCount == 1):
                results.append(rule)
                higher_rules.append(rule)
                continue;

            # HEURISTIC: This gives a *significant* reduction in space-usage
            # Split by largest wildcards first. (Order doesn't matter here, only *the collective shadow* of prior rules)
            # TODO: could be smarter to try to max the *shared* wildcards? (?)
            higher_rules = sorted(higher_rules, key=(lambda r : self.numWildcardBits(r['match'])), reverse=True)

            # INITIALIZE map to hold unshadowed fragments
            # Separate multi-in rules into single-in rules.
            # This imposes a slight linear-by-max-num-of-inports blowup, but most rules have low inport numbers
            ruleFragmentHSForInports = {}
            for inpt in rule['in_ports']:
                ruleFragmentHSForInports[inpt] = headerspace(rule['match'].length)
                ruleFragmentHSForInports[inpt].add_hs(rule['match'])

            # Use the original higher-priority rules, NOT their unshadowed fragments (avoid early exponential factor)
            priorCount = 0
            for higher in higher_rules:
                print "  Processing higher rule #", priorCount, "of",len(higher_rules)
                #print "  Higher-rule match is: \n", parseWildcard(higher['match'])
                #print "  Number of wildcard bits: ", self.numWildcardBits(higher['match'])
                priorCount += 1

                # same rule result? (mask, mod, and outport)
                # then ignore; don't split under the same rule
                # (possible side-effect: duplicate output for comparison)
                if(self.opt_no_shadow_same_action and
                   higher['out_ports'] == rule['out_ports'] and
                   wildcard_is_equal(higher['mask'],rule['mask']) and
                   wildcard_is_equal(higher['rewrite'],rule['rewrite'])):
                    #print "ignoring higher rule; same result, so not including it in the intersection to subtract"
                    #printRules([higher, rule])
                    continue;

                ####################
                # Compute the new set, shadowed by this higher-rule
                for inpt in higher['in_ports']:
                    # Anything to check?
                    if ruleFragmentHSForInports[inpt].copy_intersect(higher['match']).is_empty():
                        continue;

                    ruleFragmentHSForInports[inpt].diff_hs(higher['match'])
                    ruleFragmentHSForInports[inpt].self_diff() # All positive union, no lazy expressions

                    # Default HSA wildcards have reference equality
                    #print "*** ", higher['match'] == higher['match']
                    #print "*** ", higher['match'] == wildcard_copy(higher['match'])
                    #print "*** ", higher['match'] == rule['match']
                    # We want both to be True (so we can use sets) but not the final one

                    # HS library may still give fully-shadowed wildcards in the union, here.
                    if(self.opt_minimize_shadowing_per_cycle):
                        print "Number of fragments prior to calling remove shadows list: ", len(ruleFragmentHSForInports[inpt].hs_list)
                        ruleFragmentHSForInports[inpt].remove_shadows_list()

                    print "~~~ Port: ", inpt, "; Number of fragments ", len(ruleFragmentHSForInports[inpt].hs_list)
                ####################

            # Include this rule in splitting for later rules
            higher_rules.append(rule)

            newFragments = []
            countShadowed = 0
            for inpt in ruleFragmentHSForInports.keys():
                # Unique only
                for tw in set(ruleFragmentHSForInports[inpt].hs_list):
                    t = rule.copy()
                    t['match'] = tw
                    t['in_port'] = inpt
                    t['orig_rule_match'] = rule['match']
                    newFragments.append(t)

                    ## TODO: use a set, not a list

            # done looping
            print "Finished splitting rule", ruleCount-1, "; newFragments size = ", len(newFragments)
            print "Shadowed = ", countShadowed

            print "size of results pre: ", len(results)
            results.extend(newFragments)
            print "size of results post: ", len(results)


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


    print "Done decorrelating..."

    '''
    print "===================IOS-FWD-Rules:==========================="
    for key, value in c.ios_hs.iteritems():
        print '----Bucket: %s -----' % key
        printRules(value)
    '''


    '''print "===================OF-FWD-Rules (post-decorr):==========================="
    for key, value in c.of_hs.iteritems():
        print '----Bucket: %s -----' % key
        printRules(value)
'''



    nfr = c.compare(c.ios_hs, c.of_hs)
    _nfr = c.compare(c.of_hs, c.ios_hs)

    print '--------Not Found in TF1 (present in IOS; not present in OF):------'
    print " #rules: ", len(nfr)
    printRules(nfr)


    print '--------Not Found in TF2 (present in OF; not present in IOS):------'
    print " #rules: ", len(_nfr)
    printRules(_nfr)