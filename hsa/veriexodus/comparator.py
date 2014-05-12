from cisco_translator import *
from openflow_translator import *

class VeriComparator:
    @staticmethod
    def rule_is_equal(r1, r2, port_map):
        actual_inports = map(port_map, r1["in_ports"])
        actual_outports = map(port_map, r1["out_ports"])

        is_drop_rule = len(actual_outports) == 0 and len(r2["out_ports"]) == 0

        return set(actual_inports) == set(r2["in_ports"]) and       \
               (is_drop_rule and wildcard_is_equal(r1["match"], r2["match"]) or      \
               wildcard_is_equal(r1["match"], r2["match"]) and      \
                wildcard_is_equal(r1["mask"], r2["mask"]) and        \
                wildcard_is_equal(r1["rewrite"], r2["rewrite"]) and  \
                set(actual_inports) == set(r2["in_ports"]) and       \
                set(actual_outports) == set(r2["out_ports"]))

    def compare(self):
        example_folder = '../examples/Exodus_toy_example/'
        ios = cisco_router(1)
        ios.read_inputs(example_folder + 'ext_mac_table.txt', example_folder + 'ext_config.txt', example_folder + 'ext_route.txt', example_folder + 'ext_arp_table.txt')
        ios_tf = ios.generate_transfer_function()

        of_tf = generate_ext()

        port_map = {1:3, 2:1}
        ios_ports = lambda n: port_map[n]
        ign_ports = lambda n: n % 2 == 0
        
        filtered_rules = []
        for rule in of_tf.rules:
            if reduce(lambda rule, n: rule and not ign_ports(n), rule["in_ports"], True) and rule["out_ports"] != [65535]:
                filtered_rules.append(rule)
            
        of_tf.rules = filtered_rules
        
        # ios_tf ?= of_tf
        i1 = 0
        while i1 < len(ios_tf.rules):
            i2 = 0

            while i2 < len(of_tf.rules):
                r1 = ios_tf.rules[i1]
                r2 = of_tf.rules[i2]
                
                # map ports?
                if self.rule_is_equal(r1, r2, ios_ports):
                    print "===========match==========="
                    print str(r1["in_ports"]) + " => " + str(r1["out_ports"])
                    print r1["match"]
                    print r1["mask"]
                    print r1["rewrite"]
                    ios_tf.rules.pop(i1)
                    of_tf.rules.pop(i2)
                    i2 = i2 - 1
                    i1 = i1 - 1

                i2 = i2 + 1
            i1 = i1 + 1
        
        print "leftover rules:"
        print "OF:"
        print of_tf
        print "IOS:"
        print ios_tf

if __name__ == "__main__":
    v = VeriComparator()
    v.compare()

