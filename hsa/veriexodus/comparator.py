from cisco_translator import *
from openflow_translator import *
from headerspace.hs import *
from utils.wildcard import *


class Comparator:
    

    def compare(self, ios_tf, of_tf):
        

                
    def importIOS(self):
        example_folder = '../examples/Exodus_toy_example/'
        ios = cisco_router(1)
        ios.read_inputs(example_folder + 'ext_mac_table.txt',\
        example_folder + 'ext_config.txt', \
        example_folder + 'ext_route.txt', \
        example_folder + 'ext_arp_table.txt')
        ios_tf = ios.generate_transfer_function()
        
        filtered_rules = []
        for rule in ios_tf.rules:
            if len(rule["out_ports"]) == 0:
                continue
            filtered_rules.append(rule)
            
        ios_tf.rules = filtered_rules
        
        return ios_tf
        
    
    def importOF(self):
        
        of_tf = generate_ext()

        port_map = {1:3, 2:1}
        ios_ports = lambda n: port_map[n]
        ign_ports = lambda n: n % 2 == 0

         # filter OpenFlow rules
        filtered_rules = []
        of_controller_rules = []
        for rule in of_tf.rules:
            if reduce(lambda result, n: result and not ign_ports(n), rule["in_ports"], True):
                if len(rule["out_ports"]) == 0:
                    continue
                
                if rule["out_ports"][0] == 65535:
                    of_controller_rules.append(rule)
                    continue
                
                filtered_rules.append(rule)
        
        of_tf.rules = filtered_rules
        of_tf.controller_rules = of_controller_rules
        
        return of_tf


if __name__ == "__main__":
    c = Comparator()
    of_tf = c.importOF()
    ios_tf = c.importIOS()
    print "===============IOS:==================="
    print ios_tf
    print "===============OF:===================="
    print of_tf
    
    c.compare()
    
    
    #c.compare()
