'''
  <Cisco IOS parser --- Exodus Edition. Generates Transfer Function Objects>
  
  only support: static routing
                static acls
                
  The file is based on the original CISCO parser developed by Stanford University.

Created on May 2, 2014

@author: Da Yu
@author: Charles Yeh
'''

from headerspace.tf import *
from headerspace.hs import *
from utils.wildcard import *
from utils.helper import *

import re

NO_ETHERTYPE = 0

class cisco_router(object):
    
    def __init__(self, switch_id):
        
        # for each acl number has a list of acl dictionary entries
        self.acl = {}
        # arp table: ip-->(mac)
        self.arp_table = {}
        # mapping of ACLs to interfaces access-list# --> (interface, in/out, file, line)
        self.acl_iface = {}

        # interfaces without "in" ACLs
        self.ifaces_wo_in = []
        # interfaces without "out" ACLs
        self.ifaces_wo_out = []
        
        # interface name -> mac
        self.iface_mac = {}

        # TODO: not used
        # mac table: mac-->ports
        self.mac_table = {}
        # list of ports configured on this switch
        self.config_ports = set()

        self.switch_id = switch_id
        self.port_to_id = {}
        self.hs_format = self.HS_FORMAT()

        self.ID = 1;
        self.interface_ids = {}
    
        # dict(subnet -> list of (next_hop, interface))
        self.routes = {}
        
    @staticmethod
    def HS_FORMAT():
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
        return format
    
    @staticmethod
    def make_acl_dictionary_entry():
        entry = {}
        entry["action"] = True
        entry["src_ip"] = 0
        entry["src_ip_mask"] = 0xffffffff
        entry["dst_ip"] = 0
        entry["dst_ip_mask"] = 0xffffffff
        entry["ip_protocol"] = 0 # Note: this is used instead of any ip protocol
        entry["transport_src_begin"] = 0
        entry["transport_src_end"] = 0xffff
        entry["transport_dst_begin"] = 0
        entry["transport_dst_end"] = 0xffff
        entry["transport_ctrl_begin"] = 0
        entry["transport_ctrl_end"] = 0xff
        entry["etherType"] = 0
        return entry
    
    @staticmethod
    def get_protocol_number(proto_name):
        dict = {"ah":51, "eigrp":88, "esp":50, "gre":47, "icmp":1, "igmp":2, \
                "igrp":9, "ip": 0, "ipinip":94, "nos":4, "ospf":89, "tcp":6, \
                "udp":17}
        if proto_name in dict.keys():
            return dict[proto_name]
        else:
            try:
                num = int(proto_name)
                return num
            except Exception as e:
                return None
            
    @staticmethod
    def get_udp_port_number(port_name):
        dict = {"biff": 512, "bootpc":68, "bootps":69, "discard":9, \
                "domain":53, "dnsix":90, "echo":7, "mobile-ip":434, \
                "nameserver":42, "netbios-dgm":137, "netbios-ns":138,\
                "ntp":123, "rip":520, "snmp":161, "snmptrap":162, "sunrpc":111,\
                "syslog":514, "tacacs-ds":49, "talk":517, "tftp":69, "time":37,\
                "who":513, "xdmcp":177}
        if port_name in dict.keys():
            return dict[port_name]
        else:
            try:
                num = int(port_name)
                return num
            except Exception as e:
                return None
    
    @staticmethod
    def get_transport_port_number(port_name):
        dict = {"bgp":179, "chargen":19, "daytime":13, "discard":9, \
                "domain":53, "echo":7, "finger":79, "ftp":21, "ftp-data":20, \
                "gopher":70, "hostname":101, "irc":194, "klogin":543, \
                "kshell":544, "lpd":515, "nntp":119, "pop2":109, "pop3":110, \
                "smtp":25, "sunrpc":111, "syslog":514, "tacacs-ds":65, \
                "talk":517,"telnet":23, "time": 37, "uucp":540, "whois":43, \
                "www":80}
        if port_name in dict.keys():
            return dict[port_name]
        else:
            try:
                num = int(port_name)
                return num
            except Exception as e:
                return None
    
    def get_port_id(self, interface):
        if interface not in self.interface_ids:
            self.interface_ids[interface] = self.ID
            self.ID = self.ID + 1

        return self.interface_ids[interface]
    
    def parse_access_list_entry(self, entry, line_counter, acl_standard):
        def parse_ip(lst):
            result = {}
            if lst[0].lower() == "any":
                result["ip"] = 0
                result["ip_mask"] = 0xffffffff
                lst.pop(0)
            elif lst[0].lower() == "host":
                result["ip"] = dotted_ip_to_int(lst[1])
                result["ip_mask"] = 0
                lst.pop(0)
                lst.pop(0)
            elif is_ip_address(lst[0]):
                result["ip"] = dotted_ip_to_int(lst[0])
                if len(lst) > 1 and is_ip_address(lst[1]):
                    result["ip_mask"] = dotted_ip_to_int(lst[1])
                    lst.pop(0)
                    lst.pop(0)
                else:
                    result["ip_mask"] = 0
                    lst.pop(0)
            return result
    
        def parse_port(lst, proto):
            result = {}
            proto_reader = None
              
            if proto == 6:
                proto_reader = cisco_router.get_transport_port_number
            elif proto == 17:
                proto_reader = cisco_router.get_udp_port_number
            else:
                proto_reader = cisco_router.get_transport_port_number
                
            if lst[0] == "eq":
                lst.pop(0)
                p = proto_reader(lst.pop(0))
                if p != None:
                    result["port_begin"] = p
                    result["port_end"] = p
            elif lst[0] == "gt":
                lst.pop(0)
                p = proto_reader(lst.pop(0))
                if p != None:
                    result["port_begin"] = p + 1
                    result["port_end"] = 0xffff
            elif lst[0] == "range":
                lst.pop(0)
                p1 = proto_reader(lst.pop(0))
                p2 = proto_reader(lst.pop(0))
                if p1 != None and p2 != None:
                    result["port_begin"] = p1
                    result["port_end"] = p2
              
            return result
        
        tokens = entry.split()
        tokens.pop(0)
        acl_number = tokens.pop(0)
        
        action = tokens.pop(0)
        if action.lower() == "permit" or action.lower() == "deny": #only handle permit and deny
            if not acl_number in self.acl.keys():
                self.acl[acl_number] = []
            
            new_entry = self.make_acl_dictionary_entry()
            new_entry["action"] = (action.lower() == "permit")
             
        # standard access-list entry
        if acl_standard:
            new_entry["ip_protocol"] = 0
            new_entry["etherType"] = 0x0800 
            new_ip = parse_ip(tokens)
            if (len(new_ip.keys()) > 0):
                new_entry["src_ip"] = new_ip["ip"]
                new_entry["src_ip_mask"] = new_ip["ip_mask"]
                self.acl[acl_number].append(new_entry)
                #print self.acl_dictionary_entry_to_string(new_entry)
                return True
            else:
                return False
      
        # extended access-list entry
        else:
            new_entry["ip_protocol"] = 0
            new_entry["etherType"] = 0x0800

            if self.get_protocol_number(tokens[0]) != None:
                new_entry["ip_protocol"] = self.get_protocol_number(\
                    self.get_protocol_number(tokens.pop(0)))
            #else:
            #    return False
            
            # src ip address and ip mask
            new_ip = parse_ip(tokens)
            if (len(new_ip.keys()) > 0):
                new_entry["src_ip"] = new_ip["ip"]
                new_entry["src_ip_mask"] = new_ip["ip_mask"]

            # src transport port number
            if len(tokens) > 0:
                new_ports = parse_port(tokens, new_entry["ip_protocol"])
                if len(new_ports.keys()) > 0:
                    new_entry["transport_src_begin"] = \
                        new_ports["port_begin"]
                    new_entry["transport_src_end"] = new_ports["port_end"]
          
            # dst ip address and ip mask  
            if len(tokens) > 0:
                new_ip = parse_ip(tokens)
                if (len(new_ip.keys()) > 0):
                    new_entry["dst_ip"] = new_ip["ip"]
                    new_entry["dst_ip_mask"] = new_ip["ip_mask"]
            
            # dst transport port number
            if len(tokens) > 0:
                new_ports = parse_port(tokens, new_entry["ip_protocol"])
                if len(new_ports.keys()) > 0:
                    new_entry["transport_dst_begin"] = \
                      new_ports["port_begin"]
                    new_entry["transport_dst_end"] = new_ports["port_end"]
            
            # transport control bits
            if len(tokens) > 0:
                t = tokens.pop(0)
                if t == "established":
                    new_entry["transport_ctrl_begin"] = 0x80
                    new_entry["transport_ctrl_end"] = 0xff
            
            new_entry["line"] = [line_counter];
            self.acl[acl_number].append(new_entry)
            #print self.acl_dictionary_entry_to_string(new_entry)
            return True
            
        
    
    def parse_interface_config(self,iface_info,file_path):
        def is_in_range(range,val):
            st = range.split("-")
            if len(st) > 1 and int(val) >= int(st[0]) and int(val) <= int(st[1]):
                return True
            elif len(st) == 1 and int(val) == int(st[0]):
                return True
            else:
                return False
        
        iface_decl = iface_info[0][0].split()
        iface = iface_decl[1]

        has_in  = False
        has_out = False

        for (line, line_counter) in iface_info:
            if line.startswith("ip access-group"):
                tokens = line.split()
                acl_num = tokens[2]

                if acl_num not in self.acl_iface:
                    self.acl_iface[acl_num] = []
                self.acl_iface[acl_num].append((iface, tokens[3], file_path, [line_counter]))

                if tokens[3].lower() == "in":
                    has_in  = has_in or True
                if tokens[3].lower() == "out":
                    has_out = has_out or True

        if not has_in:
            self.ifaces_wo_in.append(iface)
        if not has_out:
            self.ifaces_wo_out.append(iface)
    
    def read_config_file(self, file_path):
        print "=== Reading Cisco Router Config File ==="
        f = open(file_path,'r')
        ipacl_start = ""
        reading_iface = False
        reading_ipacl = False
        ipacl_std = False
        iface_info = []
        line_counter = 0
        for line in f:
            line = line.strip()
            # read an access-list line 
            if line.startswith("access-list"):
                reading_ipacl = False
                reading_iface = True
                self.parse_access_list_entry(line,line_counter, int(line.split()[1]) < 100)
            elif line.startswith("ip access-list"):
                reading_ipacl = True
                reading_iface = False
                ipacl_start = (line.split())[3]
                if ((line.split())[2] == "standard"):
                    ipacl_std = True
                else:
                    ipacl_std = False

            elif reading_ipacl and (line.startswith("permit") or line.startswith("deny")):
                entry = "access-list %s %s" % (ipacl_start, line);
                self.parse_access_list_entry(entry,line_counter, ipacl_std)
                
                # read interface config
            elif line.startswith("interface"):
                reading_ipacl = False
                reading_iface = True
                iface_info = [(line,line_counter)]
            elif reading_iface:
                iface_info.append((line,line_counter))
                if line.startswith("!"):
                    reading_ipacl = False
                    reading_iface = False
                    self.parse_interface_config(iface_info,file_path)
                line_counter = line_counter + 1
        f.close()
        print "=== DONE Reading Cisco Router Config File ==="

    def read_mac_table(self, file_path):
        f = open(file_path, 'r')

        lines = f.readlines()[2:]
        for line in lines:
            line = line.strip().split()
            if len(line) > 0:
                self.iface_mac[line[6]] = line[2]

        f.close()

    def read_route_table_file(self, file_path):
        f = open(file_path, 'r')
        lines = f.readlines()[1:]
        for line in lines:
            line = line.strip().split()
            
            subnet   = line[0]
            next_hop = line[1]
            
            if subnet not in self.routes:
                self.routes[subnet] = []

            if next_hop.lower() == "drop":
                self.routes[subnet].append(("drop", None))
            else:
                self.routes[subnet].append((next_hop, line[2]))
        
    def read_arp_table_file(self, file_path):
        print "=== Reading Cisco Router Config File ==="
        f = open(file_path, 'r')
        lines = f.readlines()[1:]
        for line in lines:
            line = line.strip().split()
            
            ipaddr  = line[1]
            macaddr = line[3]
            self.arp_table[ipaddr] = int(macaddr.replace('.', ''), 16)
            
        print "=== DONE Reading Cisco ARP Table File ==="
        
    def generate_transfer_function(self):
        def generate_acl_tf(direction, bypass_ifaces):
            tf_acl = TF(self.hs_format["length"])
            for acl_num in self.acl:
                acl_rules = self.acl[acl_num]
                
                # current acl not used on any interfaces
                if acl_num not in self.acl_iface:
                    continue
                
                # get inports through interfaces
                inports = set()
                for iface_info in self.acl_iface[acl_num]:
                    if iface_info[1] == direction:
                        inports.add(self.get_port_id(iface_info[0]))
                if len(inports) == 0:
                    continue

                inports = list(inports)

                # make a tf rule for each acl rule
                for rule in acl_rules:
                    match   = wildcard_create_bit_repeat(self.hs_format["length"], 0x3)
                    mask    = wildcard_create_bit_repeat(self.hs_format["length"], 0x2)
                    rewrite = wildcard_create_bit_repeat(self.hs_format["length"], 0x1)
                    
                    # PROTOCOLS
                    if rule["etherType"] != NO_ETHERTYPE:
                        set_header_field(self.hs_format, match, "dl_proto", rule["etherType"], 0)
                    if rule["ip_protocol"]:
                        set_header_field(self.hs_format, match, "ip_proto", rule["ip_protocol"], 0)
    
                    # IPS
                    set_masked(match, "ip_src", rule["src_ip_mask"], rule["src_ip"])
                    set_masked(match, "ip_dst", rule["dst_ip_mask"], rule["dst_ip"])
    
                    # TRANSPORT_PORT
                    set_range(match, "transport_src", rule["transport_src_begin"], rule["transport_src_end"])
                    set_range(match, "transport_dst", rule["transport_dst_begin"], rule["transport_dst_end"])
    
                    set_range(match, "transport_ctrl", rule["transport_ctrl_begin"], rule["transport_ctrl_end"])
    
                    if rule["action"]:
                        # permit
                        for i in inports:
                            tfrule = TF.create_standard_rule([i], match, [i], mask, rewrite)
                            tf_acl.add_rewrite_rule(tfrule)
                    else:
                        # deny
                        tfrule = TF.create_standard_rule(inports, match, [], mask, rewrite)
                        tf_acl.add_rewrite_rule(tfrule)
    
            # add interfaces without in, let them bypass
            for iface in bypass_ifaces:
                iport = self.get_port_id(iface)
                match   = wildcard_create_bit_repeat(self.hs_format["length"], 0x3)
                mask    = wildcard_create_bit_repeat(self.hs_format["length"], 0x2)
                rewrite = wildcard_create_bit_repeat(self.hs_format["length"], 0x1)

                tfrule = TF.create_standard_rule([iport], match, [iport], mask, rewrite)
                tf_acl.add_rewrite_rule(tfrule)

            return tf_acl

        def set_range(wc, fieldname, start, end):
            if start == 0 and end == 65535:
                pass
            elif start == end:
                set_header_field(self.hs_format, wc, fieldname, start, 0)
            # TODO: handle ranges
        
        def set_masked(wc, fieldname, mask, val):
            set_header_field(self.hs_format, wc, fieldname, val, find_num_mask_bits_right_mak(mask))
        
        #-------------------------- IN ACL --------------------------
        tf_in_acl = generate_acl_tf("in", self.ifaces_wo_in)

        #----------------------- STATIC ROUTING -----------------------
        tf_rtr = TF(self.hs_format["length"])
        sizes = {}
        for subnet in self.routes:
            [subnetIp, subnetMask] = dotted_subnet_to_int(subnet)
            if subnetMask not in sizes:
                sizes[subnetMask] = []
            
            sizes[subnetMask].append(subnet)
            
        for i in range(32, -1, -1):
            if i not in sizes:
                continue

            for subnet in sizes[i]:
                [subnetIp, subnetMask] = dotted_subnet_to_int(subnet)
                    
                for route in self.routes[subnet]:
                    inports = []
                    match   = wildcard_create_bit_repeat(self.hs_format["length"], 0x3)
                    mask    = wildcard_create_bit_repeat(self.hs_format["length"], 0x2)
                    rewrite = wildcard_create_bit_repeat(self.hs_format["length"], 0x1)
                    outports = [self.get_port_id(route[1])]

                    if route[0].lower() == "drop":
                        tfrule = TF.create_standard_rule(inports, match, [], mask, rewrite)
                        tf_rtr.add_rewrite_rule(tfrule)
                        continue
                    
                    # match
                    set_header_field(self.hs_format, match, "ip_dst", subnetIp, 32 - subnetMask)

                    # mask
                    newmask = wildcard_create_bit_repeat(self.hs_format["dl_src_len"], 0x1)
                    set_wildcard_field(self.hs_format, mask, "dl_src", newmask, 0)
                    
                    # rewrite
                    macaddr = int(self.iface_mac[route[1]].replace('.', ''), 16)
                    set_header_field(self.hs_format, rewrite, "dl_src", macaddr, 0)

                    if route[0].lower() == "attached":
                        # make one rule for each destination ip
                        subnetMask = ((1 << subnetMask) - 1) << (32 - subnetMask)
                        for ip in self.arp_table:
                            if dotted_ip_to_int(ip) & subnetMask == subnetIp & subnetMask:
                                newmask    = wildcard_copy(mask)
                                newrewrite = wildcard_copy(rewrite)
                                
                                replacemask = wildcard_create_bit_repeat(self.hs_format["dl_dst_len"], 0x1)
                                set_wildcard_field(self.hs_format, newmask, "dl_dst", replacemask, 0)
                                
                                macaddr = self.arp_table[ip]
                                set_header_field(self.hs_format, newrewrite, "dl_dst", macaddr, 0)
        
                                tfrule = TF.create_standard_rule(inports, match, outports, newmask, newrewrite)
                                tf_rtr.add_rewrite_rule(tfrule)
                    else:
                        # normal routing
                        newmask    = wildcard_copy(mask)
                        newrewrite = wildcard_copy(rewrite)

                        replacemask = wildcard_create_bit_repeat(self.hs_format["dl_dst_len"], 0x1)
                        set_wildcard_field(self.hs_format, newmask, "dl_dst", replacemask, 0)
                        
                        # get MAC of next hop
                        macaddr = self.arp_table[route[0]]
                        set_header_field(self.hs_format, newrewrite, "dl_dst", macaddr, 0)
        
                        tfrule = TF.create_standard_rule(inports, match, outports, newmask, newrewrite)
                        tf_rtr.add_rewrite_rule(tfrule)
                    
        #-------------------------- OUT ACL --------------------------
        tf_out_acl = generate_acl_tf("out", self.ifaces_wo_out)

        
        #--------------------------- MERGE ---------------------------
        tf_inacl_rtr = TF.merge_tfs(tf_in_acl, tf_rtr, TF.id_port_mapper, lambda n : False)
        tf_full = TF.merge_tfs(tf_inacl_rtr, tf_out_acl, TF.id_port_mapper, lambda n : False)
        
        # add implicit all drop
        match   = wildcard_create_bit_repeat(self.hs_format["length"], 0x3)
        mask    = wildcard_create_bit_repeat(self.hs_format["length"], 0x2)
        rewrite = wildcard_create_bit_repeat(self.hs_format["length"], 0x1)
        tf_full.add_rewrite_rule(TF.create_standard_rule([], match, [], mask, rewrite))

        write_file('ios_tf_in_acl', tf_in_acl)
        write_file('ios_tf_rtr', tf_rtr)
        write_file('ios_tf_out_acl', tf_out_acl)

        write_file('ios_merge_1', tf_inacl_rtr)
        write_file('ios_merge_2', tf_full)

        return tf_full
    def read_inputs(self, mac_table, config_file, route_table, arp_table):
        self.read_mac_table(mac_table);
        self.read_config_file(config_file)
        self.read_route_table_file(route_table)
        self.read_arp_table_file(arp_table)

def write_file(fname, tf):
    f = open(fname, 'w')
    f.write(str(tf))
    f.close()
        
if __name__ == "__main__":
    cs = cisco_router(1)
    example_folder = '../examples/Exodus_toy_example/'
    cs.read_inputs(example_folder + 'ext_mac_table.txt', example_folder + 'ext_config.txt', example_folder + 'ext_route.txt', example_folder + 'ext_arp_table.txt')

    tf = cs.generate_transfer_function()
    """
    f = open('result_tf.txt', 'w')
    f.write(str(tf))
    f.close()
    """


