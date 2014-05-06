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

class cisco_router(object):
    
    def __init__(self, switch_id):
        
        # for each acl number has a list of acl dictionary entries
        self.acl = {}
        # forwarding table
        self.fwd_table = []
        # arp table: ip-->(mac)
        self.arp_table = {}
        # mac table: mac-->ports
        self.mac_table = {}
        # mapping of ACLs to interfaces access-list# --> (interface, in/out, file, line)
        self.acl_iface = {}
        # list of ports configured on this switch
        self.config_ports = set()

        self.switch_id = switch_id
        self.port_to_id = {}
        self.hs_format = self.HS_FORMAT()
    
        
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
            if self.get_protocol_number(tokens[0]) != None:
                new_entry["ip_protocol"] = self.get_protocol_number(\
                    self.get_protocol_number(tokens.pop(0)))
            elif is_ip_address(tokens[0]):
                new_entry["ip_protocol"] = 0
                new_entry["etherType"] = 0x0800
            else:
                return False
            
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
        
        tokens = iface_info[0][0].split()
        print tokens
         
    
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
                self.parse_access_list_entry(line,line_counter, int(line.split()[1]) < 100)
            elif line.startswith("ip access-list"):
                reading_ipacl = True
                ipacl_start = (line.split())[3]
                if ((line.split())[2] == "standard"):
                    ipacl_std = True
                else:
                    ipacl_std = False
            elif reading_ipacl and (line.lstrip().startswith("permit") or line.lstrip().startswith("deny")):
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
                    reading_iface = False
                    self.parse_interface_config(iface_info,file_path)
                line_counter = line_counter + 1
        f.close()
        print "=== DONE Reading Cisco Router Config File ==="
        
    def read_arp_table_file(self, file_path):
        print "=== Reading Cisco Router Config File ==="
        print "=== DONE Reading Cisco ARP Table File ==="
        
    def read_mac_table_file(self, file_path):
        print "=== Reading Cisco Router Config File ==="
        print "=== DONE Reading Cisco MAC Table File ==="
        
    def generate_transfer_function(self, tf):
        pass
    
    
        
if __name__ == "__main__":
    cs = cisco_router(1)
    cs.read_config_file("../examples/Exodus_toy_example/toy_example/ext_config.txt")
    cs.read_config_file("../examples/Exodus_toy_example/toy_example/int_config.txt")
    #cs.read_arp_table_file(file_path)
    #cs.read_mac_table_file(file_path)
    tf = TF(cs.hs_format["length"])
    cs.generate_transfer_function(tf)
