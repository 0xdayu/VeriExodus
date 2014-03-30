#!/usr/bin/python

import argparse
import json
import sys
import copy
from config_parser.transfer_function_to_openflow import OpenFlow_Rule_Generator
from config_parser.cisco_router_parser import cisco_router
from headerspace.tf import TF
from utils.wildcard_utils import set_header_field
from utils.wildcard import wildcard_create_bit_repeat
from utils.helper import dotted_subnet_to_int


OUTPORT_CONST = cisco_router.OUTPUT_PORT_TYPE_CONST * cisco_router.PORT_TYPE_MULTIPLIER
INTER_CONST = cisco_router.INTERMEDIATE_PORT_TYPE_CONST * cisco_router.PORT_TYPE_MULTIPLIER
HS_FORMAT = cisco_router.HS_FORMAT();

def get_fwd_port_id(a_port):
    return int(a_port / cisco_router.SWITCH_ID_MULTIPLIER) * cisco_router.SWITCH_ID_MULTIPLIER

ofg = OpenFlow_Rule_Generator(None,cisco_router.HS_FORMAT())
def get_openflow_rule(rule,inv_mapf):
    in_ports = "in_ports:"
    for p in rule["in_ports"]:
        in_ports = in_ports + inv_mapf[p] + ","
    in_ports = in_ports[0:-1]
    out_ports = "out_ports:"
    if len(rule["out_ports"]) > 0:
        for p in rule["out_ports"]:
            out_ports = out_ports + inv_mapf[p] + ","
    else:
        out_ports = out_ports + "None,"
    out_ports = out_ports[0:-1]
    of_rule = ofg.parse_rule(rule)
    (match,rw) = ofg.pretify(of_rule)
    return "%s%s; %s%s;"%(match,in_ports,rw,out_ports)

def get_stage(rule):
    if len(rule["in_ports"]) == 0:
        return "in"
    sample = rule["in_ports"][0]
    if sample % cisco_router.SWITCH_ID_MULTIPLIER == 0:
        return "mid"
    elif sample % cisco_router.SWITCH_ID_MULTIPLIER < cisco_router.PORT_TYPE_MULTIPLIER:
        return "in"
    else:
        return "out"

def parse_new_rule_tokens(tokens,mapf,rtr):
    in_ports = []
    out_ports = []
    match = wildcard_create_bit_repeat(HS_FORMAT["length"],0x3)
    mask = None
    rw = None
    for token in tokens:
        parts = token.split("=")
        field_name = parts[0]
        if field_name.startswith("new"):
            if mask == None:
                mask = wildcard_create_bit_repeat(HS_FORMAT["length"],0x2)
                rw = wildcard_create_bit_repeat(HS_FORMAT["length"],0x1)
            field_name = field_name[4:]
            if field_name in ["ip_src","ip_dst"]:
                [value,left_mask] = dotted_subnet_to_int(parts[1])
                right_mask = 32 - left_mask
            else:
                value = int(parts[1])
                right_mask = 0
                set_header_field(cisco_router.HS_FORMAT(), mask, field_name, 0, right_mask)
                set_header_field(cisco_router.HS_FORMAT(), rw, field_name, value, right_mask)
        else:
            if field_name in ["in_ports","out_ports"]:
                ports = parts[1].split(",")
                ports_int = []
                for port in ports:
                    ports_int.append(int(mapf[rtr][port]))
                if field_name == "in_ports":
                    in_ports = ports_int
                else:
                    out_ports = ports_int
            else:
                if field_name in ["ip_src","ip_dst"]:
                    [value,left_mask] = dotted_subnet_to_int(parts[1])
                    right_mask = 32 - left_mask
                else:
                    value = int(parts[1])
                    right_mask = 0
                set_header_field(cisco_router.HS_FORMAT(), match, field_name, value, right_mask)
    rule = TF.create_standard_rule(in_ports, match, out_ports, mask, rw, "", [])
    return rule


parser = argparse.ArgumentParser(description='Command line tool to view/edit transfer functions')
parser.add_argument('rtr_name',
                   help='name of the router to work on its transfer function.')
parser.add_argument("--view", nargs=1, metavar=('table'),
                    help="view rules in table (table: in/mid/out).")
parser.add_argument("--rm", nargs=1, metavar=('rule_indices'),
                    help="removes the rules with rule_indices from the transfer function.")
parser.add_argument("--add", nargs=2, metavar=('rule_indices','rules'),
                    help="add a set of rules at indices rule_indices to the router. rule is a\
                    semi-colon separated list of field=value or new_filed=new_value.\
                    example: \"in_port=te1/1,te2/2;ip_dst=10.0.1.0/24;new_vlan=10;out_ports=te1/2,te1/3\"\
                    field can be vlan, ip_src, ip_dst, ip_proto, transport_src, trnsport_dst.\
                    in_ports and out_ports specify the input and output ports, separated by a comma.\
                    Note that rule description should be between \" \".\
                    If adding more than one rule, the rule positions should be separated by comma and \
                    the rules should be separated by colon.")
parser.add_argument("-m", "--map_file", default="port_map.json",
                    help="Port map file name.")
parser.add_argument("-p", "--data_path", default=".",
                    help="Path to where the json transfer function files are stored")
args = parser.parse_args()

f = open("%s/%s"%(args.data_path,args.map_file),'r')
mapf = json.load(f)
mapf_extended = copy.deepcopy(mapf)
inv_mapf = {}
for rtr in mapf:
    for port in mapf[rtr]:
        inv_mapf[int(mapf[rtr][port])] = "%s-%s"%(rtr,port)
        inv_mapf[int(mapf[rtr][port])+OUTPORT_CONST] = "%s-%s"%(rtr,port)
        inv_mapf[int(mapf[rtr][port])+INTER_CONST] = "^%s-%s"%(rtr,port)
        mapf_extended[rtr]["^%s"%port] = mapf[rtr][port] + INTER_CONST
    fwd_id = get_fwd_port_id(int(mapf[rtr][port]))
    inv_mapf[fwd_id] = "FWD-ENGINE"
    mapf_extended[rtr]["^"] = fwd_id


f = TF(1)
f.load_from_json("%s/%s.tf.json"%(args.data_path,args.rtr_name))
print "Modifying transfer function of router ",args.rtr_name

if args.view:
    stage = args.view[0]
    i = 1
    for rule in f.rules:
        if stage == get_stage(rule):
            print i,":",get_openflow_rule(rule,inv_mapf)
        i = i + 1;
if args.rm:
    indices = args.rm[0].split(",")
    indices = [int(i) for i in indices]
    indices.sort(reverse=True)
    for index in indices:
        f.remove_rule(index-1)

if args.add:
    positions = (args.add[0]).split(",")
    rules = (args.add[1]).split(":")
    if len(rules) != len(positions):
        sys.stderr.write("Number of positions and number of rules should be the same")
    for i in range(len(positions)):
        position = int(positions[i])-1
        tokens = rules[i].split(";")
        rule = parse_new_rule_tokens(tokens,mapf_extended,args.rtr_name)
        if rule["mask"] == None:
            f.add_fwd_rule(rule,position)
        elif rule["mask"] != None:
            f.add_rewrite_rule(rule,position)

f.save_object_to_file("%s/%s.tf"%(args.data_path,args.rtr_name))
f.save_as_json("%s/%s.tf.json"%(args.data_path,args.rtr_name))
