#!/usr/bin/python

import argparse
import json
import os
import sys
import commands
from config_parser.transfer_function_to_openflow import OpenFlow_Rule_Generator
from config_parser.cisco_router_parser import cisco_router
from headerspace.tf import TF
from utils.wildcard_utils import set_header_field
from utils.wildcard import wildcard_create_bit_repeat
from utils.helper import dotted_subnet_to_int
from tabulate import tabulate

OUTPORT_CONST = cisco_router.OUTPUT_PORT_TYPE_CONST * cisco_router.PORT_TYPE_MULTIPLIER
INTER_CONST = cisco_router.INTERMEDIATE_PORT_TYPE_CONST * cisco_router.PORT_TYPE_MULTIPLIER

def get_fwd_port_id(a_port):
    return int(a_port / cisco_router.SWITCH_ID_MULTIPLIER) * cisco_router.SWITCH_ID_MULTIPLIER

def get_openflow_rule(tfs,inv_mapf,rule_id):
    ofg = OpenFlow_Rule_Generator(None,cisco_router.HS_FORMAT())
    tokens = rule_id.split("_")
    tf_name = ""
    for i in range(len(tokens)-1):
        tf_name += tokens[i] + "_"
    tf_name = tf_name[:-1]
    if tf_name == "":
        tf = tfs["topology"]
        rule = tf.id_to_rule[rule_id]
        rprint = (inv_mapf[rule["in_ports"][0]],inv_mapf[rule["out_ports"][0]])
        return rprint
    else:
        tf = tfs[tf_name]
        rule = tf.rules[int(tokens[-1])-1]
        of_rule = ofg.parse_rule(rule)
        (match,rw) = ofg.pretify(of_rule)
        return "%s %s"%(match,rw)

def parse_single_h(header):
    hs_format = cisco_router.HS_FORMAT()
    header = header.strip("() ").split(",")
    hs_bytes = [b.strip("D") for b in reversed(header)]
    FEC_string = ""
    if "vlan_pos" in hs_format.keys() and hs_bytes[hs_format["vlan_pos"]] != "X":
        v = int(hs_bytes[hs_format["vlan_pos"]]) + \
            int(hs_bytes[hs_format["vlan_pos"] + 1]) * 256
        FEC_string = "VLAN:%d "%v
    if "ip_dst_pos" in hs_format.keys():
        ip_address = ""
        subnet = 32
        for i in range(4):
            if 'x' in hs_bytes[hs_format["ip_dst_pos"]+i]:
                oct = hs_bytes[hs_format["ip_dst_pos"] + i]
                subnet -= oct.count("x")
                oct = oct.replace("x","0")
                ip_address = "%d.%s"%(int(oct,2),ip_address)
            elif hs_bytes[hs_format["ip_dst_pos"]+i] == 'X':
                ip_address = "0.%s"%ip_address
                subnet -= 8
            else:
                ip_address = "%s.%s"%(hs_bytes[hs_format["ip_dst_pos"]+i],ip_address)
        FEC_string = FEC_string + "DST-IP:%s/%d "%(ip_address[:-1],subnet)
    return FEC_string

def parse_hs_string(h_string):
    minplus = h_string.split("-")
    if len(minplus) == 1:
        return parse_single_h(minplus[0])
    else:
        s = "(" + parse_single_h(minplus[0]) + ") - ("
        mins = minplus[1].split("+")
        for m in mins:
            s += parse_single_h(m) + "& "
        return s[:-2] + ")"

def make_header(h_desc):
    all_x = wildcard_create_bit_repeat(cisco_router.HS_FORMAT()["length"],0x3)
    parts = h_desc.split(",")
    fields = ["vlan", "ip_src", "ip_dst", "ip_proto", "transport_src", "transport_dst"]
    for part in parts:
        tmp = part.split("=")
        field = tmp[0]
        value = tmp[1]
        if field in ["ip_src","ip_dst"]:
            (ip,sub) = dotted_subnet_to_int(value)
            set_header_field(cisco_router.HS_FORMAT(), all_x, field, ip, 32-sub)
        else:
            set_header_field(cisco_router.HS_FORMAT(), all_x, field, int(value), 0)
    return all_x

parser = argparse.ArgumentParser(description='Computes reachability using Hassel-C')
parser.add_argument('network',
                   help='The network to run reachability on.')
parser.add_argument('-s','--source', nargs=2, metavar=("source-rtr","source-port"), required=True,
                   help='The name of the source router and port.')
parser.add_argument('-d','--destination', nargs=2, metavar=("dest-rtr","dest-port"),
                   help='The name of the destination router and port.')
parser.add_argument("--loop", action="store_true",
                    help="Find loops originated from source.")
parser.add_argument("-ih", "--in_header",
                    help="Header to be injected from source. Header value should be a comma-\
                     separated list of field=value: e.g., vlan=3,ip_src=10.0.1.0/24. Field \
                     can be vlan, ip_src, ip_dst, ip_proto, transport_src, trnsport_dst.")
parser.add_argument("-hc", "--hop_count", type=int,
                    help="Only show results that go through hop_count hops.")
parser.add_argument("-m", "--map_file", default="port_map.json",
                    help="Port map file name.")
parser.add_argument("-p", "--data_path", default=".",
                    help="Path to where the json transfer function files are stored")
parser.add_argument("-e", "--exe_path", default=".",
                    help="Path to the exe file.")
parser.add_argument("-o", "--one_hop", help="Computes reachability within one hop. If this flag is\
                    used, dest_rtr should be the same as source_rtr and dest_port should be an internal port on that router\
                    such as output of the forwarding engine (use ^ before port name, e.g., ^te1/1) or the input to the \
                    forwarding engine (use ^).",action="store_true")
parser.add_argument("-v", "--verbose", help="Include details such as port name and rules\
                    being applied at each stage.",action="store_true")
args = parser.parse_args()

f = open("%s/%s"%(args.data_path,args.map_file),'r')
mapf = json.load(f)
inv_mapf = {}
for rtr in mapf:
    for port in mapf[rtr]:
        inv_mapf[int(mapf[rtr][port])] = "%s-%s"%(rtr,port)
        inv_mapf[int(mapf[rtr][port])+OUTPORT_CONST] = "%s-%s"%(rtr,port)
        inv_mapf[int(mapf[rtr][port])+INTER_CONST] = "^%s-%s"%(rtr,port)
    fwd_id = get_fwd_port_id(int(mapf[rtr][port]))
    inv_mapf[fwd_id] = "FWD-ENGINE"

tfs = {}
files_in_dir = os.listdir(args.data_path)
for file_in_dir in files_in_dir:
    if file_in_dir.endswith(".tf.json"):
        tf = TF(1)
        tf.load_from_json("%s/%s"%(args.data_path,file_in_dir))
        tfs[file_in_dir[0:-8]] = tf

command = args.exe_path + "/" + args.network

if (args.loop):
    command = command + " -loop"

if (args.in_header):
    header = make_header(args.in_header)
    command = command + " -h " + header.__str__(0)

src_id = mapf[args.source[0]][args.source[1]]
if (args.one_hop):
    if not args.destination:
        sys.exit("Error: you need to specify a destination using -d argument.")
    command = command + " -o"
    if args.destination[1] == "^":
        dst_id = get_fwd_port_id(mapf[args.destination[0]].values()[0])
    elif args.destination[1].startswith("^"):
        dst_id = mapf[args.destination[0]][args.destination[1][1:]] + INTER_CONST
    else:
        dst_id = mapf[args.destination[0]][args.destination[1]] + OUTPORT_CONST
elif args.destination:
    dst_id = mapf[args.destination[0]][args.destination[1]] + OUTPORT_CONST
else:
    dst_id = ""

if (args.hop_count):
    command = command + " -c " + str(args.hop_count)

command = command + " " + str(src_id) + " " + str(dst_id)

(stat,res) = commands.getstatusoutput(command)
print command
lines = res.split("\n")
str_rules_table = []
final_hs = ""
count = 0
for line in lines:
    line = line.strip()
    if args.verbose and line.startswith("->"):
        p1 = line.find("Port:")
        p2 = line.find("Rules:")
        if p1 != -1:
            if p2 == -1:
                port = inv_mapf[int(line[p1+5:].strip())]
                str_rules_table.append([port])
            else:
                port = inv_mapf[int(line[p1+5:p2].strip(", "))]
                rules = line[p2+6:].split(",")
                for rule in rules:
                    rule = rule.strip()
                    of_rule = get_openflow_rule(tfs,inv_mapf,rule)
                    if of_rule.__class__ == str:
                        str_rules_table[-1].append(of_rule)
                    else:
                        str_rules_table[-1].append(of_rule[0])
                str_rules_table.append([port])
    elif args.verbose:
        if line.startswith("--"):
            last_port = str_rules_table.pop()[0]
            str_rules_table[-1].append(last_port)
            final_table = []
            for l in str_rules_table:
                final_table.append([l[0],l[1],l[-1]])
                for i in range(2,len(l)-1):
                    final_table.append(["",l[i],""])
                final_table.append(["","",""])
            count += 1
            print "**FEC ",count,"**"
            print final_hs
            print tabulate(final_table,["In-Port","Match and Action","Out-Port"],tablefmt="orgtbl")
            print "\n"
            str_rules_table = []
            final_hs = ""
        elif line.startswith("HS"):
            parse_hs_string(line[4:])
            final_hs = parse_hs_string(line)
        elif line.startswith("Time"):
            tp = line.split()
            print "Run Time:", int(tp[1])/1000,"ms"
    else:
        print line
if args.verbose:
    print "Count",count
