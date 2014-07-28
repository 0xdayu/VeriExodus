from cisco_translator import *
from openflow_translator import *
from headerspace.hs import *
from utils.wildcard import *
import sys

def printRules(rules):
    printRulesToFile(sys.stdout, rules)

def printTFToFile(afile, tf):
    for rule in tf.rules:
        printRuleToFile(afile, rule)

def printRulesToFile(afile, rules):
    for rule in rules:
        printRuleToFile(afile, rule)

def printRuleToFile(afile, rule):
    ''' TODO: -verbose options :-) '''

    '''
    afile.write("in_ports: %s, match: %s => ((h & %s) | %s, %s)" % \
        (rule['in_ports'], rule['match'], rule['mask'], \
         rule['rewrite'], rule['out_ports']))
    '''
    afile.write("in_ports: %s\n, match: %s\n, mask: %s\n, rewrite: %s\n, out_ports: %s\n" % \
        (rule['in_ports'], parseWildcard(rule["match"]), parseWildcard(rule['mask']), \
         parseWildcard(rule['rewrite']), rule['out_ports']))
    afile.write("\n")
    afile.write("--------------------\n")

    # debug
    if 'orig_rule_match' in rule.keys():
        r = rule['orig_rule_match']
        afile.write('---------Original Match -----------')
        afile.write(parseWildcard(r))
        afile.write('----------------------------')

    #for debugging
    '''if 'generated' in rule.keys():
        afile.write('---------Generated By-----------')
        r = rule['generated']
        afile.write("in_ports: %s\n, match: %s\n, mask: %s\n, rewrite: %s\n, out_ports: %s\n" % \
        (r['in_ports'], parseWildcard(r['match']), parseWildcard(r['mask']), \
         parseWildcard(r['rewrite']), r['out_ports']))
        afile.write('----------------------------')
    if 'shadowed' in rule.keys():
        afile.write('---------Shadowed By-----------')
        s = rule['shadowed']
        for r in s:
            afile.write("in_ports: %s\n, match: %s\n, mask: %s\n, rewrite: %s\n, out_ports: %s\n" % \
            (r['in_ports'], parseWildcard(r['match']), parseWildcard(r['mask']), \
             parseWildcard(r['rewrite']), r['out_ports']))
        afile.write('----------------------------')
    '''
    afile.write('********************************************************\n')




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
      "transport_dst", "transport_ctrl"]
    return wc_header_to_parsed_string(format, fields, w)
