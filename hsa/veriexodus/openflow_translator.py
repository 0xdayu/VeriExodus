from config_parser.openflow_table_parser import read_openflow_tables, OpenFlowSwitch
from utils.helper import *
from utils.wildcard import *
from utils.wildcard_utils import *

DUMP_FILE = '../examples/Exodus_toy_example/ext-sat.txt'
#transfer all Openflow Rules into transfer fucntions
def convert_switches_to_tfs(h_switches, formatt):
    switch_tfs = {}

    # convert h_switches to tfs
    for switch_name in h_switches:
        switch = h_switches[switch_name]
        tf = TF(formatt["length"])
        
        # convert match rules
        for rule in switch.table_rows:
            outports = list()
            match   = wildcard_create_bit_repeat(formatt["length"], 0x3)
            mask    = wildcard_create_bit_repeat(formatt["length"], 0x2)
            rewrite = wildcard_create_bit_repeat(formatt["length"], 0x1)
            action_all = False
            
            # create "match" by piecing together requirements
            # "dl_src", "dl_dst",
            # left side is OF's name,  right side is HSA's name
            fields = {                          \
                "dl_src": "dl_src",             \
                "dl_dst": "dl_dst",             \
                "ethertype": "dl_proto",        \
                "nw_src": "ip_src",             \
                "nw_dst": "ip_dst",             \
                "tp_dst": "transport_dst",      \
                "protocol": "ip_proto"          \
            }

            # parse field names into "match"
            for pktFieldName, hsaFieldName in fields.iteritems():
                val = getattr(rule, pktFieldName)
                if val is not None:
                    # this field has non-wildcard bits
                    if (isinstance(val, str) and is_ip_subnet(val)):
                        [intIp, intSubnet] = dotted_subnet_to_int(val)
                        set_header_field(formatt, match, hsaFieldName, intIp, 32 - intSubnet)
                    elif (isinstance(val, str) and is_ip_address(val)):
                        intIp = dotted_ip_to_int(val)
                        set_header_field(formatt, match, hsaFieldName, intIp, 0)
                    elif (isinstance(val, str) and is_mac_address(val)):
                        intMac = mac_to_int(val)
                        set_header_field(formatt, match, hsaFieldName, intMac, 0)
                    else:
                        # port or protocol
                        set_header_field(formatt, match, hsaFieldName, val, 0)
            
            # parse actions into mask/rewrite/outport
            for action in rule.act_list:
                # get out-ports
                if action.act_enum == OpenFlowSwitch.Action.ACTION_FORWARD:
                    outports.append(int(action.out_port))

                if action.act_enum == OpenFlowSwitch.Action.ACTION_MOD_DL_SRC:
                    new_mask = wildcard_create_bit_repeat(formatt["dl_src_len"], 0x01)
                    set_wildcard_field(formatt, mask, "dl_src", new_mask, 0)
                    set_header_field(formatt, rewrite, "dl_src", mac_to_int(action.new_value), 0)
                if action.act_enum == OpenFlowSwitch.Action.ACTION_MOD_DL_DST:
                    new_mask = wildcard_create_bit_repeat(formatt["dl_dst_len"], 0x01)
                    set_wildcard_field(formatt, mask, "dl_dst", new_mask, 0)
                    set_header_field(formatt, rewrite, "dl_dst", mac_to_int(action.new_value), 0)
                    
                if action.act_enum == OpenFlowSwitch.Action.ACTION_MOD_NW_SRC:
                    new_mask = wildcard_create_bit_repeat(formatt["ip_src_len"], 0x01)
                    if is_ip_subnet(action.new_value):
                        intSubnet, intMask = dotted_subnet_to_int(action.new_value)
                        set_wildcard_field(formatt, mask, "ip_src", new_mask, 32 - intMask)
                        set_header_field(formatt, rewrite, "ip_src", intSubnet, 32 - intMask)
                    else:
                        set_header_field(formatt, rewrite, "ip_src", dotted_ip_to_int(action.new_value), 0)
                        set_wildcard_field(formatt, mask, "ip_src", new_mask, 0)

                if action.act_enum == OpenFlowSwitch.Action.ACTION_MOD_NW_DST:
                    new_mask = wildcard_create_bit_repeat(formatt["ip_dst_len"], 0x01)
                    if is_ip_subnet(action.new_value):
                        intSubnet, intMask = dotted_subnet_to_int(action.new_value)
                        set_wildcard_field(formatt, mask, "ip_dst", new_mask, 32 - intMask)
                        set_header_field(formatt, rewrite, "ip_dst", intSubnet, 32 - intMask)
                    else:
                        set_header_field(formatt, rewrite, "ip_dst", dotted_ip_to_int(action.new_value), 0)
                        set_wildcard_field(formatt, mask, "ip_dst", new_mask, 0)

                
                if action.act_enum == OpenFlowSwitch.Action.ACTION_ALL:
                    action_all = True

                # sending to controller
                if action.act_enum == OpenFlowSwitch.Action.ACTION_TO_CTRL:
                    outports.append(65535)

            if (rule.in_port is None):
                inports = []
            else:
                inports = [int(rule.in_port)]

            converted_rule = TF.create_standard_rule(inports, match, outports, mask, rewrite)
            converted_rule["action_all"] = action_all
            tf.add_rewrite_rule(converted_rule)
        
        # complete tf:
        switch_tfs[switch_name] = tf

    return switch_tfs
    
def merge_tfs(tfs, pipeline, pipeline_ports):
    # merge based on pipeline
    merged_tf = tfs[pipeline[0]]
    for i in range(1, len(pipeline)):
        switch = tfs[pipeline[i]]
        merged_tf = TF.merge_tfs(merged_tf, switch, pipeline_ports[i - 1])

        f = open("results/of_merge_" + str(i), 'w')
        f.write(str(merged_tf))
        f.close()

    return merged_tf


def generate_ext():
    toy_tables = set(["ext-rtr", "ext-nat", "ext-tr", "ext-acl"])
    
    #filter impossible inports and outports
    f_in_pt = lambda n : str(2 * n - 1)
    f_out_pt = lambda n : str(2 * n)
    f_rtr_pt = lambda n : str(n + 1)

    #port mapping
    pmap_fwd = lambda n : n - 1
    pmap_rtr = lambda n : n / 2 + 1
    pmap_outrtr = lambda n : (n - 1) * 2
    pmap_bck = lambda n : n + 1
    pipeline = ["ext-acl", "ext-tr", "ext-rtr", "ext-tr", "ext-acl"]
    pipeline_ports = [pmap_fwd, pmap_rtr, pmap_outrtr, pmap_bck]

    num_of_subnets = 2
    h_switches = read_openflow_tables(toy_tables, DUMP_FILE)
    """
    topology = generate_topology(pipeline, num_of_subnets, f_in_pt, f_out_pt, f_rtr_pt)
    forest = generate_rule_trees(pipeline, topology, h_switches)
    """

    formatt = {}
    formatt["vlan_pos"] = 0
    formatt["ip_src_pos"] = 2
    formatt["ip_dst_pos"] = 6
    formatt["ip_proto_pos"] = 10
    formatt["transport_src_pos"] = 11
    formatt["transport_dst_pos"] = 13
    formatt["transport_ctrl_pos"] = 15
    formatt["dl_src_pos"] = 16
    formatt["dl_dst_pos"] = 22
    formatt["dl_proto_pos"] = 28

    formatt["vlan_len"] = 2
    formatt["ip_src_len"] = 4
    formatt["ip_dst_len"] = 4
    formatt["ip_proto_len"] = 1
    formatt["transport_src_len"] = 2
    formatt["transport_dst_len"] = 2
    formatt["transport_ctrl_len"] = 1
    formatt["dl_src_len"] = 6
    formatt["dl_dst_len"] = 6
    formatt["dl_proto_len"] = 2
    formatt["length"] = 30

    switch_tfs = dict()

    switch_tfs = convert_switches_to_tfs(h_switches, formatt)

    # output HSA tf results:
    tfile = open("results/switch_tfs", "w")
    for rtrname in switch_tfs:
        tfile.write("==============" + rtrname + "==============\n")
        tfile.write(str(switch_tfs[rtrname]))
        tfile.write("\n");
    tfile.close()

    merged_tf = merge_tfs(switch_tfs, pipeline, pipeline_ports)
    f = open('results/of_tf_result', 'w')
    f.write(str(merged_tf))
    f.close()
    
    return merged_tf

if __name__ == "__main__":
    generate_ext()


