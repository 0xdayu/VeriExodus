from config_parser.openflow_table_parser import read_openflow_tables, OpenFlowSwitch
from utils.helper import *

class RuleTreeNode:
    def __init__(self, sw_id, rule, is_forest_handle=False):
        self.children = []
        self.rule = rule
        self.sw_id = sw_id
        self.is_forest_handle = is_forest_handle

def generate_transfer_funcions(forest_handle):
    def backtrack(node, h_parents):
        actionSequence = []
        while node is not forest_handle:
            actionSequence = node.rule.act_list + actionSequence
            node = h_parents[node]
        return actionSequence

    def generate(action_sequence):
        pass

    allTfs = []
    q = forest_handle.children[:]
    hParents = {}
    for root in forest_handle.children:
        hParents[root] = forest_handle

    while q:
        c = q.pop(0)
        if not c.children:
            allTfs += generate(backtrack(c, hParents))
        else:
            for child in c.children:
                hParents[child] = c
                q.add(child)

    return allTfs

def topology_to_dict(topology):
    result = {}
    for (sa, port1, sb, port2) in topology:
        result[(sa, port1)] = (sb, port2)
    return result

def generate_rule_trees(pipeline, topology, h_switches):
    """ A depth-first-search routine that eliminate paths that are incomplete as specified by
        the expected path depth (tree height). Also note that if the corresponding action is to
        drop the packet, this won't be a complete path.
    """
    def preclude_incomplete_paths(forest, height):
        def explore(c, depth):
            if depth == height:
                return True
            elif not c.children:
                return False

            isComplete = False
            newChildren = []
            for nxt in c.children:
                actions = nxt.rule.act_list
                if isinstance(actions[len(actions) - 1], OpenFlowSwitch.ActionDrop):
                    continue

                if explore(nxt, depth + 1):
                    isComplete = True
                    newChildren.append(nxt)

            c.children = newChildren
            return isComplete

        newRoots = []
        for root in forest.children:
            if explore(root, 1):
                newRoots.append(root)

        forest.children = newRoots

    """ To check whether there is a possible matching from rule in switch A's table to
        another rule in switch B's table. Note that we only need to care about forwarding
        actions in switch A's rule.
    """
    def match_rules(sw_id_a, fwd_actions, sw_id_b, nxt_rule, h_topo):
        for act in fwd_actions:
            out_pt = act.out_port
            in_pt = nxt_rule.in_port
            if (sw_id_a, out_pt) not in h_topo:
                continue
            elif not in_pt or ((sw_id_b, str(in_pt)) == h_topo[(sw_id_a, out_pt)]):
                return True
        return False

    q = []
    hTopo = topology_to_dict(topology)
    forestHandle = RuleTreeNode(None, None, True)

    # generate a list of rule roots given the ingress switch table
    for rule in h_switches[pipeline[0]].table_rows:
        root = RuleTreeNode(pipeline[0], rule)
        q.append(root)
        forestHandle.children.append(root)

    # a breadth-first-search routine that enumerate all possible rule paths
    level = 0
    while nextLevel and level < len(pipeline) - 1:
        currLevel, nextLevel = nextLevel, []
        level += 1
        nxtSwitchId = pipeline[level]

        while currLevel:
            node = currLevel.pop(0)
            nxtTable = h_switches[nxtSwitchId]
            fwdActions = filter(lambda rule: isinstance(rule, OpenFlowSwitch.ActionForward), node.rule.act_list)
            for nxtRule in nxtTable.table_rows:
                if match_rules(node.sw_id, fwdActions, nxtSwitchId, nxtRule, hTopo):
                    newRule = RuleTreeNode(nxtSwitchId, nxtRule)
                    node.children.append(newRule)
                    nextLevel.append(newRule)

        preclude_incomplete_paths(forestHandle, level + 1)

    return forestHandle

def generate_topology(pipeline, nSubnets, f_in_pt, f_out_pt, f_rtr_pt):
    def wireLinks(sa, f_port1, sb, f_port2):
        allLinks = []
        for subnetId in range(nSubnets):
            aOutPt = f_port1(subnetId + 1)
            bInPt = f_port2(subnetId + 1)
            allLinks.append((a, aOutPt, b, bInPt))
        return allLinks

    firstHalf = []
    assert len(pipeline) % 2 == 1
    for i in range(len(pipeline) / 2):
        a, b = pipeline[i], pipeline[i + 1]
        if b.endswith("rtr"):
            firstHalf += wireLinks(a, f_out_pt, b, f_rtr_pt)
        elif b.endswith("tr"):
            firstHalf += wireLinks(a, f_out_pt, b, f_in_pt)
        else:
            raise "Invalid pipeline argument"

    # mirror the first half of the topology
    secondHalf = []
    for (a, port1, b, port2) in firstHalf[::-1]:
        secondHalf.append((b, port2, a, port1));

    return firstHalf + secondHalf

toy_tables = set(["ext-rtr", "ext-nat", "ext-tr", "ext-acl"])
h_switches = read_openflow_tables(toy_tables, "toy_example/exodus-dumpflows.txt")
pipeline = ["ext-acl", "ext-tr", "ext-rtr", "ext-tr", "ext-acl"]
f_in_pt = lambda n : str(2 * n - 1)
f_out_pt = lambda n : str(2 * n)
f_rtr_pt = lambda n : str(n + 1)
num_of_subnets = 2
"""
topology = generate_topology(pipeline, num_of_subnets, f_in_pt, f_out_pt, f_rtr_pt)
forest = generate_rule_trees(pipeline, topology, h_switches)
"""

HEADER_LENGTH = 16
formatt = {}
formatt["vlan_pos"] = 0
formatt["ip_src_pos"] = 2
formatt["ip_dst_pos"] = 6
formatt["ip_proto_pos"] = 10
formatt["transport_src_pos"] = 11
formatt["transport_dst_pos"] = 13
formatt["transport_ctrl_pos"] = 15
formatt["vlan_len"] = 2
formatt["ip_src_len"] = 4
formatt["ip_dst_len"] = 4
formatt["ip_proto_len"] = 1
formatt["transport_src_len"] = 2
formatt["transport_dst_len"] = 2
formatt["transport_ctrl_len"] = 1
formatt["length"] = 16


# TODO: convert h_switches to tfs
for switch in h_switches:
    tf = TF(HEADER_LENGTH)
    
    # TODO: convert match rules
    for rule in self.table_rows:
        outports = list()
        match   = wildcard_create_bit_repeat(HEADER_LENGTH, 0x3)
        mask    = wildcard_create_bit_repeat(HEADER_LENGTH, 0x2)
        rewrite = wildcard_create_bit_repeat(HEADER_LENGTH, 0x1)
        
        # create "match" by piecing together requirements
        fields = ["in_port", "dl_src", "dl_dst", "nw_src", "nw_dst", "tp_dst"]
        for f in fields:
            fieldName = fields[f]
            val = getattr(rule, fieldName)
            if val is not None:
                # this field has non-wildcard bits
                set_header_field(formatt, match, fieldName, val, 0)
            
        for action in rule.act_list:
            # get out-ports
            if (action.act_enum == Action.ACTION_FORWARD):
                outports.append(action.out_port)

            # get mask/rewrite
            if (action.act_name == Action.ACTION_MOD_DL_SRC):
                # 4th parameter is int
                set_header_field(formatt, mask, "ip_src", 0, 0)
                set_header_field(formatt, rewrite, "ip_src", dotted_ip_to_int(action.ip_src), 0)
            if (action.act_name == Action.ACTION_MOD_DL_DST):
                set_header_field(formatt, mask, "ip_dst", 0, 0)
                set_header_field(formatt, rewrite, "ip_dst", dotted_ip_to_int(action.ip_dst), 0)

        # list of ints and 3 wildcards
        inports  = rule.in_ports
        match    = rule.match
        mask     = rule.mask
        rewrite  = rule.rewrite
        
        converted_rule = TF.create_custom_rule(inports, match, outports, mask, rewrite)
        tf.add_custom_rule(converted_rule)
        
# TODO: merged based on pipeline


