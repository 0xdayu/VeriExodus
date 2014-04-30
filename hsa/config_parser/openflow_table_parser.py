from utils.helper import is_mac_address, is_ip_address, is_ip_subnet
from headerspace.tf import *


def get_ethertype_number(proto_name):
  dict = {"ip": 0x0800, "arp": 0x0806, "ipv6": 0x86dd}
  if proto_name in dict.keys():
    return dict[proto_name]
  else:
    try:
      num = int(proto_name)
      return num
    except Exception as e:
      return None

def get_protocol_number(proto_name):
  dict = {"ah":51, "eigrp":88, "esp":50, "gre":47, "icmp":1, "igmp":2, \
      "igrp":9, "ipinip":94, "nos":4, "ospf":89, "tcp":6, \
      "udp":17}
  if proto_name in dict.keys():
    return dict[proto_name]
  else:
    try:
      num = int(proto_name)
      return num
    except Exception as e:
      return None

class OpenFlowSwitch(object):
    PATTERN_PRIORITY = "priority"
    PATTERN_ACTION = "actions"
    
    class MatchRule(object):
        FIELD_IN_PORT = "in_port"
        FIELD_DL_SRC = "dl_src"
        FIELD_DL_DST = "dl_dst"
        FIELD_NW_SRC = "nw_src"
        FIELD_NW_DST = "nw_dst"
        FIELD_TP_DST = "tp_dst"

        def __init__(self, priority, ethertype, protocol, in_port, dl_src, dl_dst, nw_src, nw_dst, tp_dst):
            assert isinstance(priority, int)

            assert ethertype is None or (ethertype >= 0 and ethertype < 65535)
            assert protocol is None or (protocol >= 0 and protocol < 256)
            assert dl_src is None or  is_mac_address(dl_src)
            assert dl_dst is None or is_mac_address(dl_dst)
            assert nw_src is None or is_ip_address(nw_src) or is_ip_subnet(nw_src)
            assert nw_dst is None or is_ip_address(nw_dst) or is_ip_subnet(nw_dst)
            assert in_port is None or isinstance(in_port, str)
            assert tp_dst is None or (isinstance(tp_dst, int) and tp_dst >= 0 and tp_dst < 65536)

            self.priority = priority
            self.ethertype = ethertype
            self.protocol = protocol
            self.dl_src, self.dl_dst = dl_src, dl_dst
            self.nw_src, self.nw_dst = nw_src, nw_dst
            self.in_port = in_port
            self.tp_dst = tp_dst
            self.act_list = []

        def addActions(self, actions):
            self.act_list += actions

    class Action(object):
        ACTION_MOD_DL_SRC = "mod_dl_src"
        ACTION_MOD_DL_DST = "mod_dl_dst"
        ACTION_MOD_NW_SRC = "mod_nw_src"
        ACTION_MOD_NW_DST = "mod_nw_dst"
        ACTION_FORWARD = "output"
        ACTION_ALL = "ALL"
        ACTION_DROP = "drop"
        ACTION_TO_CTRL = "CONTROLLER"
    
    class ActionModification(Action):
        def __init__(self, act_enum, new_value):
            assert act_enum == self.ACTION_MOD_DL_DST or self.ACTION_MOD_DL_SRC or \
                    act_enum == self.ACTION_MOD_NW_DST or act_enum == self.ACTION_MOD_NW_SRC
            self.act_enum = act_enum

            if act_enum == self.ACTION_MOD_NW_DST or act_enum == self.ACTION_MOD_NW_SRC:
                assert is_ip_address(new_value) or is_ip_subnet(new_value)
            elif act_enum == self.ACTION_MOD_DL_DST or act_enum == self.ACTION_MOD_DL_SRC:
                assert is_mac_address(new_value)
            else:
                raise ValueError("Unusual modification")

            self.new_value = new_value

    class ActionDrop(Action):
        def __init__(self, act_enum):
            assert act_enum == self.ACTION_DROP
            self.act_enum = act_enum

    class ActionDataLinkFlood(Action):
        def __init__(self, act_enum):
            assert act_enum == self.ACTION_ALL
            self.act_enum = act_enum

    class ActionForward(Action):
        def __init__(self, act_enum, out_port):
            assert act_enum == self.ACTION_FORWARD
            self.act_enum = act_enum
            assert isinstance(out_port, str)
            self.out_port = out_port

    class ActionToController(Action):
        def __init__(self, act_enum, ctrl_out_port):
            assert act_enum == self.ACTION_TO_CTRL
            self.act_enum = act_enum
            assert isinstance(ctrl_out_port, str)
            self.ctrl_out_port = ctrl_out_port

    def __init__(self, switch_id):
        self.switch_id = switch_id
        self.table_rows = []

def read_openflow_tables(targets, file_path):
    def parse_actions(entry):
        act_list = []

        enum_act_to_ctrl = OpenFlowSwitch.Action.ACTION_TO_CTRL
        enum_act_drop = OpenFlowSwitch.Action.ACTION_DROP
        enum_act_mod_dl_src = OpenFlowSwitch.Action.ACTION_MOD_DL_SRC
        enum_act_mod_dl_dst = OpenFlowSwitch.Action.ACTION_MOD_DL_DST
        enum_act_mod_nw_src = OpenFlowSwitch.Action.ACTION_MOD_NW_SRC
        enum_act_mod_nw_dst = OpenFlowSwitch.Action.ACTION_MOD_NW_DST
        enum_act_flood = OpenFlowSwitch.Action.ACTION_ALL
        enum_act_forward = OpenFlowSwitch.Action.ACTION_FORWARD
        
        for txt_action in entry.split(','):
            if txt_action.startswith(enum_act_to_ctrl):
                ctrl_port = txt_action[len(enum_act_to_ctrl) + len(':') :]
                act_list += [OpenFlowSwitch.ActionToController(enum_act_to_ctrl, ctrl_port)]
            elif txt_action.startswith(enum_act_drop):
                act_list += [OpenFlowSwitch.ActionDrop(enum_act_drop)]
            elif txt_action.startswith(enum_act_mod_dl_dst):
                new_val = txt_action[len(enum_act_mod_dl_dst) + len(':') :]
                act_list += [OpenFlowSwitch.ActionModification(enum_act_mod_dl_dst, new_val)]
            elif txt_action.startswith(enum_act_mod_dl_src):
                new_val = txt_action[len(enum_act_mod_dl_src) + len(':') :]
                act_list += [OpenFlowSwitch.ActionModification(enum_act_mod_dl_src, new_val)]
            elif txt_action.startswith(enum_act_mod_nw_dst):
                new_val = txt_action[len(enum_act_mod_nw_dst) + len(':') :]
                act_list += [OpenFlowSwitch.ActionModification(enum_act_mod_nw_dst, new_val)]
            elif txt_action.startswith(enum_act_mod_nw_src):
                new_val = txt_action[len(enum_act_mod_nw_src) + len(':') :]
                act_list += [OpenFlowSwitch.ActionModification(enum_act_mod_nw_src, new_val)]
            elif txt_action.startswith(enum_act_flood):
                act_list += [OpenFlowSwitch.ActionDataLinkFlood(enum_act_flood)]
            elif txt_action.startswith(enum_act_forward):
                out_port = txt_action[len(enum_act_forward) + len(':') :]
                act_list += [OpenFlowSwitch.ActionForward(enum_act_forward, out_port)]

        return act_list

    def parse_match_rule(entry):
        fields = entry.split(',')
        priority = int(fields[0])
        ethertype, protocol, in_port, dl_src, dl_dst, nw_src, nw_dst, tp_dst = None, None, None, None, None, None, None, None

        enum_mch_in_port = OpenFlowSwitch.MatchRule.FIELD_IN_PORT
        enum_mch_dl_src = OpenFlowSwitch.MatchRule.FIELD_DL_SRC
        enum_mch_dl_dst = OpenFlowSwitch.MatchRule.FIELD_DL_DST
        enum_mch_nw_src = OpenFlowSwitch.MatchRule.FIELD_NW_SRC
        enum_mch_nw_dst = OpenFlowSwitch.MatchRule.FIELD_NW_DST
        enum_mch_tp_dst = OpenFlowSwitch.MatchRule.FIELD_TP_DST

        for txt_field in fields[1 :]:
            testEthertype = get_ethertype_number(txt_field)
            testProt = get_protocol_number(txt_field)

            if testEthertype is not None:
                ethertype = testEthertype
            elif testProt is not None:
                ethertype = 0x0800
                protocol = testProt
            elif txt_field.startswith(enum_mch_dl_src):
                dl_src = txt_field[len(enum_mch_dl_src) + len(':') :]
            elif txt_field.startswith(enum_mch_dl_dst):
                dl_dst = txt_field[len(enum_mch_dl_dst) + len(':') :]
            elif txt_field.startswith(enum_mch_nw_src):
                nw_src = txt_field[len(enum_mch_nw_src) + len(':') :]
            elif txt_field.startswith(enum_mch_nw_dst):
                nw_dst = txt_field[len(enum_mch_nw_dst) + len(':') :]
            elif txt_field.startswith(enum_mch_in_port):
                in_port = txt_field[len(enum_mch_in_port) + len(':') :]
            elif txt_field.startswith(enum_mch_tp_dst):
                tp_dst = int(txt_field[len(enum_mch_tp_dst) + len(':') :])
            else:
                raise ValueError("Match field not considered: %s" % txt_field)

        return OpenFlowSwitch.MatchRule(priority, ethertype, protocol, in_port, dl_src, dl_dst, nw_src, nw_dst, tp_dst)
        
    print "=== Reading OpenFlow Router table ==="
    f = open(file_path, 'r')
    firstline = f.readline()
    assert firstline.startswith("mininet")

    # read in every line from the plain text file for targeted tables
    sec_name = "UNDEFINED"
    txt_sections = {}
    needed = False
    for line in f:
        if line.startswith("***"):
            sec_name = line.split()[1]
            if sec_name not in targets:
                needed = False
            else:
                txt_sections[sec_name] = []
                needed = True
        elif needed:
            txt_sections[sec_name] += [line]

    # construct open-flow table dictionary
    h_switches = {}
    for rtr_name in txt_sections.keys():
        print "--- Parsing table %s" % rtr_name
        of_router = OpenFlowSwitch(rtr_name)

        for line in txt_sections[rtr_name]:
            match_rule = None
            for entry in line.split():
                if entry.startswith(OpenFlowSwitch.PATTERN_ACTION):
                    assert match_rule is not None
                    match_rule.addActions(parse_actions(entry[len(OpenFlowSwitch.PATTERN_ACTION) + len('=') :]))
                elif entry.startswith(OpenFlowSwitch.PATTERN_PRIORITY):
                    match_rule = parse_match_rule(entry[len(OpenFlowSwitch.PATTERN_PRIORITY) + len('=') :])
            of_router.table_rows += [match_rule]

        h_switches[rtr_name] = of_router

    return h_switches


