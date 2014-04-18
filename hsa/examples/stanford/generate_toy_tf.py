from config_parser.openflow_table_parser import read_openflow_tables

def generate_transfer_funcions():
    pass

def generate_topology(pipeline, nSubnets, f_in_pt, f_out_pt, f_rtr_pt):
    def wireLinks(sa, f_port1, sb, f_port2):
        allLinks = []
        for subnetId in range(nSubnets):
            aOutPt = f_port1(subnetId + 1)
            bInPt = f_port2(subnetId + 1)
            allLinks.append((a, aOutPt, b, bInPt))
        return allLinks

    first_half = []
    assert len(pipeline) % 2 == 1
    for i in range(len(pipeline) / 2):
        a, b = pipeline[i], pipeline[i + 1]
        if b.endswith("rtr"):
            first_half += wireLinks(a, f_out_pt, b, f_rtr_pt)
        elif b.endswith("tr"):
            first_half += wireLinks(a, f_out_pt, b, f_in_pt)
        else:
            raise "Invalid pipeline argument"

    # mirror the first half of the topology
    secondHalf = []
    for (a, port1, b, port2) in first_half[::-1]:
        secondHalf.append((b, port2, a, port1));

    return first_half + secondHalf

toy_tables = set(["ext-rtr", "ext-nat", "ext-tr", "ext-acl"])
switches = read_openflow_tables(toy_tables, "toy_example/exodus-dumpflows.txt")
pipeline = ["ext-acl", "ext-tr", "ext-rtr", "ext-tr", "ext-acl"]
f_in_pt = lambda n : str(2 * n - 1)
f_out_pt = lambda n : str(2 * n)
f_rtr_pt = lambda n : str(n + 1)
num_of_subnets = 2;
generate_topology(pipeline, num_of_subnets, f_in_pt, f_out_pt, f_rtr_pt)