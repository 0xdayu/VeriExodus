from config_parser.openflow_table_parser import read_openflow_tables

toy_tables = set(["ext-rtr", "ext-nat", "ext-tr", "ext-acl"])
read_openflow_tables(toy_tables, "toy_example/exodus-dumpflows.txt")
