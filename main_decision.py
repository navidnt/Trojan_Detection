import re
from collections import defaultdict
from typing import List
from utils.exploit_gates1 import NetlistParser
import argparse
import random

from detection_codes.does_have_trojan0_1 import does_have_trojan0
from detection_codes.does_have_trojan4 import does_have_trojan4
from detection_codes.does_have_trojan5 import does_have_trojan5
from detection_codes.does_have_trojan2_1 import does_have_trojan2
from detection_codes.does_have_trojan1 import does_have_trojan1
from detection_codes.does_have_trojan7 import does_have_trojan7
from detection_codes.does_have_trojan6 import does_have_trojan6
from detection_codes.does_have_trojan3 import does_have_trojan3
from detection_codes.does_have_trojan9_1 import does_have_trojan9


def does_have_any_trojan(target_file) -> List:
    [trojan_gates, does_exist] = does_have_trojan0(target_file)
    if not does_exist:
        # print("Does not have trojan0 pattern")
        [trojan_gates, does_exist] = does_have_trojan1(target_file)
        if not does_exist:
            # print("Does not have trojan1 pattern either")
            [trojan_gates, does_exist] = does_have_trojan2(target_file)
            if not does_exist:
                # print("Does not have trojan2 pattern either")
                [trojan_gates, does_exist] = does_have_trojan4(target_file)
                if not does_exist:
                    # print("Does not have trojan4 pattern either")
                    [trojan_gates, does_exist] = does_have_trojan5(target_file)
                    if not does_exist:
                        # print("Does not have trojan5 pattern either")
                        [trojan_gates, does_exist] = does_have_trojan6(target_file)
                        if not does_exist:
                            # print("Does not have trojan6 pattern either")
                            [trojan_gates, does_exist] = does_have_trojan7(target_file)
                            if not does_exist:
                                # print("Does not have trojan7 pattern either")
                                [trojan_gates, does_exist] = does_have_trojan3(target_file)
                                if not does_exist:
                                    # print("Does not have trojan3 pattern either")
                                    [trojan_gates, does_exist] = does_have_trojan9(target_file)
                                #if not does_exist:
                                    # print("Does not have trojan9 pattern either")
    return [trojan_gates, does_exist]

def create_output_file(Trojaned, output_file_name, trojan_gates):
    # print (f"Creating output file at {output_file_name}")
    with open(output_file_name, 'w') as f:
        if Trojaned:
            f.write("TROJANED\n")
            f.write(f"TROJAN_GATES\n")
            for gate in trojan_gates:
                f.write(f"{gate}\n")
            f.write("END_TROJAN_GATES\n")
        else:
            f.write("NO_TROJAN\n")

def parse_args():
    parser = argparse.ArgumentParser(description="Hardware Trojan Detection")
    parser.add_argument("-netlist", type=str, required=True, help="Path to input netlist (.v) file")
    parser.add_argument("-output", type=str, required=True, help="Path to output result (.txt) file")
    return parser.parse_args()

def main():
    args = parse_args()
    target_netlist_path = args.netlist
    output_path = args.output
    # print (f"Target netlist path: {target_netlist_path}")
    [trojan_gates, does_exist] = does_have_any_trojan(target_netlist_path)
    create_output_file(does_exist, output_path, trojan_gates)

if __name__ == "__main__":
    main()
