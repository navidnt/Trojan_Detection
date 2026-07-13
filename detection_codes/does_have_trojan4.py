import re
from collections import defaultdict
from typing import List
from utils.exploit_gates1 import NetlistParser

def does_have_trojan4(target_file: str) -> List:
    trojan_gates = []
    parser = NetlistParser()
    parser.parse_netlist(target_file)
    visited_for_xor = []
    visited_for_dff = []

    def is_this_xor_part_of_an_LFSR(gate_name: str, start_gate_name: str, parser: NetlistParser) -> bool:
        gate = parser.get_gate(gate_name)
        for child in gate.outputs:
            if child.name in visited_for_xor:
                continue
            visited_for_xor.append(child)
            if child.name == start_gate_name:
                return True
            if child.gate_type == 'xor' or child.gate_type == 'xnor':
                if is_this_xor_part_of_an_LFSR(child.name, start_gate_name, parser):
                    return True
        return False
    
    def is_this_dff_start_of_an_LFSR(gate_name: str, start_gate_name: str, parser: NetlistParser) -> bool:
        gate = parser.get_gate(gate_name)
        for child in gate.outputs:
            if child.name in visited_for_dff or child.name in visited_for_xor:
                continue
            #child_gate = parser.get_gate(child)
            #print(f'Now on gate: {gate_name}, its child is {child.name}')
            if child is None:
                continue
            if child.gate_type == 'xor' or child.gate_type == 'xnor':
                visited_for_xor.append(child.name)
                if is_this_xor_part_of_an_LFSR(child.name, start_gate_name, parser):
                    return True
            elif child.gate_type == 'dff':
                visited_for_dff.append(child.name)
                if is_this_dff_start_of_an_LFSR(child.name, start_gate_name, parser):
                    return True
        return False
    
    visited_for_dff = []
    visited_for_xor = []
    trojan_gates = []
    start_of_LFSR = None
    set_or_reset_net = None

    for gate_name in parser.gates:
        if parser.get_gate(gate_name).gate_type == 'dff':
            if is_this_dff_start_of_an_LFSR(gate_name, gate_name, parser):
                start_of_LFSR = parser.get_gate(gate_name)
                visited_for_dff = []
                visited_for_xor = []
                # print(f'Found start of LFSR: {start_of_LFSR.name}')
                break
            visited_for_dff = []
            visited_for_xor = []
    
    if (start_of_LFSR == None):
        return [[], False]
    #     print ("No LFSR Found!")

    else:
        # print(start_of_LFSR.inputs[0])
        set_or_reset_net = start_of_LFSR.inputs[0]
        if set_or_reset_net == '1\'b1':
            set_or_reset_net = start_of_LFSR.inputs[1]
        # print (f'set or reset net: {set_or_reset_net}')

        # for gate_name in parser.gates:
        #     gate = parser.get_gate(gate_name)
        #     if gate.gate_type == 'dff':
        #         if gate.inputs[0] == set_or_reset_net or gate.inputs[1] == set_or_reset_net:
        #             trojan_gates.append(gate.name)
        #     # elif gate.gate_type == 'xor' or gate.gate_type == 'xnor':
        #     #     if is_this_xor_part_of_an_LFSR(gate_name, start_of_LFSR.name, parser):
        #     #         trojan_gates.append(gate_name)
        #         visited_for_dff = []
        #         visited_for_xor = []
        
        trojan_dffs = []

        for gate_name in parser.gates:
            gate = parser.get_gate(gate_name)
            if gate.gate_type == 'dff':
                if gate.inputs[0] == set_or_reset_net or gate.inputs[1] == set_or_reset_net:
                    if is_this_dff_start_of_an_LFSR(gate_name, start_of_LFSR.name, parser):
                        trojan_gates.append(gate_name)
                        trojan_dffs.append(gate_name)
                visited_for_dff = []
                visited_for_xor = []

        for gate_name in parser.gates:
            gate = parser.get_gate(gate_name)
            if gate.gate_type == 'xor' or gate.gate_type == 'xnor':
                visited_for_dff = []
                visited_for_xor = []
                if is_this_xor_part_of_an_LFSR(gate_name, start_of_LFSR.name, parser):
                    trojan_gates.append(gate_name)
                else:
                    for output in gate.outputs:
                        if output.name in trojan_gates and output.gate_type == 'dff':
                            trojan_gates.append(gate_name)
                            break
        
        visited_for_dff = []
        visited_for_xor = []

        # print (f"is the xor gate g178 part of the LFSR? {is_this_xor_part_of_an_LFSR('g178', start_of_LFSR.name, parser)}")


        trojan_gates.append(set_or_reset_net)

        extra_trojan_xors = []
        for gate_name in trojan_dffs:
            gate = parser.get_gate(gate_name)
            for output in gate.outputs:
                if output.gate_type == 'dff':
                    if output.inputs[0] == set_or_reset_net:
                        if output.name not in trojan_gates:
                            trojan_gates.append(output.name)
                elif output.gate_type == 'xor' or output.gate_type == 'xnor':
                    if output.name not in trojan_gates:
                        #trojan_gates.append(gate_name)
                        extra_trojan_xors.append(output.name)

        for gate_name in extra_trojan_xors:
            gate = parser.get_gate(gate_name)
            for output in gate.outputs:
                if output.gate_type == 'dff':
                    if output.inputs[0] == set_or_reset_net:
                        if output.name not in trojan_gates:
                            trojan_gates.append(output.name)
                            if gate_name not in trojan_gates:
                                trojan_gates.append(gate_name)
        # print (f'length of trojan list:{len(trojan_gates)}')
        # print (trojan_gates)
        # print (f'length of trojan dffs list:{len(trojan_dffs)}')
        # print (trojan_dffs)
        # print (f'length of trojan xors list:{len(extra_trojan_xors)}')
        # print (extra_trojan_xors)

    
    if len(trojan_gates) < 12:
        return [[], False]
    return [trojan_gates, True]