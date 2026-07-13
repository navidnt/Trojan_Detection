import re
from collections import defaultdict
from typing import List
from utils.exploit_gates3 import NetlistParser

def find_reset_signals(parser: NetlistParser) -> set[str]:
    reset_signals = set()
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type == "dff":
            reset_signal = gate.reset_signal
            if not reset_signal.startswith('1'):
                reset_signals.add(reset_signal)
    return reset_signals

def find_first_dff_gate_in_fanin_cone(gate_name: str, parser: NetlistParser, mx: int) -> List:
    has = False
    which_level = -1
    number_of_dffs = 0
    dffs = []
    previous_dffs = []
    exceptions = []
    number_of_exceptions = 0

    level = 1
    first_input = parser.get_gate(gate_name).inputs[3] if parser.get_gate(gate_name).d_input else None
    fanin_queue = [first_input] if first_input else []
    if not fanin_queue:
        return [has, which_level, number_of_dffs]
    
    #print(f"Starting search for DFFs in fanin cone of gate {gate_name} with first input {first_input}")
    if parser.get_gate(first_input) is None:
        return [has, which_level, number_of_dffs]
    if parser.get_gate(first_input).gate_type == "dff":
        return [has, which_level, number_of_dffs]

    visited = [gate_name, first_input]
    while level <= mx and not has:
        next_fanin_queue = []
        for current_gate_name in fanin_queue:
            current_gate = parser.get_gate(current_gate_name)
            for input_gate_name in current_gate.inputs:
                # ignore inputs that are not gates
                if parser.get_gate(input_gate_name) is None:
                    continue
                if input_gate_name not in visited:
                    next_fanin_queue.append(input_gate_name)
                    visited.append(input_gate_name)
        level += 1
        for gate_name in next_fanin_queue:
            gate = parser.get_gate(gate_name)
            if gate.gate_type == "dff":
                has = True
                which_level = level
                #number_of_dffs += 1
                dffs.append(gate_name)

        if has:
            for dff_name in dffs:
                dff = parser.get_gate(dff_name)
                dff_outputs = []
                for output in dff.outputs:
                    dff_outputs.append(output.name)
                #print (f"Checking DFF {dff_name} with outputs {dff_outputs}")
                if bool(set(dffs) & set(dff_outputs)):
                    #dffs.remove(dff_name)
                    exceptions.append(dff_name)
        fanin_queue = next_fanin_queue


    dffs = [item for item in dffs if item not in exceptions]
    for dff_name in dffs:
        dff = parser.get_gate(dff_name)
        if parser.get_gate(dff.inputs[3]) != None:
            if parser.get_gate(dff.inputs[3]).gate_type == "dff":
                if dff.inputs[3] not in previous_dffs:
                    previous_dffs.append(dff.inputs[3])

    number_of_dffs = len(dffs)
    return [has, which_level, number_of_dffs, dffs, previous_dffs]



def does_have_trojan2(target_file: str) -> List:
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)

    reset_signal = list(find_reset_signals(parser))[0] if find_reset_signals(parser) else None

    nearest_level_of_dffs = []
    for gate_name in parser.gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type != "dff":
            continue
        nearest_level_of_dff = find_first_dff_gate_in_fanin_cone(gate_name, parser, 10)
        nearest_level_of_dffs.append(([gate_name, nearest_level_of_dff]))
    sorted_nearest_level_of_dffs = sorted(nearest_level_of_dffs, key=lambda x: x[1][2], reverse=True)
    # print("Nearest level of DFFs:", sorted_nearest_level_of_dffs)

    if sorted_nearest_level_of_dffs == []:
        return [[], False]
    final_dff_gate = sorted_nearest_level_of_dffs[0]
    # print("Final DFF gate:", final_dff_gate[0])


    def add_fanin_cone_to_trojan_gates(gate_name: str, parser: NetlistParser, mx: int) -> List:
        flag = False
        has, which_level, number_of_dffs, dffs, previous_dffs = find_first_dff_gate_in_fanin_cone(gate_name, parser, mx)
        first_input = parser.get_gate(gate_name).inputs[3] if parser.get_gate(gate_name).d_input else None
        fanin_queue = [first_input]
        trojan_gates.append(first_input if first_input else None)
        level = 1
        visited = [gate_name, first_input] if first_input else [gate_name]
        while level <= mx:
            next_fanin_queue = []
            for current_gate_name in fanin_queue:
                current_gate = parser.get_gate(current_gate_name)
                for input_gate_name in current_gate.inputs:
                    # ignore inputs that are not gates
                    if parser.get_gate(input_gate_name) is None:
                        continue
                    if input_gate_name not in visited:
                        next_fanin_queue.append(input_gate_name)
                        visited.append(input_gate_name)
                        if input_gate_name not in trojan_gates:
                            trojan_gates.append(input_gate_name)

            if level == 2:
                if len(next_fanin_queue) != 2 * len(fanin_queue):
                    flag = True
            if len(next_fanin_queue) > 2 * len(fanin_queue):
                flag = True
            if len(next_fanin_queue) < len(fanin_queue):
                flag = True
            fanin_queue = next_fanin_queue
            # print(f"Level {level} fanin queue: {next_fanin_queue}")
            level += 1

        return [fanin_queue, level, flag]


    trojan_gates = []
    trojan_gates.append(final_dff_gate[0])
    [has, which_level, number_of_dffs, dffs, previous_dffs] = final_dff_gate[1]
    [last_level_gates, last_level, flag]  = add_fanin_cone_to_trojan_gates(final_dff_gate[0], parser, which_level - 2)
    for dff in dffs:
        trojan_gates.append(dff)

    reset_gate = parser.get_gate(dffs[0]).inputs[0]
    # print("Reset gate:", reset_gate)
    if parser.get_gate(reset_gate):
        trojan_gates.append(reset_gate)

    # print("Trojan gates found:", trojan_gates)
    # print("Number of trojan gates found:", len(trojan_gates))
    # print(which_level)

    if len(dffs) != len(last_level_gates):
        return [[], False]
    if last_level < 4:
        return [[], False]
    if flag:
        return [[], False]

    for final_dff_gate in sorted_nearest_level_of_dffs:
        # print("Final DFF gate:", final_dff_gate[0])
        trojan_gates = []
        trojan_gates.append(final_dff_gate[0])
        if len(final_dff_gate[1]) < 5:
            continue
        [has, which_level, number_of_dffs, dffs, previous_dffs] = final_dff_gate[1]
        [last_level_gates, last_level, flag]  = add_fanin_cone_to_trojan_gates(final_dff_gate[0], parser, which_level - 2)
        for dff in dffs:
            trojan_gates.append(dff)

        flag = False
        trojan_input_nets = set()
        for gate_name in trojan_gates:
            gate = parser.get_gate(gate_name)
            if gate is None:
                flag = True
                break
            if gate.gate_type == "dff":
                d_input_name = gate.inputs[3]
                if d_input_name not in trojan_gates:
                    trojan_input_nets.add(gate.input_nets[3])

            else:
                for input_name, input_net_name in zip(gate.inputs, gate.input_nets):
                    if input_name not in trojan_gates:
                        trojan_input_nets.add(input_net_name)

        if flag:
            continue

        # main_input_signals = set()
        # for trojan_input_net in trojan_input_nets:
        #     main_input_signals.add(trojan_input_net.split('[')[0])  
        #     if '[' not in trojan_input_net:
        #         flag = True
        #         break

        # print("Main input signals:", main_input_signals)

        if len(trojan_input_nets) != len(dffs):
            continue



        reset_gate = parser.get_gate(dffs[0]).inputs[0]
        # print("Reset gate:", reset_gate)

        if parser.get_gate(reset_gate):
            trojan_gates.append(reset_gate)
        
        break

    if len(trojan_gates) < 15:
        return [[], False]
    return [trojan_gates, True]



