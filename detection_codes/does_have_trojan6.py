import re
from collections import defaultdict
from typing import List
from utils.exploit_gates2 import NetlistParser


class Signal:
    def __init__(self, name: str, size: int, sig_type: str):
        self.name = name
        self.size = size
        self.type = sig_type  # "None", "PI", or "PO"

    def __repr__(self):
        return f"Signal(name='{self.name}', size={self.size}, type='{self.type}')"


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*?$", "", text, flags=re.M)
    return text


def parse_range_to_size(range_str: str) -> int:
    m = re.match(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]", range_str) if range_str else None
    if not m:
        return 1
    a, b = int(m.group(1)), int(m.group(2))
    return abs(a - b) + 1


def extract_decl_names(decl_body: str):
    parts = [p.strip() for p in decl_body.split(",")]
    names = []
    for p in parts:
        base = re.split(r"\s*\[", p)[0].strip()
        base = re.split(r"\s*=", base)[0].strip()
        if base:
            names.append(base)
    return names


def parse_verilog_signals(text: str):
    clean = strip_comments(text)
    clean = re.sub(r"\s+", " ", clean)

    port_dir_map = {}
    for dir_kw in ["input", "output"]:
        pattern = rf"\b{dir_kw}\b\s+(?:reg\s+|wire\s+)?(?P<range>\[[^\]]+\]\s+)?(?P<names>[^;]+?)\s*;"
        for m in re.finditer(pattern, clean):
            rng = m.group("range")
            size = parse_range_to_size(rng) if rng else 1
            names = extract_decl_names(m.group("names"))
            for nm in names:
                if nm not in port_dir_map:
                    port_dir_map[nm] = (dir_kw, size)

    wire_info = {}
    for m in re.finditer(r"\bwire\b\s+(?P<range>\[[^\]]+\]\s+)?(?P<names>[^;]+?)\s*;", clean):
        rng = m.group("range")
        size = parse_range_to_size(rng) if rng else 1
        names = extract_decl_names(m.group("names"))
        for nm in names:
            prev = wire_info.get(nm)
            if prev is None or size > prev:
                wire_info[nm] = size

    all_names = set(wire_info.keys()) | set(port_dir_map.keys())
    signals = []
    for nm in sorted(all_names):
        if nm in port_dir_map:
            dir_kw, port_size = port_dir_map[nm]
            sig_type = "PI" if dir_kw == "input" else "PO"
            size = max(port_size, wire_info.get(nm, port_size))
        else:
            sig_type = "None"
            size = wire_info.get(nm, 1)
        signals.append(Signal(nm, size, sig_type))

    return signals

def signals_to_dict(signals):
    """
    Convert a list of Signal objects into a dictionary mapping
    signal name -> Signal object.
    """
    return {sig.name: sig for sig in signals}


def does_have_trojan6(target_file: str) -> List:
    trojan_gates = []

    parser = NetlistParser()
    parser.parse_netlist(target_file)
    calculated_dfs = {}
    signals = parse_verilog_signals(open(target_file).read())
    signals_dict = signals_to_dict(signals)

    def find_number_of_leaves(gate_name: str) -> int:
        """
        Find the number of leaves for a given gate.
        """
        gate = parser.get_gate(gate_name)
        answer = 0
        for input in gate.inputs:
            driver_gate = parser.get_gate(input)
            if driver_gate is None:
                answer += 1
                continue
            if driver_gate.gate_type == 'dff':
                answer += 1
                continue
            if driver_gate.name in calculated_dfs:
                answer += calculated_dfs[driver_gate.name]
                continue
            answer += find_number_of_leaves(driver_gate.name)
        
        calculated_dfs[gate_name] = answer
            
        return answer
    
    def find_trojan_gates(gate_name: str):
        gate = parser.get_gate(gate_name)
        outputs = gate.outputs
        visited = set()
        trojan_gates.append(gate_name)
        for output in outputs:
            if output:
                if output.gate_type == 'xor' or output.gate_type == 'xnor':
                    trojan_gates.append(output.name)
        queue = [gate_name]
        visited.add(gate_name)
        while queue:
            current_gate_name = queue.pop(0)
            current_gate = parser.get_gate(current_gate_name)
            for input in current_gate.inputs:
                input_gate = parser.get_gate(input)
                if input_gate is None:
                    continue
                if input_gate.name in visited:
                    continue
                visited.add(input)
                trojan_gates.append(input)
                if calculated_dfs[input] > 2:
                    queue.append(input)
                else:
                    for input_of_input in input_gate.inputs:
                        input_of_input_gate = parser.get_gate(input_of_input)
                        if input_of_input_gate is None:
                            continue
                        if input_of_input_gate.gate_type == 'not':
                            trojan_gates.append(input_of_input)

    calculated_dfs = {}
    leaves_list = []
    #print (find_number_of_leaves('g1369'))
    for gate_name in parser.gates:
        if gate_name in calculated_dfs:
            continue
        if parser.get_gate(gate_name).gate_type == 'dff':
            calculated_dfs[gate_name] = 1
            continue
        find_number_of_leaves(gate_name)

    list_of_potential_final_gates = []
    leaves_list = sorted(calculated_dfs.items(), key=lambda x: x[1])
    for gate_name, num_leaves in leaves_list:
        gate = parser.get_gate(gate_name)
        if gate.gate_type in ['dff', 'not', 'buf']:
            continue
        if num_leaves == 2:
            list_of_potential_final_gates.append(gate_name)
            continue
        flag = False
        for input in gate.inputs:
            if input not in list_of_potential_final_gates:
                flag = True
                break
        if not flag:
            list_of_potential_final_gates.append(gate_name)
            
    # for gate_name in list_of_potential_final_gates:
    #     print(f"Gate: {gate_name}, Number of leaves: {calculated_dfs[gate_name]}")
    final_gate = list_of_potential_final_gates[-1]
    #print(f"Final Gate: {final_gate}")
    # for gate_name in sorted(list_of_potential_final_gates, key=lambda x: calculated_dfs[x], reverse=True):
    #     print(f"Gate: {gate_name}, Number of leaves: {calculated_dfs[gate_name]}")
    # print(calculated_dfs['g241'])

    trojan_gates = []
    find_trojan_gates(final_gate)
    # print(f"Number of Trojan Gates: {len(trojan_gates)}")
    # print(f"Trojan Gates: {trojan_gates}")
    gate = parser.get_gate(final_gate)
    outputs = []
    for output in gate.outputs:
        outputs.append(output.gate_type)
    # print(f"Outputs of Final Gate: {outputs}")

    if len(outputs) != 2:
        return [[], False]
    gate0 = gate.outputs[0]
    gate1 = gate.outputs[1]
    if gate0.gate_type != gate1.gate_type:
        return [[], False]
    last_gate = None
    for output in parser.get_gate(final_gate).outputs:
        if output not in trojan_gates:
            trojan_gates.append(output.name)
            last_gate = output

    
    def extract_before_bracket(s: str) -> str:
        if '[' in s:
            return s.split('[', 1)[0]
        return s


    last_output_signal = None
    trojan_dffs = []
    for gate_name in parser.gates:
        if parser.get_gate(gate_name).gate_type == 'dff':
            outputs = parser.get_gate(gate_name).outputs
            if (len(outputs) != 1):
                continue
            if outputs[0] and outputs[0].name in trojan_gates:
                trojan_dffs.append(gate_name)
            if outputs[0] and outputs[0].name == last_gate.name:
                last_output_signal = extract_before_bracket(parser.get_gate(gate_name).output_net)

    # print(f"Trojan DFFs: {trojan_dffs}")
    # print(f"Number of Trojan DFFs: {len(trojan_dffs)}")
    # print(f"Last Output Signal: {last_output_signal}")
    # print(f"Last Gate: {last_gate.name}")

    visited_gates = set()
    visited_inputs = set()
    def find_leaves(gate_name: str) -> List[str]:
        """
        Find the leaves of a given gate.
        """
        visited_gates.add(gate_name)
        gate = parser.get_gate(gate_name)
        leaves = []
        for input in gate.inputs:
            driver_gate = parser.get_gate(input)
            if driver_gate is None:
                if input not in visited_inputs:
                    leaves.append(input)
                    visited_inputs.add(input)
                continue
            if driver_gate.name in visited_gates:
                continue
            leaves.extend(find_leaves(driver_gate.name))    
        return leaves
    
    for gate_name in trojan_gates:
        gate = parser.get_gate(gate_name)
        if gate.gate_type == 'dff':
            return [[], False]
        
    # trojan_gates += trojan_dffs

    if len(trojan_gates) < 40:
        return [[], False]
    return [trojan_gates, True]