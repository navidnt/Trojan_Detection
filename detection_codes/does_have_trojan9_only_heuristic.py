import re
from collections import defaultdict
from typing import List
from detection_codes.does_have_trojan3 import parse_verilog_signals, signals_to_dict
from utils.exploit_gates2 import NetlistParser
import torch
import torch.nn as nn
from transformers import BertModel, BertConfig
from torch.utils.data import Dataset, DataLoader
import torch.nn.functional as F
from utils.exploit_gates2 import transform_and_parse_with_originals





# VOCAB = ['DFF', 'AND', 'OR', 'NOT', 'X', '[PAD]']
VOCAB = ['AND', 'OR', 'NOT', 'X', '[PAD]']
PAD_TOKEN = '[PAD]'
MAX_LEN = 512
TREE_DIM = 64
EMBED_DIM = 512
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Extract Trojan gates from the reference file
def extract_trojan_gates(filename):
    trojan_gates = []
    inside_block = False

    with open(filename, 'r') as file:
        for line in file:
            stripped = line.strip()
            if stripped == "TROJAN_GATES":
                inside_block = True
                continue
            if stripped == "END_TROJAN_GATES":
                break
            if inside_block:
                trojan_gates.append(stripped)

    return trojan_gates

# -----Tokenizer-----
class SimpleGateTokenizer:
    def __init__(self, vocab):
        self.token2id = {tok: i for i, tok in enumerate(vocab)}
        self.pad_id = self.token2id[PAD_TOKEN]

    def encode(self, tokens, max_len=MAX_LEN):
        ids = [self.token2id.get(tok, self.token2id['X']) for tok in tokens]
        return ids[:max_len] + [self.pad_id] * (max_len - len(ids))

# ------------------------------
# Tree-Based Positional Encoding
# ------------------------------
def shift_right(vec, n=2):
    return [0]*n + vec[:-n]

def encode_node(parent_encoding, is_left):
    bit = [1, 0] if is_left else [0, 1]
    return (shift_right(parent_encoding)[:len(parent_encoding)] + bit)[:len(parent_encoding)]

def tree_based_positional_encoding(tree, tree_dim=TREE_DIM):
    encodings = []

    def traverse(node, encoding):
        encodings.append(encoding[:tree_dim])
        if 'left' in node:
            left_encoding = encode_node(encoding, is_left=True)
            traverse(node['left'], left_encoding)
        if 'right' in node:
            right_encoding = encode_node(encoding, is_left=False)
            traverse(node['right'], right_encoding)

    root_encoding = [0] * tree_dim
    traverse(tree, root_encoding)
    return encodings

# # ------------------------------
# # Dummy Tree and Tokens (Preorder)
# # ------------------------------
# sample_tree = {
#     'type': 'OR',
#     'left': {
#         'type': 'NOT',
#         'left': {'type': 'X'}
#     },
#     'right': {
#         'type': 'AND',
#         'left': {'type': 'X'},
#         'right': {'type': 'X'}
#     }
# }
# sample_tokens = ['OR', 'NOT', 'X', 'AND', 'X', 'X']

# ------------------------------
# Dataset
# ------------------------------
class GateDataset(Dataset):
    def __init__(self, samples, tokenizer):
        self.samples = samples
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        item = self.samples[idx]
        token_ids = self.tokenizer.encode(item['tokens'])
        tree_pos = item['tree_pos']
        tree_pos += [[0]*TREE_DIM] * (MAX_LEN - len(tree_pos))
        tree_pos = tree_pos[:MAX_LEN]
        return {
            'input_ids': torch.tensor(token_ids),
            'tree_pos': torch.tensor(tree_pos, dtype=torch.float32),
            'label': torch.tensor(item['label'])
        }

# ------------------------------
# Embedding Layer
# ------------------------------
class CustomEmbedding(nn.Module):
    def __init__(self, vocab_size):
        super().__init__()
        self.word_embed = nn.Embedding(vocab_size, EMBED_DIM)
        self.pos_embed = nn.Embedding(MAX_LEN, EMBED_DIM)
        self.tree_proj = nn.Linear(TREE_DIM, EMBED_DIM)

    def forward(self, input_ids, tree_pos):
        word_emb = self.word_embed(input_ids)
        pos_ids = torch.arange(input_ids.size(1), device=input_ids.device).unsqueeze(0)
        pos_emb = self.pos_embed(pos_ids)
        tree_emb = self.tree_proj(tree_pos)
        return word_emb + pos_emb + tree_emb

# ------------------------------
# BERT-based Trojan Classifier
# ------------------------------
class TrojanBERT(nn.Module):
    def __init__(self, vocab_size):
        super().__init__()
        self.embeddings = CustomEmbedding(vocab_size)
        config = BertConfig(
            hidden_size=EMBED_DIM,
            num_hidden_layers=4,
            num_attention_heads=8,
            intermediate_size=1024,
            max_position_embeddings=MAX_LEN
        )
        self.bert = BertModel(config)
        self.classifier = nn.Linear(EMBED_DIM, 2)

    def forward(self, input_ids, tree_pos):
        x = self.embeddings(input_ids, tree_pos)
        out = self.bert(inputs_embeds=x)
        cls = out.last_hidden_state[:, 0]  # [CLS] token representation
        return self.classifier(cls)

def build_fanin_tree(parser, gate_name, max_depth=6):
    def recurse(g, depth):
        if depth == 0 or g not in parser.gates:
            return {'type': 'X'}

        gate = parser.gates[g]
        gate_type = gate.gate_type            # ✅ access attribute, not key
        inputs = gate.inputs             # ✅ access attribute, not key

        if len(inputs) == 0:
            return {'type': gate_type}

        if len(inputs) == 1:
            return {
                'type': gate_type,
                'left': recurse(inputs[0], depth - 1)
            }

        def to_binary_tree(ins):
            if len(ins) == 2:
                return {
                    'left': recurse(ins[0], depth - 1),
                    'right': recurse(ins[1], depth - 1)
                }
            return {
                'left': recurse(ins[0], depth - 1),
                'right': to_binary_tree(ins[1:])
            }

        tree = {'type': gate_type}
        tree.update(to_binary_tree(inputs))
        return tree

    return recurse(gate_name, max_depth)

def predict_gate_trojan_probability(parser, gate_name, model, tokenizer):
    # Step 1: Token sequence
    tokens = parser.tokenize_gate_fanin_cone(gate_name, max_depth=6)

    # Step 2: Fan-in tree
    tree = build_fanin_tree(parser, gate_name, max_depth=6)

    # Step 3: Tree-based position encoding
    tree_pos = tree_based_positional_encoding(tree)

    # Step 4: Padding to MAX_LEN
    token_ids = tokenizer.encode(tokens, max_len=MAX_LEN)
    tree_pos += [[0]*TREE_DIM] * (MAX_LEN - len(tree_pos))
    tree_pos = tree_pos[:MAX_LEN]

    # Step 5: Tensorize and move to device
    input_ids = torch.tensor([token_ids]).to(device)
    tree_pos_tensor = torch.tensor([tree_pos], dtype=torch.float32).to(device)

    # Step 6: Run through model
    model.eval()
    with torch.no_grad():
        logits = model(input_ids, tree_pos_tensor)
        probs = F.softmax(logits, dim=-1)
        trojan_prob = probs[0][1].item()  # class 1 = Trojan
        #print("Model output logits:", logits)
        #print("Probabilities:", probs)

    return trojan_prob



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







def does_have_trojan9(target_file: str) -> List:
    trojan_gates = []
    trojan_gates_set = set()

    new_parser = NetlistParser()
    new_parser.parse_netlist(target_file)

    with open(target_file, "r") as f:
        text = f.read()
    signals = parse_verilog_signals(text)
    signal_dict = signals_to_dict(signals)

    def find_fanin_cone(gate_name: str) -> set:
        """
        Find the fanin cone of a gate until primary inputs or a dff using bfs.
        """
        gate = new_parser.get_gate(gate_name)
        fanin_inputs = set()
        queue = [gate]
        visited = set()
        visited.add(gate.name)
        while queue:
            current_gate = queue.pop(0)
            inputs = current_gate.inputs
            if current_gate.gate_type == 'dff':
                fanin_inputs.add(current_gate.output_net.split('[')[0])
                continue
            for input_name in inputs:
                driver_gate = new_parser.get_gate(input_name)
                if driver_gate is None:
                    # print (input_name)
                    if input_name[0] != '1':
                        if signal_dict[input_name.split('[')[0]].size > 1 and signal_dict[input_name.split('[')[0]].size <= 3:
                            fanin_inputs.add(input_name)
                        else:
                            fanin_inputs.add(input_name.split('[')[0])

                else:
                    if driver_gate.name not in visited:
                        queue.append(driver_gate)
                        visited.add(driver_gate.name)
        return fanin_inputs

    def find_whole_fanin_cone(gate_name: str) -> set:
        """
        Find the fanin cone of a gate until primary inputs or a dff using bfs.
        """
        gate = new_parser.get_gate(gate_name)
        fanin_inputs = set()
        queue = [gate]
        visited = set()
        visited.add(gate.name)
        while queue:
            current_gate = queue.pop(0)
            inputs = current_gate.inputs
            if current_gate.gate_type == 'dff':
                fanin_inputs.add(current_gate.output_net.split('[')[0])
                continue
            for input_name in inputs:
                driver_gate = new_parser.get_gate(input_name)
                if driver_gate is None:
                    # print (input_name)
                    if input_name[0] != '1':
                        if signal_dict[input_name.split('[')[0]].size > 1 and signal_dict[input_name.split('[')[0]].size <= 3:
                            fanin_inputs.add(input_name)
                        else:
                            fanin_inputs.add(input_name.split('[')[0])

                else:
                    if driver_gate.name not in visited:
                        queue.append(driver_gate)
                        visited.add(driver_gate.name)
        return visited

    ans = 0
    eligible_outputs = []
    for gate_name in new_parser.gates:
        gate = new_parser.get_gate(gate_name)
        gate_outputs = gate.outputs
        # flag = False
        # for output in gate_outputs:
        #     if output.gate_type != 'dff':
        #         flag = True
        #         break
        # if flag:
        #     continue
        if gate.gate_type != 'dff':
            #print(gate_name)
            brackets = set()
            num_of_big = 0
            fanin_inputs = find_fanin_cone(gate_name)
            if len(fanin_inputs) >= 5 and len(fanin_inputs) <= 25:
                for net in fanin_inputs:
                    if '[' in net:
                        brackets.add(net.split('[')[0])
                if len(brackets) > 2:
                    continue
                # for net in fanin_inputs:
                #     if '[' not in net:
                #         if signal_dict[net].size > 2:
                #             num_of_big += 1
                # if num_of_big < 3:
                #     continue
                if '[' not in gate.output_net:
                    continue
                if signal_dict[gate.output_net.split('[')[0]].size > 64:
                    continue
                eligible_outputs.append(gate_name)
                # print(f"Gate: {gate_name}, Fanin size: {len(fanin_inputs)}, Fanin: {sorted(fanin_inputs)}, Output: {gate.output_net}")
                ans += 1

    if ans < 4:
        return [[], False]
    # create target_file_simplified.v
    # transform_and_parse_with_originals(target_file, f"target_file_simplified.v")

    # parser = NetlistParser()
    # parser.parse_netlist("target_file_simplified.v")
    # calculated_dfs = {}

    # # VOCAB = ['DFF', 'AND', 'OR', 'NOT', 'X', '[PAD]']
    # # PAD_TOKEN = '[PAD]'
    # # MAX_LEN = 512
    # # TREE_DIM = 64
    # # EMBED_DIM = 512
    # # device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # tokenizer = SimpleGateTokenizer(VOCAB)
    # model_save_path = f"./Models/only_design9/TrojanBERT_Trojan{9}.pt"

    # model1 = TrojanBERT(vocab_size=len(VOCAB)).to(device)
    # model1.load_state_dict(torch.load(model_save_path))
    
    # results = []
    # for gate_name in parser.gates:
    #     prob = predict_gate_trojan_probability(parser, gate_name, model1, tokenizer)
    #     results.append((gate_name, prob))

    # results.sort(key=lambda x: x[1], reverse=True)

    # threshold = 0.5
    # for gate_name, prob in results:
    #     if prob > threshold:
    #         trojan_gates_set.add(gate_name)
    # predict_Trojan_threshold = 0.5 # change this to the threshold you want to use
    # predicted_trojan_gates = set(gate_name.split('_')[0] for gate_name, prob in results if prob >= predict_Trojan_threshold)
    # negatives = set(gate_name.split('_')[0] for gate_name, prob in results if prob < predict_Trojan_threshold)
    # positives = set(gate_name.split('_')[0] for gate_name, prob in results if prob >= predict_Trojan_threshold)

    # trojan_gates = list(positives)
    eligible_gates = set()
    for gate_name in eligible_outputs:
        add_set = find_whole_fanin_cone(gate_name)
        eligible_gates.update(add_set)

    real_eligible_gates = set()
    for gate_name in eligible_gates:
        if '[' in gate_name:
            real_eligible_gates.add(gate_name.split('[')[0])
        else:
            real_eligible_gates.add(gate_name)

    does_exist = True
    if len(real_eligible_gates) == 0:
        does_exist = False
    trojan_gates = list(real_eligible_gates)

    # predict_Trojan_threshold = 0.87 # change this to the threshold you want to use
    # predicted_trojan_gates = set(gate_name.split('_')[0] for gate_name, prob in results if prob >= predict_Trojan_threshold)
    # negatives = set(gate_name.split('_')[0] for gate_name, prob in results if prob < predict_Trojan_threshold)
    # positives = set(gate_name.split('_')[0] for gate_name, prob in results if prob >= predict_Trojan_threshold)

    # trojan_gates_set = set(trojan_gates)
    # trojan_gates_set.update(positives)
    # trojan_gates = list(trojan_gates_set)

    return [trojan_gates, does_exist]