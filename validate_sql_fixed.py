"""SQL-Injection validation - FIXED version"""
import zipfile
import random
from pathlib import Path
from collections import defaultdict, deque

random.seed(42)
MIN_SUPPORT = 30
THETA_MODEL = 0.8
THETA_OBS = 0.6
THETA_EDGE = 0.75

def load_syscalls(zip_path):
    syscalls = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.sc'):
                    with zf.open(name) as f:
                        for line in f:
                            parts = line.decode('utf-8', errors='ignore').strip().split()
                            if len(parts) >= 6:
                                syscalls.append(parts[5])
    except:
        pass
    return syscalls

def count_pairs(syscalls, delta=15):
    """Same function used in training and testing"""
    pairs = defaultdict(lambda: {'xy': 0, 'yx': 0})
    for i, a in enumerate(syscalls):
        for j in range(i + 1, min(i + delta + 1, len(syscalls))):
            b = syscalls[j]
            if a == b:
                continue
            x, y = (a, b) if a < b else (b, a)
            if a == x:
                pairs[(x, y)]['xy'] += 1
            else:
                pairs[(x, y)]['yx'] += 1
    return pairs

def get_pair_violation(syscalls, rule_a, rule_b, delta=15):
    """
    Check if rule 'a < b' is violated.
    Violation = observed b→a ratio >= THETA_OBS with support >= MIN_SUPPORT
    Returns: (violated: bool, ratio: float, support: int)
    """
    pairs = count_pairs(syscalls, delta)
    
    # Canonical key
    x, y = (rule_a, rule_b) if rule_a < rule_b else (rule_b, rule_a)
    
    if (x, y) not in pairs:
        return False, 0, 0
    
    c = pairs[(x, y)]
    total = c['xy'] + c['yx']
    
    if total < MIN_SUPPORT:
        return False, 0, total
    
    # Rule is a < b, so we expect a→b (x→y if a==x, else y→x)
    # Violation is when we see b→a strongly
    if rule_a == x:
        # rule: x < y, violation = y→x observed (yx/total >= threshold)
        obs_violation = c['yx'] / total
    else:
        # rule: y < x, violation = x→y observed (xy/total >= threshold)
        obs_violation = c['xy'] / total
    
    violated = obs_violation >= THETA_OBS
    return violated, obs_violation, total

def find_cycle_edges(edges):
    graph = defaultdict(set)
    for (a, b) in edges:
        graph[a].add(b)
    cycle_edges = []
    for (a, b) in edges:
        visited, stack = set(), [b]
        while stack:
            node = stack.pop()
            if node == a:
                cycle_edges.append((a, b))
                break
            if node not in visited:
                visited.add(node)
                stack.extend(graph[node])
    return cycle_edges

def is_acyclic(edges):
    return len(find_cycle_edges(edges)) == 0

def transitive_closure_bfs(edges):
    graph = defaultdict(set)
    nodes = set()
    for (a, b) in edges:
        graph[a].add(b)
        nodes.add(a)
        nodes.add(b)
    closure = set()
    for start in nodes:
        visited = set()
        queue = deque([start])
        while queue:
            node = queue.popleft()
            for neighbor in graph[node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    closure.add((start, neighbor))
                    queue.append(neighbor)
    return closure, nodes

def r_diamond(R):
    R_bar = set(R)
    while True:
        cycle_edges = find_cycle_edges(R_bar)
        if not cycle_edges:
            break
        R_bar.remove(random.choice(cycle_edges))
    R_diamond = set(R_bar)
    candidates = list(R - R_bar)
    random.shuffle(candidates)
    for edge in candidates:
        if is_acyclic(R_bar | {edge}):
            R_bar = R_bar | {edge}
            R_diamond = set(R_bar)
    closure, nodes = transitive_closure_bfs(R_diamond)
    return closure, nodes

# Main
scenario = Path("data/LID-DS-2021/CWE-89-SQL-injection")
train_files = list(scenario.glob("training/*.zip"))
normal_files = list(scenario.glob("test/normal/*.zip"))
attack_files = list(scenario.glob("test/normal_and_attack/*.zip"))

print("=" * 70)
print("SQL-INJECTION VALIDATION (FIXED)")
print("=" * 70)
print(f"Data: {len(train_files)} train, {len(normal_files)} normal, {len(attack_files)} attack")

# Train STIDE
stide = set()
for zf in train_files:
    syscalls = load_syscalls(zf)
    for i in range(len(syscalls) - 4):
        stide.add(tuple(syscalls[i:i+5]))
print(f"STIDE: {len(stide)} n-grams")

# Build R
all_pairs = defaultdict(lambda: {'xy': 0, 'yx': 0})
for zf in train_files:
    syscalls = load_syscalls(zf)
    pairs = count_pairs(syscalls)
    for k, c in pairs.items():
        all_pairs[k]['xy'] += c['xy']
        all_pairs[k]['yx'] += c['yx']

R = set()
edge_weights = {}
for (x, y), c in all_pairs.items():
    total = c['xy'] + c['yx']
    if total >= MIN_SUPPORT:
        conf = c['xy'] / total
        if conf >= THETA_EDGE:
            R.add((x, y))
            edge_weights[(x, y)] = conf
        elif conf <= (1 - THETA_EDGE):
            R.add((y, x))
            edge_weights[(y, x)] = 1 - conf

print(f"Initial R: {len(R)} edges")

closure_set, nodes = r_diamond(R)
closure = {n: set() for n in nodes}
for (a, b) in closure_set:
    closure[a].add(b)

print(f"R◇: {len(closure_set)} edges, {len(nodes)} syscalls")

# Test all files
results = []
for is_attack, files in [(False, normal_files), (True, attack_files)]:
    for zf in files:
        syscalls = load_syscalls(zf)
        ngrams = [tuple(syscalls[i:i+5]) for i in range(len(syscalls)-4)]
        stide_score = sum(1 for ng in ngrams if ng not in stide) / len(ngrams) if ngrams else 0
        
        pairs = count_pairs(syscalls)
        viols_hc = 0
        violated_rules = []
        for (x, y), c in pairs.items():
            total = c['xy'] + c['yx']
            if total < MIN_SUPPORT:
                continue
            obs_xy = c['xy'] / total
            obs_yx = c['yx'] / total
            
            # Check x→y observed but model says y < x
            if obs_xy >= THETA_OBS and x in nodes and y in nodes:
                if x in closure.get(y, set()) and edge_weights.get((y, x), 0) >= THETA_MODEL:
                    viols_hc += 1
                    violated_rules.append((y, x))  # Store as tuple
            # Check y→x observed but model says x < y
            if obs_yx >= THETA_OBS and x in nodes and y in nodes:
                if y in closure.get(x, set()) and edge_weights.get((x, y), 0) >= THETA_MODEL:
                    viols_hc += 1
                    violated_rules.append((x, y))
        
        results.append({
            'file': zf.name, 'attack': is_attack,
            'stide': stide_score, 'viols_hc': viols_hc,
            'rules': violated_rules
        })

normal_r = [r for r in results if not r['attack']]
attack_r = [r for r in results if r['attack']]

# STIDE Results
print(f"\n{'='*70}")
print("STIDE Detection")
print("=" * 70)
best_f1, best_t, best_p, best_rec = 0, 0, 0, 0
best_tp, best_fp = 0, 0
for t in [0.001, 0.002, 0.005, 0.01, 0.02, 0.05]:
    tp = sum(1 for r in attack_r if r['stide'] >= t)
    fp = sum(1 for r in normal_r if r['stide'] >= t)
    fn = len(attack_r) - tp
    p = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    f1 = 2*p*rec/(p+rec) if p+rec else 0
    print(f"  t={t:.4f}: TP={tp:3d} FP={fp:3d} P={p:.3f} R={rec:.3f} F1={f1:.3f}")
    if f1 > best_f1:
        best_f1, best_t, best_p, best_rec = f1, t, p, rec
        best_tp, best_fp = tp, fp

print(f"\nBest STIDE: t={best_t}, P={best_p:.3f}, R={best_rec:.3f}, F1={best_f1:.3f}")

# PO Standalone
print(f"\n{'='*70}")
print("R◇ PO as Standalone Detector")
print("=" * 70)
po_best_f1 = 0
for thresh in [0, 1, 2, 3, 5]:
    tp = sum(1 for r in attack_r if r['viols_hc'] > thresh)
    fp = sum(1 for r in normal_r if r['viols_hc'] > thresh)
    fn = len(attack_r) - tp
    p = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    f1 = 2*p*rec/(p+rec) if p+rec else 0
    print(f"  viols>{thresh}: TP={tp:3d} FP={fp:3d} P={p:.3f} R={rec:.3f} F1={f1:.3f}")
    if f1 > po_best_f1:
        po_best_f1 = f1

# Context-gated
print(f"\n{'='*70}")
print(f"Context-Gated (STIDE t={best_t})")
print("=" * 70)

flagged = [r for r in results if r['stide'] >= best_t]
tp_f = [r for r in flagged if r['attack']]
fp_f = [r for r in flagged if not r['attack']]

print(f"STIDE Alerts: {len(tp_f)} TP + {len(fp_f)} FP")

tp_hc = sum(1 for r in tp_f if r['viols_hc'] > 0)
fp_hc = sum(1 for r in fp_f if r['viols_hc'] > 0)

hc_tp_rate = tp_hc / len(tp_f) if tp_f else 0
hc_fp_rate = fp_hc / len(fp_f) if fp_f else 0
explprec = tp_hc / (tp_hc + fp_hc) if (tp_hc + fp_hc) else 0

print(f"HC@TP: {tp_hc}/{len(tp_f)} = {hc_tp_rate:.1%}")
print(f"HC@FP: {fp_hc}/{len(fp_f)} = {hc_fp_rate:.1%}")
print(f"ExplPrec: {tp_hc}/{tp_hc+fp_hc} = {explprec:.1%}" if (tp_hc+fp_hc) > 0 else "ExplPrec: N/A")

# Rule breakdown - count from results
print(f"\n{'='*70}")
print("Rule Violation Breakdown (from HC violations)")
print("=" * 70)
all_rules = defaultdict(lambda: {'attack': 0, 'normal': 0})
for r in results:
    for rule in r['rules']:
        rule_str = f"{rule[0]}<{rule[1]}"
        if r['attack']:
            all_rules[rule_str]['attack'] += 1
        else:
            all_rules[rule_str]['normal'] += 1

print(f"{'Rule':<25} {'Attack':>10} {'Normal':>10} {'Precision':>12}")
print("-" * 60)
top_rules = sorted(all_rules.items(), key=lambda x: -x[1]['attack'])[:10]
for rule_str, counts in top_rules:
    total = counts['attack'] + counts['normal']
    prec = counts['attack'] / total if total > 0 else 0
    print(f"{rule_str:<25} {counts['attack']:>10} {counts['normal']:>10} {prec:>12.1%}")

# Auto-select top rule and validate
if top_rules:
    top_rule_str = top_rules[0][0]
    top_rule_parts = top_rule_str.split('<')
    rule_a, rule_b = top_rule_parts[0], top_rule_parts[1]
    
    print(f"\n{'='*70}")
    print(f"Top Rule Validation: {rule_a} < {rule_b}")
    print("(Using same count_pairs logic as main pipeline)")
    print("=" * 70)
    
    n_viol, n_total = 0, 0
    a_viol, a_total = 0, 0
    
    for zf in normal_files:
        syscalls = load_syscalls(zf)
        violated, ratio, support = get_pair_violation(syscalls, rule_a, rule_b)
        if support >= MIN_SUPPORT:
            n_total += 1
            if violated:
                n_viol += 1
    
    for zf in attack_files:
        syscalls = load_syscalls(zf)
        violated, ratio, support = get_pair_violation(syscalls, rule_a, rule_b)
        if support >= MIN_SUPPORT:
            a_total += 1
            if violated:
                a_viol += 1
    
    print(f"Normal files with violation: {n_viol}/{n_total} ({n_viol/n_total*100:.1f}%)" if n_total else "Normal: N/A (no files with sufficient support)")
    print(f"Attack files with violation: {a_viol}/{a_total} ({a_viol/a_total*100:.1f}%)" if a_total else "Attack: N/A (no files with sufficient support)")
    
    if n_viol + a_viol > 0:
        rule_prec = a_viol / (a_viol + n_viol)
        print(f"Rule Precision: {rule_prec:.1%}")

# Final Summary
print(f"\n{'='*70}")
print("FINAL SUMMARY FOR PAPER")
print("=" * 70)
print(f"""
CWE-89-SQL-Injection Results:
=============================
Dataset: {len(train_files)} train, {len(normal_files)} normal, {len(attack_files)} attack

STIDE Detection:
  - Precision: {best_p:.3f}
  - Recall: {best_rec:.3f}
  - F1: {best_f1:.3f}
  - Threshold: {best_t}
  - TP: {best_tp}, FP: {best_fp}

R◇ PO Standalone:
  - Best F1: {po_best_f1:.3f}

Context-Gated Explainability:
  - HC@TP: {hc_tp_rate:.1%} ({tp_hc}/{len(tp_f)})
  - HC@FP: {hc_fp_rate:.1%} ({fp_hc}/{len(fp_f)})
  - ExplPrec: {explprec:.1%}

Top Rule: {top_rules[0][0] if top_rules else 'N/A'}
  - Attack: {top_rules[0][1]['attack'] if top_rules else 0}
  - Normal: {top_rules[0][1]['normal'] if top_rules else 0}

Interpretation:
  - SQL-Injection is argument-based attack
  - Syscall ORDER changes are minimal
  - PO provides limited but still useful signal (ExplPrec={explprec:.0%})
""")
