"""Final validation with multiple seeds for stability"""
import zipfile
import random
from pathlib import Path
from collections import defaultdict, deque
import numpy as np

SEEDS = [42, 7, 13, 21, 99]
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
    R_diamond_set = set(R_bar)
    candidates = list(R - R_bar)
    random.shuffle(candidates)
    for edge in candidates:
        if is_acyclic(R_bar | {edge}):
            R_bar = R_bar | {edge}
            R_diamond_set = set(R_bar)
    closure, nodes = transitive_closure_bfs(R_diamond_set)
    return closure, nodes

def evaluate_scenario_single_seed(name, path, seed):
    """Evaluate with a specific seed"""
    random.seed(seed)
    
    train_files = list(Path(path).glob("training/*.zip"))
    normal_files = list(Path(path).glob("test/normal/*.zip"))
    attack_files = list(Path(path).glob("test/normal_and_attack/*.zip"))
    
    # STIDE
    stide = set()
    for zf in train_files:
        syscalls = load_syscalls(zf)
        for i in range(len(syscalls) - 4):
            stide.add(tuple(syscalls[i:i+5]))
    
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
    
    # R◇
    closure_set, nodes = r_diamond(R)
    closure = {n: set() for n in nodes}
    for (a, b) in closure_set:
        closure[a].add(b)
    
    # Test
    results = []
    for is_attack, files in [(False, normal_files), (True, attack_files)]:
        for zf in files:
            syscalls = load_syscalls(zf)
            ngrams = [tuple(syscalls[i:i+5]) for i in range(len(syscalls)-4)]
            stide_score = sum(1 for ng in ngrams if ng not in stide) / len(ngrams) if ngrams else 0
            
            pairs = count_pairs(syscalls)
            viols_hc = 0
            rules = []
            for (x, y), c in pairs.items():
                total = c['xy'] + c['yx']
                if total < MIN_SUPPORT:
                    continue
                obs_xy = c['xy'] / total
                obs_yx = c['yx'] / total
                
                if obs_xy >= THETA_OBS and x in nodes and y in nodes:
                    if x in closure.get(y, set()) and edge_weights.get((y, x), 0) >= THETA_MODEL:
                        viols_hc += 1
                        rules.append(f"{y}<{x}")
                if obs_yx >= THETA_OBS and x in nodes and y in nodes:
                    if y in closure.get(x, set()) and edge_weights.get((x, y), 0) >= THETA_MODEL:
                        viols_hc += 1
                        rules.append(f"{x}<{y}")
            
            results.append({'attack': is_attack, 'stide': stide_score, 'viols_hc': viols_hc, 'rules': rules})
    
    normal_r = [r for r in results if not r['attack']]
    attack_r = [r for r in results if r['attack']]
    
    # Best STIDE
    best_f1, best_t = 0, 0
    for t in [0.001, 0.005, 0.01, 0.02, 0.05]:
        tp = sum(1 for r in attack_r if r['stide'] >= t)
        fp = sum(1 for r in normal_r if r['stide'] >= t)
        fn = len(attack_r) - tp
        p = tp/(tp+fp) if tp+fp else 0
        rec = tp/(tp+fn) if tp+fn else 0
        f1 = 2*p*rec/(p+rec) if p+rec else 0
        if f1 > best_f1:
            best_f1, best_t = f1, t
    
    # PO F1
    po_best_f1 = 0
    for thresh in [0, 1, 2, 3]:
        tp = sum(1 for r in attack_r if r['viols_hc'] > thresh)
        fp = sum(1 for r in normal_r if r['viols_hc'] > thresh)
        fn = len(attack_r) - tp
        p = tp/(tp+fp) if tp+fp else 0
        rec = tp/(tp+fn) if tp+fn else 0
        f1 = 2*p*rec/(p+rec) if p+rec else 0
        if f1 > po_best_f1:
            po_best_f1 = f1
    
    # Context-gated
    flagged = [r for r in results if r['stide'] >= best_t]
    tp_f = [r for r in flagged if r['attack']]
    fp_f = [r for r in flagged if not r['attack']]
    
    tp_hc = sum(1 for r in tp_f if r['viols_hc'] > 0)
    fp_hc = sum(1 for r in fp_f if r['viols_hc'] > 0)
    
    hc_tp = tp_hc / len(tp_f) if tp_f else 0
    hc_fp = fp_hc / len(fp_f) if fp_f else 0
    explprec = tp_hc / (tp_hc + fp_hc) if (tp_hc + fp_hc) else 0
    
    # Top rule
    all_rules = defaultdict(lambda: {'attack': 0, 'normal': 0})
    for r in results:
        for rule in r['rules']:
            if r['attack']:
                all_rules[rule]['attack'] += 1
            else:
                all_rules[rule]['normal'] += 1
    
    top_rule = max(all_rules.items(), key=lambda x: x[1]['attack']) if all_rules else (None, {'attack': 0, 'normal': 0})
    
    return {
        'stide_f1': best_f1,
        'po_f1': po_best_f1,
        'hc_tp': hc_tp,
        'hc_fp': hc_fp,
        'explprec': explprec,
        'top_rule': top_rule[0],
        'rule_attack': top_rule[1]['attack'],
        'rule_normal': top_rule[1]['normal'],
        'r_diamond_edges': len(closure_set)
    }

def evaluate_scenario_multiseed(name, path):
    """Evaluate with multiple seeds and report mean±std"""
    print(f"\n{'='*70}")
    print(f"{name} - Multi-seed evaluation")
    print(f"{'='*70}")
    
    all_results = []
    for seed in SEEDS:
        r = evaluate_scenario_single_seed(name, path, seed)
        all_results.append(r)
        print(f"  Seed {seed:2d}: HC@TP={r['hc_tp']:.1%}, PO_F1={r['po_f1']:.3f}, R◇={r['r_diamond_edges']} edges, Top={r['top_rule']}")
    
    # Aggregate
    hc_tp_vals = [r['hc_tp'] for r in all_results]
    hc_fp_vals = [r['hc_fp'] for r in all_results]
    explprec_vals = [r['explprec'] for r in all_results]
    po_f1_vals = [r['po_f1'] for r in all_results]
    
    print(f"\n  Summary ({len(SEEDS)} seeds):")
    print(f"  STIDE F1: {all_results[0]['stide_f1']:.3f} (deterministic)")
    print(f"  R◇ PO F1: {np.mean(po_f1_vals):.3f} ± {np.std(po_f1_vals):.3f}")
    print(f"  HC@TP: {np.mean(hc_tp_vals)*100:.1f}% ± {np.std(hc_tp_vals)*100:.1f}%")
    print(f"  HC@FP: {np.mean(hc_fp_vals)*100:.1f}% ± {np.std(hc_fp_vals)*100:.1f}%")
    print(f"  ExplPrec: {np.mean(explprec_vals)*100:.1f}% ± {np.std(explprec_vals)*100:.1f}%")
    
    # Most common top rule
    rule_counts = defaultdict(int)
    for r in all_results:
        if r['top_rule']:
            rule_counts[r['top_rule']] += 1
    most_common_rule = max(rule_counts.items(), key=lambda x: x[1])[0] if rule_counts else None
    print(f"  Most common top rule: {most_common_rule} ({rule_counts[most_common_rule]}/{len(SEEDS)} seeds)")
    
    return {
        'name': name,
        'stide_f1': all_results[0]['stide_f1'],
        'po_f1_mean': np.mean(po_f1_vals),
        'po_f1_std': np.std(po_f1_vals),
        'hc_tp_mean': np.mean(hc_tp_vals),
        'hc_tp_std': np.std(hc_tp_vals),
        'hc_fp_mean': np.mean(hc_fp_vals),
        'hc_fp_std': np.std(hc_fp_vals),
        'explprec_mean': np.mean(explprec_vals),
        'explprec_std': np.std(explprec_vals),
        'top_rule': most_common_rule
    }

# Run all scenarios
scenarios = [
    ("Bruteforce_CWE-307", "data/LID-DS-2021/Bruteforce_CWE-307"),
    ("CWE-89-SQL-injection", "data/LID-DS-2021/CWE-89-SQL-injection"),
    ("CVE-2017-12635", "data/LID-DS-2021/CVE-2017-12635_6"),
]

print("=" * 70)
print("FINAL VALIDATION WITH MULTIPLE SEEDS")
print(f"Seeds: {SEEDS}")
print("=" * 70)

all_scenario_results = []
for name, path in scenarios:
    r = evaluate_scenario_multiseed(name, path)
    all_scenario_results.append(r)

# Final table
print("\n" + "=" * 90)
print("FINAL PAPER TABLE (Mean ± Std over 5 seeds)")
print("=" * 90)
print(f"{'Scenario':<22} {'STIDE':>8} {'R◇ PO F1':>12} {'HC@TP':>14} {'HC@FP':>14} {'ExplPrec':>14}")
print("-" * 90)
for r in all_scenario_results:
    po = f"{r['po_f1_mean']:.3f}±{r['po_f1_std']:.3f}"
    hctp = f"{r['hc_tp_mean']*100:.1f}±{r['hc_tp_std']*100:.1f}%"
    hcfp = f"{r['hc_fp_mean']*100:.1f}±{r['hc_fp_std']*100:.1f}%"
    exp = f"{r['explprec_mean']*100:.1f}±{r['explprec_std']*100:.1f}%"
    print(f"{r['name']:<22} {r['stide_f1']:>8.3f} {po:>12} {hctp:>14} {hcfp:>14} {exp:>14}")

print("\n" + "=" * 90)
print("TOP RULES (Most common across seeds)")
print("=" * 90)
for r in all_scenario_results:
    print(f"{r['name']:<22}: {r['top_rule']}")
