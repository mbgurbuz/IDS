"""Full validation of Bruteforce results"""
import zipfile
from pathlib import Path
from collections import defaultdict

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

def count_pair_ratio(syscalls, a, b, delta=15):
    """Count ratio of b→a vs a→b"""
    ab, ba = 0, 0
    for i, s in enumerate(syscalls):
        if s == a:
            for j in range(i+1, min(i+delta+1, len(syscalls))):
                if syscalls[j] == b:
                    ab += 1
                    break
        elif s == b:
            for j in range(i+1, min(i+delta+1, len(syscalls))):
                if syscalls[j] == a:
                    ba += 1
                    break
    total = ab + ba
    return ba / total if total >= 10 else None  # Only if enough support

scenario = Path("data/LID-DS-2021/Bruteforce_CWE-307")
normal_files = list(scenario.glob("test/normal/*.zip"))
attack_files = list(scenario.glob("test/normal_and_attack/*.zip"))

print("=" * 70)
print("VALIDATION 1: stat→shutdown ratio >= 0.6 across ALL files")
print("=" * 70)

# Check shutdown<stat rule (violation = stat→shutdown >= 0.6)
normal_violations = 0
normal_with_data = 0
attack_violations = 0
attack_with_data = 0

print(f"\nChecking {len(normal_files)} normal files...")
for zf in normal_files:
    syscalls = load_syscalls(zf)
    ratio = count_pair_ratio(syscalls, 'shutdown', 'stat')
    if ratio is not None:
        normal_with_data += 1
        if ratio >= 0.6:
            normal_violations += 1

print(f"Normal: {normal_violations}/{normal_with_data} files have stat→shutdown >= 60%")
print(f"        = {normal_violations/normal_with_data*100:.1f}% violation rate" if normal_with_data else "")

print(f"\nChecking {len(attack_files)} attack files...")
for zf in attack_files:
    syscalls = load_syscalls(zf)
    ratio = count_pair_ratio(syscalls, 'shutdown', 'stat')
    if ratio is not None:
        attack_with_data += 1
        if ratio >= 0.6:
            attack_violations += 1

print(f"Attack: {attack_violations}/{attack_with_data} files have stat→shutdown >= 60%")
print(f"        = {attack_violations/attack_with_data*100:.1f}% violation rate" if attack_with_data else "")

# Precision of this single rule
if normal_violations + attack_violations > 0:
    precision = attack_violations / (attack_violations + normal_violations)
    print(f"\nRule precision: {precision:.1%}")

print("\n" + "=" * 70)
print("VALIDATION 2: Are there other discriminative rules?")
print("=" * 70)

# Top rules from R◇ that might be discriminative
# Check multiple rules
rules_to_check = [
    ('shutdown', 'stat'),
    ('poll', 'shutdown'),
    ('rt_sigprocmask', 'lstat'),
    ('shutdown', 'epoll_wait'),
    ('close', 'shutdown'),
]

print(f"\n{'Rule':<25} {'Normal Viol':<12} {'Attack Viol':<12} {'Precision':<10}")
print("-" * 60)

for a, b in rules_to_check:
    n_viol = 0
    n_total = 0
    a_viol = 0
    a_total = 0
    
    for zf in normal_files:
        syscalls = load_syscalls(zf)
        ratio = count_pair_ratio(syscalls, a, b)
        if ratio is not None:
            n_total += 1
            if ratio >= 0.6:
                n_viol += 1
    
    for zf in attack_files:
        syscalls = load_syscalls(zf)
        ratio = count_pair_ratio(syscalls, a, b)
        if ratio is not None:
            a_total += 1
            if ratio >= 0.6:
                a_viol += 1
    
    if n_viol + a_viol > 0:
        prec = a_viol / (a_viol + n_viol)
        print(f"{a}<{b:<15} {n_viol:>4}/{n_total:<6} {a_viol:>4}/{a_total:<6} {prec:>8.1%}")
    else:
        print(f"{a}<{b:<15} {n_viol:>4}/{n_total:<6} {a_viol:>4}/{a_total:<6} {'N/A':>8}")

print("\n" + "=" * 70)
print("CONCLUSION")
print("=" * 70)
if normal_violations == 0 and attack_violations > attack_with_data * 0.9:
    print("✅ STRONG: shutdown<stat rule is highly discriminative")
    print(f"   - 0 false positives in {normal_with_data} normal files")
    print(f"   - {attack_violations}/{attack_with_data} attacks detected")
elif normal_violations < normal_with_data * 0.05:
    print("✅ GOOD: Rule has low false positive rate")
else:
    print("⚠️ CAUTION: Rule has notable false positives")
    print("   Consider adding to limitations section")
