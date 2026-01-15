"""Check Bruteforce results"""
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

scenario = Path("data/LID-DS-2021/Bruteforce_CWE-307")
train_files = list(scenario.glob("training/*.zip"))[:10]
normal_files = list(scenario.glob("test/normal/*.zip"))[:10]
attack_files = list(scenario.glob("test/normal_and_attack/*.zip"))[:10]

print("=== TRAINING ===")
for zf in train_files[:3]:
    syscalls = load_syscalls(zf)
    unique = set(syscalls)
    print(f"{zf.name}: {len(syscalls)} syscalls, {len(unique)} unique")
    print(f"  Top: {sorted([(s, syscalls.count(s)) for s in unique], key=lambda x:-x[1])[:5]}")

print("\n=== NORMAL ===")
for zf in normal_files[:3]:
    syscalls = load_syscalls(zf)
    unique = set(syscalls)
    has_shutdown = 'shutdown' in syscalls
    has_stat = 'stat' in syscalls
    print(f"{zf.name}: {len(syscalls)} syscalls, shutdown={has_shutdown}, stat={has_stat}")

print("\n=== ATTACK ===")
for zf in attack_files[:3]:
    syscalls = load_syscalls(zf)
    unique = set(syscalls)
    has_shutdown = 'shutdown' in syscalls
    has_stat = 'stat' in syscalls
    # Check order of shutdown and stat
    if has_shutdown and has_stat:
        shut_idx = syscalls.index('shutdown')
        stat_idx = syscalls.index('stat')
        print(f"{zf.name}: {len(syscalls)} syscalls, shutdown@{shut_idx}, stat@{stat_idx}, order={'shutdown<stat' if shut_idx < stat_idx else 'stat<shutdown'}")
    else:
        print(f"{zf.name}: {len(syscalls)} syscalls, shutdown={has_shutdown}, stat={has_stat}")

# Check the rule: shutdown < stat
# Model says: shutdown should come BEFORE stat
# If attack VIOLATES this: stat comes before shutdown

print("\n=== DETAILED CHECK ===")
print("Model rule: shutdown < stat (shutdown should precede stat)")
print("Violation: stat → shutdown observed\n")

def count_pairs_specific(syscalls, a, b):
    """Count how often a->b vs b->a in window"""
    ab, ba = 0, 0
    for i, s in enumerate(syscalls):
        if s == a:
            for j in range(i+1, min(i+16, len(syscalls))):
                if syscalls[j] == b:
                    ab += 1
                    break
        if s == b:
            for j in range(i+1, min(i+16, len(syscalls))):
                if syscalls[j] == a:
                    ba += 1
                    break
    return ab, ba

print("Normal files - shutdown/stat order:")
for zf in normal_files[:5]:
    syscalls = load_syscalls(zf)
    shut_stat, stat_shut = count_pairs_specific(syscalls, 'shutdown', 'stat')
    total = shut_stat + stat_shut
    if total > 0:
        print(f"  {zf.name}: shutdown→stat={shut_stat}, stat→shutdown={stat_shut}, ratio={stat_shut/total:.1%}")

print("\nAttack files - shutdown/stat order:")
for zf in attack_files[:5]:
    syscalls = load_syscalls(zf)
    shut_stat, stat_shut = count_pairs_specific(syscalls, 'shutdown', 'stat')
    total = shut_stat + stat_shut
    if total > 0:
        print(f"  {zf.name}: shutdown→stat={shut_stat}, stat→shutdown={stat_shut}, ratio={stat_shut/total:.1%}")
