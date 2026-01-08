"""
Simple STIDE (Sequence Time-Delay Embedding) Implementation
Based on LID-DS example
"""
import zipfile
from pathlib import Path
from collections import defaultdict
from pprint import pprint

def parse_sc_file(zip_path):
    syscalls = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            sc_files = [f for f in zf.namelist() if f.endswith('.sc')]
            if not sc_files:
                return syscalls
            with zf.open(sc_files[0]) as f:
                for line in f:
                    line = line.decode('utf-8', errors='ignore').strip()
                    parts = line.split()
                    if len(parts) >= 7 and parts[6] == '<':  # Sadece closing calls
                        syscalls.append(parts[5])  # syscall name
    except:
        pass
    return syscalls

def get_ngrams(syscalls, n=7):
    ngrams = []
    for i in range(len(syscalls) - n + 1):
        ngram = tuple(syscalls[i:i+n])
        ngrams.append(ngram)
    return ngrams

def train_stide(training_dir, ngram_length=7):
    normal_ngrams = set()
    
    zip_files = list(Path(training_dir).glob("*.zip"))
    print(f"Training on {len(zip_files)} files...")
    
    for zf in zip_files:
        syscalls = parse_sc_file(zf)
        ngrams = get_ngrams(syscalls, ngram_length)
        normal_ngrams.update(ngrams)
    
    print(f"Learned {len(normal_ngrams)} unique normal n-grams")
    return normal_ngrams

def detect_stide(test_dir, normal_ngrams, ngram_length=7, window_size=100):
    results = []
    
    zip_files = list(Path(test_dir).glob("*.zip"))
    
    for zf in zip_files:
        syscalls = parse_sc_file(zf)
        ngrams = get_ngrams(syscalls, ngram_length)
        
        if not ngrams:
            continue
        
        mismatches = sum(1 for ng in ngrams if ng not in normal_ngrams)
        mismatch_rate = mismatches / len(ngrams) if ngrams else 0
        
        results.append({
            'file': zf.name,
            'total_ngrams': len(ngrams),
            'mismatches': mismatches,
            'mismatch_rate': mismatch_rate
        })
    
    return results

def evaluate(normal_results, attack_results, threshold):
    tp = sum(1 for r in attack_results if r['mismatch_rate'] > threshold)
    fn = len(attack_results) - tp
    fp = sum(1 for r in normal_results if r['mismatch_rate'] > threshold)
    tn = len(normal_results) - fp
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'threshold': threshold,
        'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'accuracy': round((tp + tn) / (tp + tn + fp + fn), 4)
    }

if __name__ == '__main__':
    # Paths
    scenario = "data/LID-DS-2021/Bruteforce_CWE-307"
    training_dir = f"{scenario}/training"
    test_normal_dir = f"{scenario}/test/normal"
    test_attack_dir = f"{scenario}/test/normal_and_attack"
    
    # Train
    print("=== TRAINING ===")
    normal_ngrams = train_stide(training_dir, ngram_length=7)
    
    # Detect
    print("\n=== DETECTION ===")
    normal_results = detect_stide(test_normal_dir, normal_ngrams)
    attack_results = detect_stide(test_attack_dir, normal_ngrams)
    
    print(f"Normal test files: {len(normal_results)}")
    print(f"Attack test files: {len(attack_results)}")
    
    # Score
    normal_scores = [r['mismatch_rate'] for r in normal_results]
    attack_scores = [r['mismatch_rate'] for r in attack_results]
    
    print(f"\nNormal mismatch rate - min: {min(normal_scores):.4f}, max: {max(normal_scores):.4f}, avg: {sum(normal_scores)/len(normal_scores):.4f}")
    print(f"Attack mismatch rate - min: {min(attack_scores):.4f}, max: {max(attack_scores):.4f}, avg: {sum(attack_scores)/len(attack_scores):.4f}")
    
    # Different Thresolds
    print("\n=== EVALUATION ===")
    for thresh in [0.01, 0.02, 0.03, 0.05, 0.1, 0.15, 0.2]:
        result = evaluate(normal_results, attack_results, thresh)
        print(f"Threshold {thresh}: P={result['precision']}, R={result['recall']}, F1={result['f1']}")
