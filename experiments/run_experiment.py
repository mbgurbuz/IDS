#!/usr/bin/env python3
"""
Main Experiment Runner
======================

LID-DS veri seti üzerinde explainable anomaly detection deneyi çalıştırır.

Kullanım:
    # Sentetik veri ile demo
    python run_experiment.py --demo
    
    # Tek senaryo
    python run_experiment.py --scenario CVE-2017-7529
    
    # Tüm senaryolar
    python run_experiment.py --all
"""

import sys
import os
import argparse
import json
import random
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src import (
    LIDDSDataLoader,
    PrecedenceExtractor,
    PartialOrderBuilder,
    AnomalyDetector,
    evaluate,
    Recording,
    Syscall,
    RecordingType
)
from config import Config, get_config


def print_header(text: str):
    """Print a header"""
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def run_experiment(
    training_recordings: list,
    test_recordings: list,
    config: Config,
    scenario_name: str = "experiment"
) -> dict:
    """
    Ana deney pipeline'ı
    
    1. Training: Normal veriden model oluştur
    2. Detection: Test verisinde anomali tespit et
    3. Evaluation: Metrikleri hesapla
    """
    
    results = {
        'scenario': scenario_name,
        'timestamp': datetime.now().isoformat(),
        'config': {
            'window_size': config.windowing.window_size,
            'delta_hops': config.windowing.delta_hops,
            'min_support': config.precedence.min_support,
            'theta': config.precedence.theta,
            'anomaly_threshold': config.detection.anomaly_threshold,
        }
    }
    
    # ========================================
    # ADIM 1: TRAINING - Precedence Extraction
    # ========================================
    print_header("STEP 1: PRECEDENCE EXTRACTION (Training)")
    
    print(f"Processing {len(training_recordings)} training recordings...")
    
    extractor = PrecedenceExtractor(
        window_size=config.windowing.window_size,
        overlap=config.windowing.overlap,
        delta_hops=config.windowing.delta_hops,
        min_support=config.precedence.min_support,
        theta=config.precedence.theta
    )
    
    # Training verisini işle
    for rec in training_recordings:
        extractor.process_recording(rec)
    
    # Precedence matrix oluştur
    probs, support, syscalls = extractor.get_precedence_matrix()
    stats = extractor.get_statistics()
    
    print(f"  Total syscalls: {stats['total_syscalls']}")
    print(f"  Total windows processed: {stats['total_windows']}")
    print(f"  Total pairs found: {stats['total_pairs']}")
    print(f"  Strong pairs (θ≥{config.precedence.theta}): {stats['strong_pairs']}")
    
    results['training'] = stats
    
    # ========================================
    # ADIM 2: PARTIAL ORDER MODEL
    # ========================================
    print_header("STEP 2: PARTIAL ORDER MODEL CONSTRUCTION")
    
    builder = PartialOrderBuilder(
        theta=config.precedence.theta,
        repair_method=config.partial_order.repair_method
    )
    
    model = builder.build(probs, support, syscalls)
    
    print(model.summary())
    
    results['model'] = {
        'nodes': len(model.nodes),
        'edges': len(model.edges),
        'hasse_edges': len(model.hasse_edges),
        'repair_method': model.repair_method,
    }
    
    # Model kaydet
    model_path = config.output_path / f"{scenario_name}_model.json"
    model.save(str(model_path))
    print(f"\nModel saved to: {model_path}")
    
    # ========================================
    # ADIM 3: ANOMALY DETECTION
    # ========================================
    print_header("STEP 3: ANOMALY DETECTION (Testing)")
    
    print(f"Testing {len(test_recordings)} recordings...")
    
    detector = AnomalyDetector(
        model=model,
        window_size=config.windowing.window_size,
        overlap=config.windowing.overlap,
        delta_hops=config.windowing.delta_hops,
        min_support=config.detection.min_violation_support,
        min_violation_prob=config.detection.min_violation_prob,
        anomaly_threshold=config.detection.anomaly_threshold
    )
    
    # Test recordings için label'ları hazırla
    labels = {}
    for rec in test_recordings:
        if rec.is_attack:
            labels[rec.recording_id] = "attack"
        else:
            labels[rec.recording_id] = "normal"
    
    # Tespit yap
    detection_results = detector.detect_batch(test_recordings, labels)
    
    # Sonuçları göster
    print("\nDetection Results:")
    print("-" * 40)
    
    for dr in detection_results:
        print(dr.get_summary())
    
    # ========================================
    # ADIM 4: EVALUATION
    # ========================================
    print_header("STEP 4: EVALUATION")
    
    metrics = evaluate(detection_results)
    print(metrics.report())
    
    results['evaluation'] = {
        'total': metrics.total,
        'true_positives': metrics.true_positives,
        'false_positives': metrics.false_positives,
        'true_negatives': metrics.true_negatives,
        'false_negatives': metrics.false_negatives,
        'precision': metrics.precision,
        'recall': metrics.recall,
        'f1_score': metrics.f1_score,
        'accuracy': metrics.accuracy,
    }
    
    # Detaylı sonuçları kaydet
    detections_path = config.output_path / f"{scenario_name}_detections.json"
    detection_data = []
    for dr in detection_results:
        detection_data.append({
            'recording_id': dr.recording_id,
            'is_anomaly': dr.is_anomaly,
            'anomaly_score': dr.anomaly_score,
            'true_label': dr.true_label,
            'violation_count': len(dr.violations),
            'violations': [
                {
                    'type': v.type.value,
                    'syscall_a': v.syscall_a,
                    'syscall_b': v.syscall_b,
                    'observed_prob': v.observed_prob,
                    'explanation': v.explain()
                }
                for v in dr.violations[:10]
            ]
        })
    
    with open(detections_path, 'w') as f:
        json.dump(detection_data, f, indent=2)
    print(f"\nDetections saved to: {detections_path}")
    
    # Ana sonuçları kaydet
    results_path = config.output_path / f"{scenario_name}_results.json"
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {results_path}")
    
    return results


def create_synthetic_demo_data():
    """
    Gerçekçi sentetik veri oluştur.
    
    LID-DS veri seti olmadan test için kullanılır.
    Gerçek syscall pattern'lerini taklit eder.
    """
    
    # Gerçekçi syscall pattern'leri (normal davranış)
    NORMAL_PATTERNS = [
        # Dosya okuma: openat -> read -> read -> close
        ['openat', 'read', 'read', 'read', 'close'],
        ['openat', 'fstat', 'read', 'close'],
        ['openat', 'read', 'close'],
        
        # Dosya yazma: openat -> write -> close
        ['openat', 'write', 'write', 'close'],
        ['openat', 'fstat', 'write', 'fsync', 'close'],
        
        # Network server: socket -> bind -> listen -> accept
        ['socket', 'setsockopt', 'bind', 'listen', 'accept'],
        ['socket', 'bind', 'listen', 'accept', 'read', 'write', 'close'],
        
        # Network client: socket -> connect -> write -> read
        ['socket', 'connect', 'write', 'read', 'close'],
        
        # Memory operations: mmap -> mprotect -> munmap
        ['mmap', 'mprotect', 'munmap'],
        ['brk', 'mmap', 'mprotect'],
        
        # Process: clone -> wait4
        ['clone', 'wait4'],
        ['fork', 'execve', 'wait4'],
        
        # Directory operations
        ['openat', 'getdents64', 'close'],
        ['stat', 'access', 'openat', 'read', 'close'],
    ]
    
    # Attack pattern'leri (tersine çevrilmiş veya anormal sıralar)
    ATTACK_PATTERNS = [
        # Tersine dosya işlemi (exploit sonrası cleanup)
        ['close', 'read', 'openat'],
        ['close', 'write', 'openat'],
        
        # Tersine network (backdoor pattern)
        ['accept', 'listen', 'bind', 'socket'],
        ['read', 'connect', 'socket'],
        
        # Tersine memory (ROP/JOP exploit)
        ['munmap', 'mprotect', 'mmap'],
        ['mprotect', 'mmap', 'execve'],
        
        # Anormal process spawning
        ['execve', 'clone', 'clone', 'execve'],
        
        # Shell spawn pattern
        ['socket', 'dup2', 'dup2', 'execve'],
    ]
    
    def create_recording(recording_id: str, patterns: list, 
                        is_attack: bool, num_patterns: int = 50) -> Recording:
        """Tek bir recording oluştur"""
        syscalls = []
        ts = 0.0
        
        for _ in range(num_patterns):
            pattern = random.choice(patterns)
            for sc_name in pattern:
                syscalls.append(Syscall(
                    timestamp=ts,
                    process_name="test_process",
                    process_id=random.randint(1000, 9999),
                    thread_id=random.randint(1, 10),
                    syscall_name=sc_name,
                    syscall_args="",
                    return_value="0"
                ))
                ts += random.uniform(0.0001, 0.001)
        
        return Recording(
            recording_id=recording_id,
            recording_type=RecordingType.TEST_ATTACK if is_attack else RecordingType.TRAINING,
            file_path=Path(f"/synthetic/{recording_id}"),
            syscalls=syscalls,
            scenario_name="synthetic_demo",
            is_attack=is_attack
        )
    
    # Training verileri (sadece normal)
    print("Creating synthetic training data...")
    training = []
    for i in range(10):
        rec = create_recording(f"train_{i:03d}", NORMAL_PATTERNS, is_attack=False, num_patterns=100)
        training.append(rec)
    
    # Test verileri (normal + attack)
    print("Creating synthetic test data...")
    test = []
    
    # Normal test recordings
    for i in range(5):
        rec = create_recording(f"test_normal_{i:03d}", NORMAL_PATTERNS, is_attack=False, num_patterns=50)
        rec.recording_type = RecordingType.TEST_NORMAL
        test.append(rec)
    
    # Attack test recordings
    for i in range(5):
        rec = create_recording(f"test_attack_{i:03d}", ATTACK_PATTERNS, is_attack=True, num_patterns=50)
        rec.recording_type = RecordingType.TEST_ATTACK
        test.append(rec)
    
    print(f"Created {len(training)} training recordings, {len(test)} test recordings")
    
    return training, test


def run_with_lidds(scenario: str, config: Config):
    """LID-DS veri seti ile çalıştır"""
    print_header(f"Loading LID-DS Scenario: {scenario}")
    
    try:
        loader = LIDDSDataLoader(str(config.data_path))
        
        # Mevcut senaryoları göster
        scenarios = loader.list_scenarios()
        if not scenarios:
            print(f"No scenarios found in {config.data_path}")
            print("Please download LID-DS from:")
            print("  https://drive.proton.me/urls/BWKRGQK994#fCK9JKL93Sjm")
            return None
        
        print(f"Available scenarios: {scenarios}")
        
        if scenario not in scenarios:
            print(f"Scenario '{scenario}' not found!")
            return None
        
        # Veriyi yükle
        training = list(loader.training_data(scenario))
        test = list(loader.test_data(scenario))
        
        print(f"Loaded {len(training)} training recordings")
        print(f"Loaded {len(test)} test recordings")
        
        # İstatistikleri göster
        stats = loader.get_statistics(scenario)
        print(f"\nScenario Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        return run_experiment(training, test, config, scenario)
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None


def run_demo(config: Config):
    """Sentetik veri ile demo çalıştır"""
    print_header("DEMO MODE: Using Synthetic Data")
    
    training, test = create_synthetic_demo_data()
    return run_experiment(training, test, config, "synthetic_demo")


def main():
    parser = argparse.ArgumentParser(
        description="Explainable Anomaly Detection Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run demo with synthetic data
  python run_experiment.py --demo
  
  # Run with specific LID-DS scenario
  python run_experiment.py --scenario CVE-2017-7529
  
  # Run with custom parameters
  python run_experiment.py --demo --window_size 50 --theta 0.8
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--demo', action='store_true',
                           help='Run demo with synthetic data')
    mode_group.add_argument('--scenario', type=str,
                           help='LID-DS scenario name')
    mode_group.add_argument('--all', action='store_true',
                           help='Run all available scenarios')
    
    # Data path
    parser.add_argument('--data_path', type=str, default='data/LID-DS-2021',
                       help='Path to LID-DS dataset')
    
    # Parameters
    parser.add_argument('--window_size', type=int, default=100,
                       help='Window size (number of syscalls)')
    parser.add_argument('--delta_hops', type=int, default=50,
                       help='Maximum hop distance')
    parser.add_argument('--min_support', type=int, default=30,
                       help='Minimum support threshold')
    parser.add_argument('--theta', type=float, default=0.7,
                       help='Direction threshold')
    parser.add_argument('--anomaly_threshold', type=float, default=0.3,
                       help='Anomaly score threshold')
    
    # Output
    parser.add_argument('--output', type=str, default='results',
                       help='Output directory')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Config oluştur
    config = get_config("default")
    config.data_path = Path(args.data_path)
    config.output_path = Path(args.output)
    config.output_path.mkdir(parents=True, exist_ok=True)
    
    # Parametreleri güncelle
    config.windowing.window_size = args.window_size
    config.windowing.delta_hops = args.delta_hops
    config.precedence.min_support = args.min_support
    config.precedence.theta = args.theta
    config.detection.anomaly_threshold = args.anomaly_threshold
    
    print_header("EXPLAINABLE ANOMALY DETECTION FOR CONTAINER SECURITY")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Output: {config.output_path}")
    
    # Çalıştır
    if args.demo:
        results = run_demo(config)
    elif args.scenario:
        results = run_with_lidds(args.scenario, config)
    elif args.all:
        print("Running all scenarios...")
        try:
            loader = LIDDSDataLoader(str(config.data_path))
            scenarios = loader.list_scenarios()
            for scenario in scenarios:
                print(f"\n{'#'*60}")
                print(f"# Scenario: {scenario}")
                print(f"{'#'*60}")
                run_with_lidds(scenario, config)
        except FileNotFoundError:
            print("LID-DS dataset not found. Running demo instead.")
            results = run_demo(config)
    
    print_header("EXPERIMENT COMPLETE")


if __name__ == "__main__":
    main()
