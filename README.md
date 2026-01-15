# Hybrid Syscall Modeling for Explainable Container Runtime Security

This repository contains the implementation for the paper "Hybrid Syscall Modeling for Explainable Container Runtime Security" (LNCS 2025).

## Overview

We present a hybrid approach that separates **detection** from **explanation**:
- **STIDE**: Lightweight n-gram model for anomaly detection
- **R◇ Partial Order**: Provides human-readable explanations via syscall precedence violations

## Results Summary

| Scenario | STIDE F1 | R◇ PO F1 | HC@TP | ExplPrec | Top Rule |
|----------|----------|----------|-------|----------|----------|
| CVE-2017-12635 (CouchDB) | 0.992 | 0.972±0.002 | 99.1% | 100% | munmap < mprotect |
| Bruteforce_CWE-307 | 0.972 | 0.902±0.184 | 88.0% | 100% | shutdown < stat |
| CWE-89-SQL-injection | 0.835 | 0.603±0.148 | 56.8% | 93% | pwrite < write |

## Project Structure
```
explainable_ids/
├── README.md
├── requirements.txt
├── config.py                      # Hyperparameters
├── final_validation_multiseed.py  # Main evaluation (5-seed)
├── rdiamond_couchdb.py            # CouchDB detailed analysis
├── rdiamond_others.py             # Bruteforce + SQL analysis
├── validate_bruteforce.py         # Bruteforce rule validation
├── validate_sql_fixed.py          # SQL rule validation
├── check_bruteforce.py            # Bruteforce sanity check
├── simple_stide.py                # STIDE baseline
└── data/
    └── LID-DS-2021/               # Dataset (download separately)
```

## Installation
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Dataset

Download LID-DS 2021 from: https://github.com/LID-DS/LID-DS

Extract to `data/LID-DS-2021/`:
```
data/LID-DS-2021/
├── CVE-2017-12635_6/
├── Bruteforce_CWE-307/
└── CWE-89-SQL-injection/
```

## Usage

### Run Full Evaluation (5 seeds)
```bash
python final_validation_multiseed.py
```

### Run Individual Scenario Analysis
```bash
# CouchDB (Privilege Escalation)
python rdiamond_couchdb.py

# Bruteforce + SQL-Injection
python rdiamond_others.py
```

### Validate Specific Rules
```bash
python validate_bruteforce.py
python validate_sql_fixed.py
```

## Methodology

### 1. STIDE Detection
- Extract 5-gram syscall sequences from training data
- Flag test traces with unseen n-grams above threshold

### 2. R◇ Partial Order Construction
- Count pairwise syscall precedences within δ-hop window
- Build relation R with high-confidence edges (θ ≥ 0.75)
- Apply R◇ algorithm to obtain consistent partial order:
  1. Break cycles by removing random edges
  2. Re-add edges while maintaining acyclicity
  3. Compute transitive closure

### 3. Violation Detection
- For each test trace, identify precedence violations
- High-confidence (HC) violation: observed order contradicts model edge with confidence ≥ 0.80

### 4. Explainability Metrics
- **HC@TP**: % of true positive alerts with ≥1 HC violation
- **HC@FP**: % of false positive alerts with ≥1 HC violation  
- **ExplPrec**: Precision of HC violations as attack indicators

## Hyperparameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| n (STIDE) | 5 | N-gram length |
| δ (delta) | 15 | Maximum hop distance |
| τ (min_support) | 30 | Minimum pair occurrences |
| θ_edge | 0.75 | Edge confidence threshold |
| θ_obs | 0.60 | Observed ratio threshold |
| θ_model | 0.80 | Model confidence threshold |

## Key Findings

1. **CVE-2017-12635**: Rule `munmap < mprotect` detects memory protection bypass with 100% precision
2. **Bruteforce**: Rule `shutdown < stat` captures login retry pattern
3. **SQL-Injection**: Lower coverage but high precision when violations detected

## Citation
```bibtex
@inproceedings{janicki2025hybrid,
  title={Hybrid Syscall Modeling for Explainable Container Runtime Security},
  author={Janicki, Ryszard and Gurbuz, Muhammet Bekir},
  booktitle={Lecture Notes in Computer Science},
  year={2025},
  publisher={Springer}
}
```

## References

- Janicki, R., Liu, T. "On Approximations of Arbitrary Relations by Partial Orders"
- LID-DS 2021 Dataset: Grimmer et al., CRITIS 2022

