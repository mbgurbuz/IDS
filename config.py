"""
Hyperparameters for Hybrid Syscall Anomaly Detection
"""

# STIDE Parameters
STIDE_N = 5  # N-gram length

# R◇ Training Parameters
DELTA = 15           # Maximum hop distance for pair counting
MIN_SUPPORT = 30     # Minimum pair occurrences to consider
THETA_EDGE = 0.75    # Edge confidence threshold for building R

# R◇ Testing Parameters  
THETA_OBS = 0.60     # Observed ratio threshold for violation
THETA_MODEL = 0.80   # Model confidence threshold for HC violation

# Evaluation
SEEDS = [42, 7, 13, 21, 99]  # Random seeds for R◇ stability analysis

# Dataset paths
DATA_DIR = "data/LID-DS-2021"
SCENARIOS = {
    "CVE-2017-12635": "CVE-2017-12635_6",
    "Bruteforce": "Bruteforce_CWE-307",
    "SQL-Injection": "CWE-89-SQL-injection",
}
