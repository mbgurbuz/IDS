"""
Configuration parameters for Explainable Anomaly Detection
Based on the paper methodology (Section III)
"""

from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class WindowingConfig:
    """
    Windowing parameters (Paper Section III-B-1)
    """
    # W: Window size (number of syscalls or seconds)
    window_size: int = 100
    
    # Overlap ratio between consecutive windows (0.0 - 1.0)
    overlap: float = 0.5
    
    # Δ (delta_hops): Maximum hop distance for pair counting
    # "we only count a → b when the two events occur within at most Δ calls"
    delta_hops: int = 50


@dataclass
class PrecedenceConfig:
    """
    Pairwise precedence extraction parameters (Paper Section III-B-2, III-B-3)
    """
    # τ (min_support): Minimum support threshold
    # "discarding pairs with insufficient evidence"
    min_support: int = 30
    
    # θ (theta): Direction threshold for edge inclusion
    # "Dominant direction threshold"
    theta: float = 0.7
    
    # δ (ambiguity_band): Near-neutral threshold (not near 50:50)
    # If |P(a→b) - 0.5| < ambiguity_band, abstain
    ambiguity_band: float = 0.1


@dataclass
class PartialOrderConfig:
    """
    Partial Order model parameters (Paper Section III-D)
    """
    # Repair method: "baseline", "rdiamond", "schroeder"
    # R◇ is recommended in the paper
    repair_method: str = "rdiamond"
    
    # Whether to compute transitive reduction (Hasse diagram)
    compute_hasse: bool = True


@dataclass
class DetectionConfig:
    """
    Anomaly detection parameters (Paper Section III-E, III-F)
    """
    # η (anomaly_threshold): Window anomaly score threshold
    anomaly_threshold: float = 0.3
    
    # K: Number of consecutive violating windows for debouncing
    consecutive_windows: int = 1
    
    # Minimum probability for violation detection
    min_violation_prob: float = 0.6
    
    # τv: Minimum support for violation evidence
    min_violation_support: int = 10


@dataclass
class Config:
    """
    Main configuration class combining all parameters
    """
    # Sub-configurations
    windowing: WindowingConfig = None
    precedence: PrecedenceConfig = None
    partial_order: PartialOrderConfig = None
    detection: DetectionConfig = None
    
    # Data paths
    data_path: Path = Path("data/LID-DS-2021")
    output_path: Path = Path("results")
    
    # Scenario to run (or "all")
    scenario: str = "CVE-2017-7529"
    
    # Verbosity
    verbose: bool = True
    
    def __post_init__(self):
        if self.windowing is None:
            self.windowing = WindowingConfig()
        if self.precedence is None:
            self.precedence = PrecedenceConfig()
        if self.partial_order is None:
            self.partial_order = PartialOrderConfig()
        if self.detection is None:
            self.detection = DetectionConfig()
            
        # Ensure output directory exists
        self.output_path.mkdir(parents=True, exist_ok=True)


# Pre-defined configurations for different use cases

# Default configuration (balanced)
DEFAULT_CONFIG = Config()

# High sensitivity (catches more anomalies, may have more false positives)
HIGH_SENSITIVITY_CONFIG = Config(
    windowing=WindowingConfig(window_size=50, delta_hops=30),
    precedence=PrecedenceConfig(min_support=15, theta=0.6),
    detection=DetectionConfig(anomaly_threshold=0.2, min_violation_prob=0.5)
)

# High specificity (fewer false positives, may miss some anomalies)
HIGH_SPECIFICITY_CONFIG = Config(
    windowing=WindowingConfig(window_size=200, delta_hops=100),
    precedence=PrecedenceConfig(min_support=50, theta=0.8),
    detection=DetectionConfig(anomaly_threshold=0.5, min_violation_prob=0.75)
)


def get_config(preset: str = "default") -> Config:
    """Get a pre-defined configuration"""
    configs = {
        "default": DEFAULT_CONFIG,
        "high_sensitivity": HIGH_SENSITIVITY_CONFIG,
        "high_specificity": HIGH_SPECIFICITY_CONFIG,
    }
    return configs.get(preset, DEFAULT_CONFIG)
