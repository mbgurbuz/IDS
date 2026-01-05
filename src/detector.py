"""
Anomaly Detector and Explainer
==============================

Partial Order modeline göre anomali tespiti ve açıklaması.

Paper Section III-E: "Partial Order Violations"
Paper Section III-F: "Anomaly Detection and Explainability"
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set, Optional, Any
from enum import Enum

from .data_loader import Recording, Syscall
from .precedence_extractor import PrecedenceExtractor
from .partial_order import PartialOrderModel


class ViolationType(Enum):
    """
    İhlal türleri (Paper Section III-E-2)
    """
    # Model a→b diyor, ama b→a gözlemlendi
    ORDER_INVERSION = "order_inversion"
    
    # A<B<C varken C→A gözlemlendi
    TRANSITIVITY_BREAK = "transitivity_break"
    
    # Modelde olmayan yeni güçlü ilişki
    NOVEL_PRECEDENCE = "novel_precedence"


@dataclass
class Violation:
    """
    Tespit edilen bir ihlal
    
    Paper Section III-E-1: "Definition of a Violation"
    """
    type: ViolationType
    
    # İhlal eden syscall çifti
    syscall_a: str
    syscall_b: str
    
    # Model beklentisi
    expected_direction: str  # "a→b"
    
    # Gözlemlenen yön
    observed_direction: str  # "b→a"
    
    # Gözlemlenen olasılık (güven)
    observed_prob: float
    
    # Destek sayısı
    support: int
    
    # Hangi pencerede tespit edildi
    window_id: int = 0
    
    # Ek bağlam
    context: Dict[str, Any] = field(default_factory=dict)
    
    def explain(self) -> str:
        """
        İnsan-okunabilir açıklama üret.
        
        Paper Section III-F: "Anomaly Detection and Explainability"
        """
        if self.type == ViolationType.ORDER_INVERSION:
            return (
                f"⚠️  ORDER INVERSION: "
                f"Expected '{self.syscall_a}' → '{self.syscall_b}', "
                f"but observed '{self.syscall_b}' → '{self.syscall_a}' "
                f"(confidence: {self.observed_prob:.1%}, support: {self.support})"
            )
        
        elif self.type == ViolationType.TRANSITIVITY_BREAK:
            return (
                f"⚠️  TRANSITIVITY BREAK: "
                f"Model implies '{self.syscall_a}' < '{self.syscall_b}' chain, "
                f"but observed violation "
                f"(confidence: {self.observed_prob:.1%})"
            )
        
        elif self.type == ViolationType.NOVEL_PRECEDENCE:
            return (
                f"ℹ️  NOVEL PRECEDENCE: "
                f"New strong relation '{self.syscall_a}' → '{self.syscall_b}' "
                f"not in model (confidence: {self.observed_prob:.1%})"
            )
        
        return f"Unknown violation: {self.type}"
    
    def explain_turkish(self) -> str:
        """Türkçe açıklama"""
        if self.type == ViolationType.ORDER_INVERSION:
            return (
                f"⚠️  SIRA İHLALİ: "
                f"Model '{self.syscall_a}' → '{self.syscall_b}' bekliyor, "
                f"ancak '{self.syscall_b}' → '{self.syscall_a}' gözlemlendi "
                f"(güven: {self.observed_prob:.1%}, destek: {self.support})"
            )
        
        elif self.type == ViolationType.TRANSITIVITY_BREAK:
            return (
                f"⚠️  GEÇİŞLİLİK İHLALİ: "
                f"Model '{self.syscall_a}' < '{self.syscall_b}' zincirini öngörüyor, "
                f"ancak ihlal gözlemlendi "
                f"(güven: {self.observed_prob:.1%})"
            )
        
        elif self.type == ViolationType.NOVEL_PRECEDENCE:
            return (
                f"ℹ️  YENİ İLİŞKİ: "
                f"Modelde olmayan güçlü ilişki: '{self.syscall_a}' → '{self.syscall_b}' "
                f"(güven: {self.observed_prob:.1%})"
            )
        
        return f"Bilinmeyen ihlal: {self.type}"


@dataclass
class DetectionResult:
    """
    Bir recording için tespit sonucu
    """
    recording_id: str
    is_anomaly: bool
    anomaly_score: float
    violations: List[Violation]
    
    # Ground truth (varsa)
    true_label: str = "unknown"  # "normal" veya "attack"
    
    # İstatistikler
    total_windows: int = 0
    violating_windows: int = 0
    
    def is_correct(self) -> Optional[bool]:
        """Tespit doğru mu? (ground truth varsa)"""
        if self.true_label == "unknown":
            return None
        
        if self.true_label == "attack":
            return self.is_anomaly  # TP veya FN
        else:
            return not self.is_anomaly  # TN veya FP
    
    def get_summary(self) -> str:
        """Özet rapor"""
        status = "🔴 ANOMALY" if self.is_anomaly else "🟢 NORMAL"
        
        lines = [
            f"{'='*60}",
            f"Recording: {self.recording_id}",
            f"Status: {status} (score: {self.anomaly_score:.4f})",
            f"True Label: {self.true_label}",
            f"Violations: {len(self.violations)}",
            f"Windows: {self.violating_windows}/{self.total_windows} violating",
        ]
        
        if self.violations:
            lines.append("-" * 40)
            # İlk 5 ihlali göster
            for v in self.violations[:5]:
                lines.append(f"  • {v.explain()}")
            
            if len(self.violations) > 5:
                lines.append(f"  ... and {len(self.violations) - 5} more violations")
        
        lines.append("=" * 60)
        return "\n".join(lines)


class AnomalyDetector:
    """
    Partial Order modeline göre anomali dedektörü.
    
    Paper Section III-E and III-F
    """
    
    def __init__(
        self,
        model: PartialOrderModel,
        window_size: int = 100,
        overlap: float = 0.5,
        delta_hops: int = 50,
        min_support: int = 10,
        min_violation_prob: float = 0.6,
        anomaly_threshold: float = 0.3
    ):
        """
        Args:
            model: Eğitilmiş Partial Order modeli
            window_size: Pencere boyutu
            overlap: Pencere örtüşme oranı
            delta_hops: Maksimum hop mesafesi
            min_support: Minimum destek eşiği (ihlal için)
            min_violation_prob: Minimum ihlal olasılığı
            anomaly_threshold: Anomali skoru eşiği
        """
        self.model = model
        self.window_size = window_size
        self.overlap = overlap
        self.delta_hops = delta_hops
        self.min_support = min_support
        self.min_violation_prob = min_violation_prob
        self.anomaly_threshold = anomaly_threshold
    
    def _create_windows(self, syscalls: List[Syscall]) -> List[List[Syscall]]:
        """Syscall listesini pencerelere böl"""
        windows = []
        step = max(1, int(self.window_size * (1.0 - self.overlap)))
        
        for start in range(0, len(syscalls), step):
            end = min(start + self.window_size, len(syscalls))
            window = syscalls[start:end]
            if window:
                windows.append(window)
        
        return windows
    
    def _count_pairs_in_window(
        self, 
        window: List[Syscall]
    ) -> Dict[Tuple[str, str], int]:
        """Penceredeki çiftleri say"""
        counts: Dict[Tuple[str, str], int] = defaultdict(int)
        previous: deque = deque(maxlen=self.delta_hops)
        
        for syscall in window:
            current = syscall.syscall_name
            for prev in previous:
                if prev != current:
                    counts[(prev, current)] += 1
            previous.append(current)
        
        return dict(counts)
    
    def _detect_violations_in_window(
        self, 
        window: List[Syscall],
        window_id: int
    ) -> List[Violation]:
        """
        Tek bir pencerede ihlalleri tespit et.
        
        Paper Section III-E-1: "Definition of a Violation"
        """
        violations = []
        pair_counts = self._count_pairs_in_window(window)
        
        # Her unique çift için kontrol
        checked_pairs: Set[frozenset] = set()
        
        for (a, b), ab_count in pair_counts.items():
            pair_key = frozenset([a, b])
            if pair_key in checked_pairs:
                continue
            checked_pairs.add(pair_key)
            
            # Ters yönü al
            ba_count = pair_counts.get((b, a), 0)
            total = ab_count + ba_count
            
            # Minimum destek kontrolü
            if total < self.min_support:
                continue
            
            # Gözlemlenen olasılıklar
            prob_ab = ab_count / (total + 1e-9)
            prob_ba = ba_count / (total + 1e-9)
            
            # 1. ORDER INVERSION: Model a→b diyor, ama b→a gözlemlendi
            if self.model.precedes(a, b):
                if prob_ba >= self.min_violation_prob:
                    violations.append(Violation(
                        type=ViolationType.ORDER_INVERSION,
                        syscall_a=a,
                        syscall_b=b,
                        expected_direction=f"{a}→{b}",
                        observed_direction=f"{b}→{a}",
                        observed_prob=prob_ba,
                        support=total,
                        window_id=window_id,
                        context={'ab_count': ab_count, 'ba_count': ba_count}
                    ))
            
            elif self.model.precedes(b, a):
                if prob_ab >= self.min_violation_prob:
                    violations.append(Violation(
                        type=ViolationType.ORDER_INVERSION,
                        syscall_a=b,
                        syscall_b=a,
                        expected_direction=f"{b}→{a}",
                        observed_direction=f"{a}→{b}",
                        observed_prob=prob_ab,
                        support=total,
                        window_id=window_id,
                        context={'ab_count': ab_count, 'ba_count': ba_count}
                    ))
            
            # 2. NOVEL PRECEDENCE: Modelde karşılaştırılamaz ama güçlü yön var
            elif self.model.are_incomparable(a, b):
                if prob_ab >= self.min_violation_prob:
                    violations.append(Violation(
                        type=ViolationType.NOVEL_PRECEDENCE,
                        syscall_a=a,
                        syscall_b=b,
                        expected_direction="incomparable",
                        observed_direction=f"{a}→{b}",
                        observed_prob=prob_ab,
                        support=total,
                        window_id=window_id
                    ))
                elif prob_ba >= self.min_violation_prob:
                    violations.append(Violation(
                        type=ViolationType.NOVEL_PRECEDENCE,
                        syscall_a=b,
                        syscall_b=a,
                        expected_direction="incomparable",
                        observed_direction=f"{b}→{a}",
                        observed_prob=prob_ba,
                        support=total,
                        window_id=window_id
                    ))
        
        return violations
    
    def _compute_anomaly_score(self, violations: List[Violation]) -> float:
        """
        İhlallerden anomali skoru hesapla.
        
        Paper Section III-E-1: "Window score"
        
        Sadece UNIQUE violation çiftlerini say ve 
        ORDER_INVERSION'a odaklan.
        """
        if not violations:
            return 0.0
        
        # Unique violation çiftlerini bul (syscall_a, syscall_b, type)
        unique_violations = {}
        for v in violations:
            key = (v.syscall_a, v.syscall_b, v.type)
            if key not in unique_violations:
                unique_violations[key] = v
            else:
                # En yüksek prob'u tut
                if v.observed_prob > unique_violations[key].observed_prob:
                    unique_violations[key] = v
        
        # İhlal türüne göre ağırlıklar
        weights = {
            ViolationType.ORDER_INVERSION: 1.0,
            ViolationType.TRANSITIVITY_BREAK: 0.5,
            ViolationType.NOVEL_PRECEDENCE: 0.1,  # Çok düşük - novel çok yaygın
        }
        
        # Sadece ORDER_INVERSION sayısına göre score
        inversion_count = sum(
            1 for v in unique_violations.values() 
            if v.type == ViolationType.ORDER_INVERSION
        )
        
        # ORDER_INVERSION yoksa, diğerlerine bak
        if inversion_count == 0:
            # Sadece çok güçlü NOVEL_PRECEDENCE varsa düşük score
            strong_novel = sum(
                1 for v in unique_violations.values()
                if v.type == ViolationType.NOVEL_PRECEDENCE and v.observed_prob > 0.9
            )
            return min(0.3, strong_novel * 0.05)
        
        # ORDER_INVERSION bazlı score
        # Her inversion için ortalama prob * weight
        inversion_score = 0.0
        for v in unique_violations.values():
            if v.type == ViolationType.ORDER_INVERSION:
                inversion_score += v.observed_prob
        
        # Normalize: max 10 inversion = score 1.0
        score = min(1.0, inversion_score / 5.0)
        
        return score
    
    def detect(
        self, 
        recording: Recording,
        true_label: str = "unknown"
    ) -> DetectionResult:
        """
        Tek bir recording'de anomali tespit et.
        
        Args:
            recording: Analiz edilecek recording
            true_label: Ground truth etiketi ("normal", "attack", "unknown")
            
        Returns:
            DetectionResult
        """
        windows = self._create_windows(recording.syscalls)
        all_violations: List[Violation] = []
        violating_window_count = 0
        
        for window_id, window in enumerate(windows, 1):
            violations = self._detect_violations_in_window(window, window_id)
            if violations:
                violating_window_count += 1
                all_violations.extend(violations)
        
        # Anomali skoru hesapla
        score = self._compute_anomaly_score(all_violations)
        
        # Sadece ORDER_INVERSION varsa anomali say
        inversion_count = sum(
            1 for v in all_violations 
            if v.type == ViolationType.ORDER_INVERSION
        )
        is_anomaly = score >= self.anomaly_threshold and inversion_count > 0
        
        return DetectionResult(
            recording_id=recording.recording_id,
            is_anomaly=is_anomaly,
            anomaly_score=score,
            violations=all_violations,
            true_label=true_label,
            total_windows=len(windows),
            violating_windows=violating_window_count
        )
    
    def detect_batch(
        self, 
        recordings: List[Recording],
        labels: Optional[Dict[str, str]] = None
    ) -> List[DetectionResult]:
        """
        Birden fazla recording'i analiz et.
        
        Args:
            recordings: Recording listesi
            labels: {recording_id: label} etiket sözlüğü
            
        Returns:
            DetectionResult listesi
        """
        if labels is None:
            labels = {}
        
        results = []
        for recording in recordings:
            label = labels.get(
                recording.recording_id,
                "attack" if recording.is_attack else "normal"
            )
            result = self.detect(recording, true_label=label)
            results.append(result)
        
        return results


@dataclass
class EvaluationMetrics:
    """
    Değerlendirme metrikleri
    """
    total: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0
    
    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        correct = self.true_positives + self.true_negatives
        return correct / self.total if self.total > 0 else 0.0
    
    def report(self) -> str:
        """Değerlendirme raporu"""
        lines = [
            "=" * 50,
            "EVALUATION REPORT",
            "=" * 50,
            f"Total recordings: {self.total}",
            "-" * 50,
            "Confusion Matrix:",
            f"  True Positives (TP):  {self.true_positives}",
            f"  False Positives (FP): {self.false_positives}",
            f"  True Negatives (TN):  {self.true_negatives}",
            f"  False Negatives (FN): {self.false_negatives}",
            "-" * 50,
            "Metrics:",
            f"  Precision: {self.precision:.4f}",
            f"  Recall:    {self.recall:.4f}",
            f"  F1 Score:  {self.f1_score:.4f}",
            f"  Accuracy:  {self.accuracy:.4f}",
            "=" * 50,
        ]
        return "\n".join(lines)


def evaluate(results: List[DetectionResult]) -> EvaluationMetrics:
    """
    Tespit sonuçlarını değerlendir.
    
    Args:
        results: DetectionResult listesi
        
    Returns:
        EvaluationMetrics
    """
    metrics = EvaluationMetrics(total=len(results))
    
    for r in results:
        if r.true_label == "unknown":
            continue
        
        if r.true_label == "attack":
            if r.is_anomaly:
                metrics.true_positives += 1
            else:
                metrics.false_negatives += 1
        else:  # normal
            if r.is_anomaly:
                metrics.false_positives += 1
            else:
                metrics.true_negatives += 1
    
    return metrics
