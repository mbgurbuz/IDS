"""
Precedence Extractor
====================

Syscall dizilerinden pairwise precedence istatistikleri çıkarır.

Paper Section III-B:
- "Extraction of Raw Precedence Statistics"
- "Mapping to Qualitative Pairwise Relations"
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set, Iterator, Optional
import math

from .data_loader import Recording, Syscall


@dataclass
class PrecedencePair:
    """
    İki syscall arasındaki precedence ilişkisi
    """
    syscall_a: str  # Önce gelen
    syscall_b: str  # Sonra gelen
    
    # A→B sayısı
    count_ab: int = 0
    # B→A sayısı
    count_ba: int = 0
    
    # Hesaplanan değerler
    @property
    def total_count(self) -> int:
        return self.count_ab + self.count_ba
    
    @property
    def prob_ab(self) -> float:
        """P(A→B) olasılığı"""
        if self.total_count == 0:
            return 0.0
        return self.count_ab / self.total_count
    
    @property
    def prob_ba(self) -> float:
        """P(B→A) olasılığı"""
        return 1.0 - self.prob_ab
    
    @property
    def dominant_direction(self) -> Optional[str]:
        """Baskın yön: "ab", "ba", veya None (belirsiz)"""
        if self.prob_ab > 0.5:
            return "ab"
        elif self.prob_ab < 0.5:
            return "ba"
        return None
    
    def is_strong(self, theta: float) -> bool:
        """Yön yeterince güçlü mü?"""
        return self.prob_ab >= theta or self.prob_ba >= theta


@dataclass
class WindowStats:
    """
    Tek bir pencerenin istatistikleri
    """
    window_id: int
    start_time: float
    end_time: float
    syscall_count: int
    pair_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)


class PrecedenceExtractor:
    """
    Syscall dizilerinden pairwise precedence çıkarıcı.
    
    Paper Section III-B-2:
    "For each container, we segment its syscall stream into processing windows 
     and aggregate window-level evidence for any ordered pair (a, b)"
    
    Parameters:
        window_size: W - Pencere boyutu (syscall sayısı)
        overlap: Pencere örtüşme oranı (0.0-1.0)
        delta_hops: Δ - Maksimum hop mesafesi
        min_support: τ - Minimum destek eşiği
        theta: θ - Yön belirleme eşiği
    """
    
    def __init__(
        self,
        window_size: int = 100,
        overlap: float = 0.5,
        delta_hops: int = 50,
        min_support: int = 30,
        theta: float = 0.7
    ):
        self.window_size = window_size
        self.overlap = overlap
        self.delta_hops = delta_hops
        self.min_support = min_support
        self.theta = theta
        
        # Results
        self._aggregate_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self._syscalls: Set[str] = set()
        self._window_count = 0
    
    def _create_windows(
        self, 
        syscalls: List[Syscall]
    ) -> Iterator[List[Syscall]]:
        """
        Syscall listesini sliding window'lara böl.
        
        Paper: "Events are filtered... divided into fixed-length windows"
        """
        if not syscalls:
            return
        
        step = max(1, int(self.window_size * (1.0 - self.overlap)))
        
        for start_idx in range(0, len(syscalls), step):
            end_idx = min(start_idx + self.window_size, len(syscalls))
            window = syscalls[start_idx:end_idx]
            if window:
                yield window
    
    def _count_pairs_in_window(
        self, 
        window: List[Syscall]
    ) -> Dict[Tuple[str, str], int]:
        """
        Bir pencerede syscall çiftlerini say (hop mesafesi dahilinde).
        
        Paper: "we only count a → b when the two events occur within at most Δ calls"
        
        Returns:
            {(syscall_a, syscall_b): count}
        """
        counts: Dict[Tuple[str, str], int] = defaultdict(int)
        
        # Önceki syscall'ları tutan deque (max delta_hops uzunluğunda)
        # Bu, her syscall için önceki Δ syscall'ı verimli şekilde tutar
        previous: deque = deque(maxlen=self.delta_hops)
        
        for syscall in window:
            current_name = syscall.syscall_name
            self._syscalls.add(current_name)
            
            # Önceki her syscall için (prev, current) çifti oluştur
            for prev_name in previous:
                if prev_name != current_name:  # Self-loops hariç
                    counts[(prev_name, current_name)] += 1
            
            previous.append(current_name)
        
        return dict(counts)
    
    def process_recording(self, recording: Recording) -> List[WindowStats]:
        """
        Tek bir recording'i işle ve pencere istatistiklerini döndür.
        """
        window_stats = []
        
        for window in self._create_windows(recording.syscalls):
            self._window_count += 1
            
            # Pencere istatistikleri
            stats = WindowStats(
                window_id=self._window_count,
                start_time=window[0].timestamp,
                end_time=window[-1].timestamp,
                syscall_count=len(window)
            )
            
            # Çift sayımı
            pair_counts = self._count_pairs_in_window(window)
            stats.pair_counts = pair_counts
            
            # Aggregate'e ekle
            for (a, b), count in pair_counts.items():
                self._aggregate_counts[(a, b)] += count
            
            window_stats.append(stats)
        
        return window_stats
    
    def process_recordings(self, recordings: List[Recording]) -> None:
        """
        Birden fazla recording'i işle.
        """
        for recording in recordings:
            self.process_recording(recording)
    
    def get_precedence_matrix(
        self
    ) -> Tuple[Dict[Tuple[str, str], float], Dict[Tuple[str, str], int], Set[str]]:
        """
        Aggregate istatistiklerden precedence matrisini oluştur.
        
        Paper Section III-B-3: "Mapping to Qualitative Pairwise Relations"
        
        Returns:
            probs: {(a, b): P(a→b)} - Olasılıklar
            support: {(a, b): total_count} - Destek sayıları
            syscalls: Görülen tüm syscall isimleri
        """
        probs: Dict[Tuple[str, str], float] = {}
        support: Dict[Tuple[str, str], int] = {}
        
        # Her unique (a, b) çifti için olasılık hesapla
        processed_pairs: Set[frozenset] = set()
        
        for (a, b), ab_count in self._aggregate_counts.items():
            pair_key = frozenset([a, b])
            if pair_key in processed_pairs:
                continue
            processed_pairs.add(pair_key)
            
            # Ters yönü de al
            ba_count = self._aggregate_counts.get((b, a), 0)
            total = ab_count + ba_count
            
            # Minimum destek kontrolü
            if total < self.min_support:
                continue
            
            # a != b kontrolü
            if a == b:
                continue
            
            # Olasılıkları hesapla
            prob_ab = ab_count / (total + 1e-9)
            prob_ba = ba_count / (total + 1e-9)
            
            # Her iki yön için de kaydet
            probs[(a, b)] = prob_ab
            probs[(b, a)] = prob_ba
            support[(a, b)] = total
            support[(b, a)] = total
        
        return probs, support, self._syscalls.copy()
    
    def get_strong_edges(
        self
    ) -> Dict[Tuple[str, str], float]:
        """
        Sadece güçlü (theta üzerinde) edge'leri döndür.
        
        Returns:
            {(a, b): prob} - Sadece dominant yöndeki edge'ler
        """
        probs, support, _ = self.get_precedence_matrix()
        
        strong_edges: Dict[Tuple[str, str], float] = {}
        processed_pairs: Set[frozenset] = set()
        
        for (a, b), prob in probs.items():
            pair_key = frozenset([a, b])
            if pair_key in processed_pairs:
                continue
            processed_pairs.add(pair_key)
            
            prob_ba = probs.get((b, a), 0.0)
            
            # Hangi yön daha güçlü?
            if prob >= self.theta:
                strong_edges[(a, b)] = prob
            elif prob_ba >= self.theta:
                strong_edges[(b, a)] = prob_ba
        
        return strong_edges
    
    def get_statistics(self) -> Dict:
        """
        Çıkarıcı istatistiklerini al
        """
        probs, support, syscalls = self.get_precedence_matrix()
        strong_edges = self.get_strong_edges()
        
        return {
            'total_syscalls': len(syscalls),
            'total_windows': self._window_count,
            'total_pairs': len(probs) // 2,  # Her çift iki kez sayıldı
            'strong_pairs': len(strong_edges),
            'avg_support': sum(support.values()) / max(1, len(support)),
        }
    
    def reset(self):
        """
        Tüm aggregate istatistikleri sıfırla
        """
        self._aggregate_counts.clear()
        self._syscalls.clear()
        self._window_count = 0


def extract_precedence(
    recordings: List[Recording],
    window_size: int = 100,
    overlap: float = 0.5,
    delta_hops: int = 50,
    min_support: int = 30,
    theta: float = 0.7
) -> Tuple[Dict[Tuple[str, str], float], Dict[Tuple[str, str], int], Set[str]]:
    """
    Convenience function: Recording listesinden precedence çıkar.
    
    Returns:
        probs, support, syscalls
    """
    extractor = PrecedenceExtractor(
        window_size=window_size,
        overlap=overlap,
        delta_hops=delta_hops,
        min_support=min_support,
        theta=theta
    )
    extractor.process_recordings(recordings)
    return extractor.get_precedence_matrix()
