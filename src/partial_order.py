"""
Partial Order (Poset) Model
===========================

Syscall precedence'larından Strict Partial Order modeli oluşturur.

Paper Section III-C: "Fundamentals of Partially Ordered Sets"
Paper Section III-D: "Approximating Partial Orders"

Özellikler:
- Irreflexive: a ⊀ a (hiçbir syscall kendinden önce gelmez)
- Asymmetric: a < b ⟹ ¬(b < a) (tek yönlü ilişki)
- Transitive: a < b ∧ b < c ⟹ a < c (geçişlilik)
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set, Optional
import json


@dataclass
class PartialOrderModel:
    """
    Strict Partial Order modeli
    
    Attributes:
        edges: DAG edge'leri {(a, b): weight}
        hasse_edges: Transitive reduction {(a, b): weight}
        nodes: Tüm syscall isimleri
        theta: Edge dahil etme eşiği
        repair_method: Döngü kırma yöntemi
    """
    edges: Dict[Tuple[str, str], float] = field(default_factory=dict)
    hasse_edges: Dict[Tuple[str, str], float] = field(default_factory=dict)
    nodes: Set[str] = field(default_factory=set)
    theta: float = 0.7
    repair_method: str = "rdiamond"
    
    # Cache
    _adjacency: Dict[str, List[str]] = field(default_factory=dict, repr=False)
    _reachable: Dict[str, Set[str]] = field(default_factory=dict, repr=False)
    
    def precedes(self, a: str, b: str) -> bool:
        """
        Model'e göre a, b'den önce mi gelir? (a < b)
        
        Direct edge veya transitive closure'da olmalı.
        """
        if a == b:
            return False
        
        # Direct edge
        if (a, b) in self.edges:
            return True
        
        # Transitive (reachability)
        if a in self._reachable:
            return b in self._reachable[a]
        
        return False
    
    def strictly_precedes(self, a: str, b: str) -> bool:
        """Direct edge var mı? (transitive olmadan)"""
        return (a, b) in self.edges
    
    def are_comparable(self, a: str, b: str) -> bool:
        """a ve b karşılaştırılabilir mi?"""
        return self.precedes(a, b) or self.precedes(b, a)
    
    def are_incomparable(self, a: str, b: str) -> bool:
        """a ve b karşılaştırılamaz mı?"""
        return not self.are_comparable(a, b) and a != b
    
    def get_predecessors(self, node: str) -> Set[str]:
        """node'dan önce gelen tüm düğümler"""
        return {a for (a, b) in self.edges if b == node}
    
    def get_successors(self, node: str) -> Set[str]:
        """node'dan sonra gelen tüm düğümler"""
        return set(self._adjacency.get(node, []))
    
    def get_edge_weight(self, a: str, b: str) -> float:
        """Edge ağırlığını al (yoksa 0)"""
        return self.edges.get((a, b), 0.0)
    
    def to_dict(self) -> Dict:
        """JSON serialization için dict'e dönüştür"""
        return {
            'edges': {f"{a},{b}": w for (a, b), w in self.edges.items()},
            'hasse_edges': {f"{a},{b}": w for (a, b), w in self.hasse_edges.items()},
            'nodes': list(self.nodes),
            'theta': self.theta,
            'repair_method': self.repair_method,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'PartialOrderModel':
        """Dict'ten model oluştur"""
        model = cls()
        model.edges = {tuple(k.split(',')): v for k, v in data.get('edges', {}).items()}
        model.hasse_edges = {tuple(k.split(',')): v for k, v in data.get('hasse_edges', {}).items()}
        model.nodes = set(data.get('nodes', []))
        model.theta = data.get('theta', 0.7)
        model.repair_method = data.get('repair_method', 'rdiamond')
        model._rebuild_cache()
        return model
    
    def save(self, filepath: str):
        """Modeli JSON olarak kaydet"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, filepath: str) -> 'PartialOrderModel':
        """Modeli JSON'dan yükle"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def _rebuild_cache(self):
        """Adjacency ve reachability cache'lerini yeniden oluştur"""
        self._build_adjacency()
        self._compute_reachability()
    
    def _build_adjacency(self):
        """Adjacency list oluştur"""
        self._adjacency = defaultdict(list)
        for (a, b) in self.edges:
            self._adjacency[a].append(b)
    
    def _compute_reachability(self):
        """Her düğümden erişilebilir düğümleri hesapla (transitive closure)"""
        self._reachable = {node: set() for node in self.nodes}
        
        for start in self.nodes:
            visited = set()
            queue = deque(self._adjacency.get(start, []))
            
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                self._reachable[start].add(current)
                
                for neighbor in self._adjacency.get(current, []):
                    if neighbor not in visited:
                        queue.append(neighbor)
    
    def summary(self) -> str:
        """Model özeti"""
        lines = [
            "=" * 50,
            "PARTIAL ORDER MODEL",
            "=" * 50,
            f"Syscalls: {len(self.nodes)}",
            f"Edges (DAG): {len(self.edges)}",
            f"Hasse edges: {len(self.hasse_edges)}",
            f"Theta: {self.theta}",
            f"Repair method: {self.repair_method}",
            "-" * 50,
            "Top 10 precedence rules:",
        ]
        
        # En güçlü 10 edge
        sorted_edges = sorted(self.hasse_edges.items(), key=lambda x: x[1], reverse=True)
        for (a, b), w in sorted_edges[:10]:
            lines.append(f"  {a} → {b}  (w={w:.3f})")
        
        lines.append("=" * 50)
        return "\n".join(lines)


class PartialOrderBuilder:
    """
    Precedence istatistiklerinden Partial Order modeli oluşturur.
    
    Paper Section III-D: "Approximating Partial Orders"
    
    Adımlar:
    1. Güçlü edge'leri seç (θ üzerinde)
    2. Döngüleri kır (R◇ veya baseline)
    3. Transitive reduction (Hasse diyagramı)
    """
    
    def __init__(
        self,
        theta: float = 0.7,
        repair_method: str = "rdiamond"
    ):
        self.theta = theta
        self.repair_method = repair_method
    
    def build(
        self,
        probs: Dict[Tuple[str, str], float],
        support: Dict[Tuple[str, str], int],
        syscalls: Set[str]
    ) -> PartialOrderModel:
        """
        Precedence istatistiklerinden model oluştur.
        
        Args:
            probs: {(a, b): P(a→b)}
            support: {(a, b): count}
            syscalls: Tüm syscall isimleri
            
        Returns:
            PartialOrderModel
        """
        # Adım 1: Güçlü edge'leri seç
        strong_edges = self._select_strong_edges(probs)
        
        # Adım 2: Döngüleri kır
        if self.repair_method == "baseline":
            dag_edges = self._cycle_break_baseline(strong_edges)
        elif self.repair_method == "rdiamond":
            dag_edges = self._rdiamond_repair(strong_edges)
        else:
            dag_edges = self._cycle_break_baseline(strong_edges)
        
        # Adım 3: Transitive reduction
        hasse_edges = self._transitive_reduction(dag_edges, syscalls)
        
        # Model oluştur
        model = PartialOrderModel(
            edges=dag_edges,
            hasse_edges=hasse_edges,
            nodes=syscalls.copy(),
            theta=self.theta,
            repair_method=self.repair_method
        )
        model._rebuild_cache()
        
        return model
    
    def _select_strong_edges(
        self, 
        probs: Dict[Tuple[str, str], float]
    ) -> Dict[Tuple[str, str], float]:
        """
        Theta üzerindeki edge'leri seç.
        
        Paper: "Dominant direction threshold θ"
        """
        strong: Dict[Tuple[str, str], float] = {}
        processed: Set[frozenset] = set()
        
        for (a, b), prob in probs.items():
            pair_key = frozenset([a, b])
            if pair_key in processed:
                continue
            processed.add(pair_key)
            
            if a == b:
                continue
            
            prob_ba = probs.get((b, a), 0.0)
            
            # Hangi yön daha güçlü ve theta'yı geçiyor?
            if prob >= self.theta and prob > prob_ba:
                strong[(a, b)] = prob
            elif prob_ba >= self.theta and prob_ba > prob:
                strong[(b, a)] = prob_ba
        
        return strong
    
    def _build_adjacency(
        self, 
        edges: Dict[Tuple[str, str], float]
    ) -> Dict[str, List[str]]:
        """Adjacency list oluştur"""
        adj = defaultdict(list)
        for (a, b) in edges:
            adj[a].append(b)
        return dict(adj)
    
    def _find_cycle(
        self, 
        adj: Dict[str, List[str]]
    ) -> List[str]:
        """
        DFS ile döngü bul.
        
        Returns:
            Döngü varsa [v0, v1, ..., vk, v0] listesi, yoksa []
        """
        color = {}  # 0: unseen, 1: visiting, 2: done
        parent = {}
        
        def dfs(u: str) -> List[str]:
            color[u] = 1
            for v in adj.get(u, []):
                if color.get(v, 0) == 0:
                    parent[v] = u
                    cycle = dfs(v)
                    if cycle:
                        return cycle
                elif color.get(v) == 1:
                    # Döngü bulundu
                    cycle = [v]
                    cur = u
                    while cur != v:
                        cycle.append(cur)
                        cur = parent.get(cur, v)
                    cycle.append(v)
                    cycle.reverse()
                    return cycle
            color[u] = 2
            return []
        
        for node in list(adj.keys()):
            if color.get(node, 0) == 0:
                parent[node] = node
                cycle = dfs(node)
                if cycle:
                    return cycle
        
        return []
    
    def _find_weakest_edge_in_cycle(
        self, 
        cycle: List[str], 
        edges: Dict[Tuple[str, str], float]
    ) -> Optional[Tuple[str, str]]:
        """Döngüdeki en zayıf edge'i bul"""
        weakest = None
        weakest_weight = float('inf')
        
        for i in range(len(cycle) - 1):
            edge = (cycle[i], cycle[i + 1])
            weight = edges.get(edge, 0.0)
            if weight < weakest_weight:
                weakest_weight = weight
                weakest = edge
        
        return weakest
    
    def _would_create_cycle(
        self, 
        edges: Dict[Tuple[str, str], float], 
        u: str, 
        v: str
    ) -> bool:
        """u→v eklersek döngü oluşur mu?"""
        # v'den u'ya path var mı?
        adj = self._build_adjacency(edges)
        visited = set()
        queue = deque([v])
        
        while queue:
            current = queue.popleft()
            if current == u:
                return True
            if current in visited:
                continue
            visited.add(current)
            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)
        
        return False
    
    def _cycle_break_baseline(
        self, 
        edges: Dict[Tuple[str, str], float]
    ) -> Dict[Tuple[str, str], float]:
        """
        Basit döngü kırma: Döngü bulunca en zayıf edge'i sil.
        
        Paper: "Acyclic refinement: iteratively remove edges on cycles"
        """
        result = dict(edges)
        
        while True:
            adj = self._build_adjacency(result)
            cycle = self._find_cycle(adj)
            
            if not cycle:
                break
            
            edge = self._find_weakest_edge_in_cycle(cycle, result)
            if edge and edge in result:
                del result[edge]
            else:
                break
        
        return result
    
    def _rdiamond_repair(
        self, 
        edges: Dict[Tuple[str, str], float]
    ) -> Dict[Tuple[str, str], float]:
        """
        R◇ algoritması: Döngüleri kır, sonra güçlü edge'leri geri ekle.
        
        Paper Section III-D-2: "Randomized R◇"
        
        Adımlar:
        1. Döngüleri kır (en zayıf edge'leri silerek)
        2. Silinen edge'leri güçten zayıfa sırala
        3. Döngü yaratmayanları geri ekle
        """
        result = dict(edges)
        removed: Dict[Tuple[str, str], float] = {}
        
        # Adım 1: Döngüleri kır
        while True:
            adj = self._build_adjacency(result)
            cycle = self._find_cycle(adj)
            
            if not cycle:
                break
            
            edge = self._find_weakest_edge_in_cycle(cycle, result)
            if edge and edge in result:
                removed[edge] = result[edge]
                del result[edge]
            else:
                break
        
        # Adım 2 & 3: Güçlü edge'leri geri ekle
        sorted_removed = sorted(removed.items(), key=lambda x: x[1], reverse=True)
        
        for (u, v), weight in sorted_removed:
            if (u, v) not in result:
                if not self._would_create_cycle(result, u, v):
                    result[(u, v)] = weight
        
        return result
    
    def _transitive_reduction(
        self, 
        edges: Dict[Tuple[str, str], float], 
        nodes: Set[str]
    ) -> Dict[Tuple[str, str], float]:
        """
        Transitive reduction: Gereksiz edge'leri kaldır (Hasse diyagramı).
        
        a→c edge'i varsa ve a→b→c path'i varsa, a→c gereksizdir.
        """
        adj = self._build_adjacency(edges)
        
        # Her düğümden erişilebilir düğümleri hesapla
        reachable: Dict[str, Set[str]] = {node: set() for node in nodes}
        
        for start in nodes:
            visited = set()
            queue = deque(adj.get(start, []))
            
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                reachable[start].add(current)
                
                for neighbor in adj.get(current, []):
                    if neighbor not in visited:
                        queue.append(neighbor)
        
        # Gereksiz edge'leri kaldır
        reduced = dict(edges)
        
        for (u, v) in list(edges.keys()):
            # u→v edge'i, u'dan başka bir k üzerinden v'ye ulaşılabiliyorsa gereksiz
            for k in adj.get(u, []):
                if k != v and v in reachable.get(k, set()):
                    reduced.pop((u, v), None)
                    break
        
        return reduced


def build_partial_order(
    probs: Dict[Tuple[str, str], float],
    support: Dict[Tuple[str, str], int],
    syscalls: Set[str],
    theta: float = 0.7,
    repair_method: str = "rdiamond"
) -> PartialOrderModel:
    """
    Convenience function: Precedence'dan model oluştur.
    """
    builder = PartialOrderBuilder(theta=theta, repair_method=repair_method)
    return builder.build(probs, support, syscalls)
