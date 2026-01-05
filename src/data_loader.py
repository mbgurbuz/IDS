"""
LID-DS Data Loader
==================

LID-DS 2021 veri setini yükler.
Zip dosyalarından .sc (syscall) dosyalarını okur.

LID-DS 2021 Format (.sc dosyası):
    timestamp user_id pid process_name thread_id syscall_name direction args...
    
Örnek:
    1631011407593552353 0 937365 apache2 937365 select < res=0
"""

import os
import zipfile
import io
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Iterator, Optional, Dict, Tuple
from enum import Enum


class RecordingType(Enum):
    """Recording türü"""
    TRAINING = "training"
    VALIDATION = "validation"
    TEST_NORMAL = "test_normal"
    TEST_ATTACK = "test_attack"


@dataclass
class Syscall:
    """Tek bir sistem çağrısı"""
    timestamp: float
    process_name: str
    process_id: int
    thread_id: int
    syscall_name: str
    syscall_args: str = ""
    return_value: str = ""
    user_id: int = 0
    direction: str = ""  # '<' veya '>'
    
    def __repr__(self):
        return f"Syscall({self.syscall_name}, pid={self.process_id})"


@dataclass
class Recording:
    """Bir recording (container çalışması)"""
    recording_id: str
    recording_type: RecordingType
    file_path: Path
    syscalls: List[Syscall] = field(default_factory=list)
    scenario_name: str = ""
    is_attack: bool = False
    
    def __len__(self):
        return len(self.syscalls)
    
    def __repr__(self):
        return f"Recording({self.recording_id}, {len(self.syscalls)} syscalls, attack={self.is_attack})"


class LIDDSParser:
    """
    LID-DS .sc dosyası parser
    
    Format: timestamp user_id pid process_name thread_id syscall_name direction args...
    """
    
    @staticmethod
    def parse_line(line: str) -> Optional[Syscall]:
        """Tek bir satırı parse et"""
        line = line.strip()
        if not line:
            return None
        
        parts = line.split()
        if len(parts) < 7:
            return None
        
        try:
            timestamp = int(parts[0]) / 1e9  # nanosecond -> second
            user_id = int(parts[1])
            pid = int(parts[2])
            process_name = parts[3]
            thread_id = int(parts[4])
            syscall_name = parts[5]
            direction = parts[6]  # '<' veya '>'
            
            # Geri kalan args
            args = " ".join(parts[7:]) if len(parts) > 7 else ""
            
            # Return value'yu args'tan çıkar (eğer varsa)
            return_value = ""
            if "res=" in args:
                for part in args.split():
                    if part.startswith("res="):
                        return_value = part[4:]
                        break
            
            return Syscall(
                timestamp=timestamp,
                user_id=user_id,
                process_id=pid,
                process_name=process_name,
                thread_id=thread_id,
                syscall_name=syscall_name,
                direction=direction,
                syscall_args=args,
                return_value=return_value
            )
        except (ValueError, IndexError) as e:
            return None
    
    @staticmethod
    def parse_sc_content(content: str) -> List[Syscall]:
        """SC dosya içeriğini parse et"""
        syscalls = []
        for line in content.split('\n'):
            sc = LIDDSParser.parse_line(line)
            if sc:
                syscalls.append(sc)
        return syscalls
    
    @staticmethod
    def parse_zip_file(zip_path: Path) -> List[Syscall]:
        """Zip dosyasından .sc dosyasını oku ve parse et"""
        syscalls = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # .sc dosyasını bul
                sc_files = [f for f in zf.namelist() if f.endswith('.sc')]
                
                if not sc_files:
                    return syscalls
                
                # İlk .sc dosyasını oku
                sc_file = sc_files[0]
                with zf.open(sc_file) as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    syscalls = LIDDSParser.parse_sc_content(content)
        
        except (zipfile.BadZipFile, IOError) as e:
            print(f"Warning: Could not read {zip_path}: {e}")
        
        return syscalls


class LIDDSDataLoader:
    """
    LID-DS 2021 veri seti yükleyici
    
    Beklenen yapı:
        data_path/
        ├── Scenario_Name/
        │   ├── training/
        │   │   └── *.zip
        │   ├── validation/
        │   │   └── *.zip
        │   └── test/
        │       ├── normal/
        │       │   └── *.zip
        │       └── normal_and_attack/
        │           └── *.zip
    """
    
    def __init__(self, data_path: str):
        self.data_path = Path(data_path)
        if not self.data_path.exists():
            raise FileNotFoundError(f"LID-DS path not found: {data_path}")
    
    def list_scenarios(self) -> List[str]:
        """Mevcut senaryoları listele"""
        scenarios = []
        for item in self.data_path.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                # Training veya test klasörü var mı kontrol et
                if (item / "training").exists() or (item / "test").exists():
                    scenarios.append(item.name)
        return sorted(scenarios)
    
    def _load_recordings_from_dir(
        self, 
        directory: Path, 
        recording_type: RecordingType,
        scenario_name: str,
        is_attack: bool = False,
        limit: Optional[int] = None
    ) -> Iterator[Recording]:
        """Bir dizindeki tüm zip dosyalarını yükle"""
        
        if not directory.exists():
            return
        
        zip_files = sorted(directory.glob("*.zip"))
        
        if limit:
            zip_files = zip_files[:limit]
        
        for zip_path in zip_files:
            recording_id = zip_path.stem  # Dosya adı (uzantısız)
            
            syscalls = LIDDSParser.parse_zip_file(zip_path)
            
            if syscalls:  # Boş olmayan kayıtları döndür
                yield Recording(
                    recording_id=recording_id,
                    recording_type=recording_type,
                    file_path=zip_path,
                    syscalls=syscalls,
                    scenario_name=scenario_name,
                    is_attack=is_attack
                )
    
    def training_data(
        self, 
        scenario: str, 
        limit: Optional[int] = None
    ) -> Iterator[Recording]:
        """Training verilerini yükle"""
        training_dir = self.data_path / scenario / "training"
        yield from self._load_recordings_from_dir(
            training_dir,
            RecordingType.TRAINING,
            scenario,
            is_attack=False,
            limit=limit
        )
    
    def validation_data(
        self, 
        scenario: str, 
        limit: Optional[int] = None
    ) -> Iterator[Recording]:
        """Validation verilerini yükle"""
        validation_dir = self.data_path / scenario / "validation"
        yield from self._load_recordings_from_dir(
            validation_dir,
            RecordingType.VALIDATION,
            scenario,
            is_attack=False,
            limit=limit
        )
    
    def test_data(
        self, 
        scenario: str, 
        limit: Optional[int] = None
    ) -> Iterator[Recording]:
        """Test verilerini yükle (normal + attack)"""
        test_dir = self.data_path / scenario / "test"
        
        # Normal test verileri
        normal_dir = test_dir / "normal"
        yield from self._load_recordings_from_dir(
            normal_dir,
            RecordingType.TEST_NORMAL,
            scenario,
            is_attack=False,
            limit=limit
        )
        
        # Attack test verileri
        attack_dir = test_dir / "normal_and_attack"
        yield from self._load_recordings_from_dir(
            attack_dir,
            RecordingType.TEST_ATTACK,
            scenario,
            is_attack=True,
            limit=limit
        )
    
    def get_statistics(self, scenario: str) -> Dict:
        """Senaryo istatistiklerini döndür"""
        stats = {
            'scenario': scenario,
            'training_recordings': 0,
            'training_syscalls': 0,
            'validation_recordings': 0,
            'validation_syscalls': 0,
            'test_normal_recordings': 0,
            'test_normal_syscalls': 0,
            'test_attack_recordings': 0,
            'test_attack_syscalls': 0,
        }
        
        # Training
        training_dir = self.data_path / scenario / "training"
        if training_dir.exists():
            stats['training_recordings'] = len(list(training_dir.glob("*.zip")))
        
        # Validation
        validation_dir = self.data_path / scenario / "validation"
        if validation_dir.exists():
            stats['validation_recordings'] = len(list(validation_dir.glob("*.zip")))
        
        # Test normal
        test_normal_dir = self.data_path / scenario / "test" / "normal"
        if test_normal_dir.exists():
            stats['test_normal_recordings'] = len(list(test_normal_dir.glob("*.zip")))
        
        # Test attack
        test_attack_dir = self.data_path / scenario / "test" / "normal_and_attack"
        if test_attack_dir.exists():
            stats['test_attack_recordings'] = len(list(test_attack_dir.glob("*.zip")))
        
        return stats


# Test için
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python data_loader.py <data_path> [scenario]")
        sys.exit(1)
    
    data_path = sys.argv[1]
    loader = LIDDSDataLoader(data_path)
    
    print("Available scenarios:", loader.list_scenarios())
    
    if len(sys.argv) > 2:
        scenario = sys.argv[2]
        print(f"\nStatistics for {scenario}:")
        stats = loader.get_statistics(scenario)
        for k, v in stats.items():
            print(f"  {k}: {v}")
        
        print("\nLoading first training recording...")
        for rec in loader.training_data(scenario, limit=1):
            print(f"  {rec}")
            print(f"  First 5 syscalls:")
            for sc in rec.syscalls[:5]:
                print(f"    {sc.syscall_name} ({sc.process_name})")
