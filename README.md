# Explainable Anomaly Detection for Container Security
## LID-DS Dataset Implementation

Bu proje, "Explainable Anomaly Detection in Container Security" makalesindeki 
metodolojiyi LID-DS veri setine uygular.

---

## 📁 Proje Yapısı

```
explainable_ids/
├── README.md                    # Bu dosya
├── requirements.txt             # Python bağımlılıkları
├── config.py                    # Konfigürasyon parametreleri
│
├── data/                        # Veri klasörü
│   └── LID-DS-2021/            # LID-DS veri seti (sen indireceksin)
│       └── CVE-2017-7529/      # Örnek senaryo
│           ├── training/
│           └── test/
│
├── src/                         # Kaynak kodlar
│   ├── __init__.py
│   ├── data_loader.py          # LID-DS veri okuyucu
│   ├── precedence_extractor.py # Pairwise precedence çıkarıcı
│   ├── partial_order.py        # Poset modeli
│   ├── detector.py             # Anomali dedektörü
│   └── explainer.py            # Açıklama üretici
│
├── experiments/                 # Deneyler
│   ├── run_experiment.py       # Ana deney scripti
│   └── evaluate.py             # Değerlendirme metrikleri
│
└── results/                     # Sonuçlar
    ├── model.json              # Eğitilmiş model
    ├── detections.json         # Tespit edilen anomaliler
    └── report.txt              # Değerlendirme raporu
```

---

## 🚀 Kurulum Adımları

### Adım 1: LID-DS Veri Setini İndir

```bash
# LID-DS 2021'i indir (Proton Drive):
# https://drive.proton.me/urls/BWKRGQK994#fCK9JKL93Sjm

# İndirdikten sonra data/ klasörüne çıkar:
mkdir -p data/LID-DS-2021
unzip LID-DS-2021.zip -d data/LID-DS-2021/
```

### Adım 2: Python Ortamını Kur

```bash
# Virtual environment oluştur
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Bağımlılıkları kur
pip install -r requirements.txt
```

### Adım 3: Deneyi Çalıştır

```bash
# Tek bir senaryo için
python experiments/run_experiment.py --scenario CVE-2017-7529

# Tüm senaryolar için
python experiments/run_experiment.py --all
```

---

## 📊 Metodoloji (Makaleden)

### 1️⃣ Windowing & Pairwise Precedence Extraction
- Syscall dizisini W boyutunda pencerelere böl
- Her pencerede, Δ hop içindeki çiftleri (a→b) say
- Minimum destek (τ) ve yön eşiği (θ) uygula

### 2️⃣ Partial Order (Poset) Modeli Oluşturma  
- Sadece normal veriden öğren
- Döngüleri R◇ algoritması ile kır
- Transitive reduction ile Hasse diyagramı oluştur

### 3️⃣ Anomali Tespiti
- Test verisinde model ihlallerini ara
- ORDER_INVERSION: Model A→B derken B→A gözlemlenirse
- TRANSITIVITY_BREAK: A<B<C varken C→A gözlemlenirse

### 4️⃣ Explainability
- Her ihlal için anlaşılır açıklama üret
- Örnek: "Violation: 'read' should precede 'close', but observed 'close' → 'read'"

---

## 🔧 Konfigürasyon Parametreleri

| Parametre | Varsayılan | Açıklama |
|-----------|------------|----------|
| W | 100 | Pencere boyutu (syscall sayısı) |
| overlap | 0.5 | Pencere örtüşme oranı |
| delta_hops | 50 | Maksimum hop mesafesi |
| min_support | 30 | Minimum destek eşiği |
| theta | 0.7 | Yön belirleme eşiği |
| anomaly_threshold | 0.3 | Anomali skoru eşiği |

---

## 📈 Beklenen Çıktılar

### 1. Model Özeti
```
PARTIAL ORDER MODEL SUMMARY
============================
Total syscalls: 45
Total edges (DAG): 120
Hasse edges (reduced): 78
Repair method: rdiamond

Top precedence rules:
  openat → read (w=0.92)
  socket → bind (w=0.89)
  ...
```

### 2. Detection Sonuçları
```
DETECTION RESULTS
=================
Trace: attack_001
Status: 🔴 ANOMALY (score: 0.78)
Violations:
  ⚠️ ORDER INVERSION: Model 'bind' → 'listen' bekliyor, 
     ancak 'listen' → 'bind' gözlemlendi (güven: 95%)
```

### 3. Değerlendirme Metrikleri
```
EVALUATION REPORT
=================
True Positives:  45
False Positives: 3
True Negatives:  150
False Negatives: 2

Precision: 0.9375
Recall:    0.9574
F1 Score:  0.9474
Accuracy:  0.9750
```

---

## 📚 Referanslar

1. Gurbuz, M.B. "Explainable Anomaly Detection in Container Security"
2. Grimmer et al. "Dataset Report: LID-DS 2021" CRITIS 2022
3. Janicki & Liu "On approximations of arbitrary relations by partial orders"
