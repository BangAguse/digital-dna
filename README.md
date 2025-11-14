<a href="https://freeimage.host/i/f9nl4sV"><img src="https://iili.io/f9nl4sV.md.jpg" alt="f9nl4sV.md.jpg" border="0"></a>
# Digital DNA MVP
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue" />
  <img src="https://img.shields.io/github/tag/KalloloCoder/digital-dna.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
  <img src="https://img.shields.io/badge/Maintained-Yes-green" />
  <img src="https://img.shields.io/badge/Open%20Source-Yes-brightgreen" />
  <img src="https://img.shields.io/github/stars/KalloloCoder/digital-dna?style=social" />
  <img src="https://img.shields.io/github/forks/KalloloCoder/digital-dna?style=social" />
  <img src="https://img.shields.io/github/issues/KalloloCoder/digital-dna" />
  <a href="https://github.com/KalloloCoder">
    <img src="https://img.shields.io/badge/Author-KalloloCoder-blue" />
  </a>
</p>
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

Selamat datang ke **Digital DNA MVP** - Sistem Identitas Digital Adaptif berbasis Behavioral Biometrics.

## 📋 Daftar Isi

1. [Visi & Misi](#visi--misi)
2. [Problem Statement](#problem-statement)
3. [Fitur MVP](#fitur-mvp)
4. [Arsitektur](#arsitektur)
5. [Instalasi & Setup](#instalasi--setup)
6. [Quickstart](#quickstart)
7. [Struktur Folder](#struktur-folder)
8. [Testing](#testing)
9. [Roadmap](#roadmap)
10. [Contributing](#contributing)

---

## 🎯 Visi & Misi

### Visi
Menciptakan sistem keamanan digital yang adaptif dan personal, dimana setiap entitas digital (user, perangkat, aplikasi) memiliki "DNA" unik yang mencerminkan perilaku autentik mereka.

### Misi
1. **Authenticate** - Verifikasi identitas melalui behavioral biometrics
2. **Detect** - Mendeteksi anomali, spoofing, insider threat, dan credential theft secara real-time
3. **Verify** - Verifikasi DNA secara lokal dan terdesentralisasi (federated)
4. **Enforce** - Enforce access control dengan keputusan adaptif (allow/challenge/quarantine)
5. **Adapt** - Adaptif terhadap perubahan perilaku normal (behavioral drift)

---

## 🚨 Problem Statement

### Tantangan Keamanan Modern
- **Identity Spoofing**: Attacker meniru identitas user legitimate
- **Insider Threats**: Employee/admin yang abuse privilege
- **Credential Theft**: Password/token stolen, digunakan dari lokasi/context berbeda
- **Behavioral Drift**: Sistem kesulitan membedakan perubahan perilaku normal vs attack
- **Centralized Dependency**: Single point of failure dalam verifikasi identitas
- **Adaptive Attacks**: Static security rules mudah di-bypass

### Solusi Digital DNA
- ✅ Behavioral profile yang unik dan sulit di-forge
- ✅ Real-time anomaly detection dengan multiple dimensions
- ✅ Federated verification untuk resilience dan privacy
- ✅ Adaptive policies yang belajar dari perilaku normal
- ✅ Zero-knowledge proof untuk privacy-preserving verification

---

## ⭐ Fitur MVP

### Phase 1: Behavioral Capture
- [x] Keystroke dynamics (inter-keystroke time, dwell time, pressure)
- [x] Resource usage patterns (CPU, memory, process count)
- [x] API call patterns (endpoints, latency, error rates)
- [x] Network patterns (IP, ports, data transfer)
- [x] Login patterns (time, location, device fingerprint)
- [x] File access patterns (read/write ratios, sensitive files)

### Phase 2: DNA Generation
- [x] Composite hashing dari behavioral vectors
- [x] Entropy calculation untuk uniqueness measurement
- [x] Mock cryptographic signing
- [x] DNA versioning dan TTL management
- [x] Support multiple hashing algorithms (SHA256, SHA512, BLAKE2)

### Phase 3: Local Verification
- [x] DNA format dan hash integrity verification
- [x] Baseline establishment untuk normal behavior
- [x] Statistical anomaly detection (Z-score analysis)
- [x] Spoofing detection (identity misalignment)
- [x] Insider threat detection (privilege abuse)
- [x] Credential theft detection (velocity checks, automation patterns)
- [x] Behavioral drift detection

### Phase 4: Federated Verification
- [x] Node-to-node communication (mock)
- [x] Zero-knowledge proof stub implementation
- [x] Consensus mechanism (majority, quorum, unanimous)
- [x] Mesh network topology
- [x] Cross-node DNA verification

### Phase 5: Policy Enforcement
- [x] Policy rule engine dengan multiple rule types
- [x] Access control decisions (ALLOW, CHALLENGE, QUARANTINE, DENY)
- [x] Adaptive policies berdasarkan threat level
- [x] Decision audit trail
- [x] Administrative overrides
- [x] Recommendations engine

---

## 🏗️ Arsitektur

```
┌─────────────────────────────────────────────────────────────────┐
│                     DIGITAL DNA SYSTEM                           │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ 1. BEHAVIORAL CAPTURE LAYER (agent/)                             │
│   - BehavioralCapture: keystroke, CPU, API, network, login, files│
│   - Mock data generation untuk testing                           │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 2. DNA GENERATION LAYER (generator/)                             │
│   - DNAGenerator: composite hash, entropy, cryptographic signing │
│   - Multiple algorithms: SHA256, SHA512, BLAKE2                  │
│   - DNA versioning dan TTL                                      │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 3. LOCAL VERIFICATION LAYER (verification/)                      │
│   - LocalVerifier: format check, hash integrity, baseline        │
│   - Anomaly detection: Z-score, behavioral drift                │
│   - Threat detection: spoofing, insider, credential theft       │
└──────────────────────────────────────────────────────────────────┘
                              ↓
                    ┌─────────────────┐
                    │   Confidence    │
                    │  + Threat Level │
                    └─────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 4. FEDERATED LAYER (federated/)                                  │
│   - FederatedNode: cross-node communication                      │
│   - ZKProofStub: zero-knowledge proof                           │
│   - ConsensusResult: majority/quorum/unanimous                  │
└──────────────────────────────────────────────────────────────────┘
                              ↓
                    ┌─────────────────┐
                    │  Final Decision │
                    │  Confidence     │
                    └─────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ 5. POLICY ENGINE LAYER (policy/)                                 │
│   - PolicyEngine: rule evaluation, access control                │
│   - Actions: ALLOW / CHALLENGE / QUARANTINE / DENY              │
│   - Audit trail dan recommendations                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## 💻 Instalasi & Setup

### Prerequisites
- Python 3.11+
- pip atau conda
- Git

### Installation Steps

1. **Clone Repository**
```bash
git clone https://github.com/yourusername/digital-dna.git
cd digital-dna
```

2. **Create Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# atau
venv\Scripts\activate     # Windows
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Verify Installation**
```bash
python -m pytest tests/ -v
```

---

## 🚀 Quickstart

### Basic Usage

```python
from agent.agent import BehavioralCapture
from generator.dna_generator import DNAGenerator
from verification.local_verifier import LocalVerifier
from policy.access_control import PolicyEngine

# 1. Capture behavioral vectors
agent = BehavioralCapture("user_alice", entity_type="user")
profile = agent.generate_mock_profile()

# 2. Generate Digital DNA
generator = DNAGenerator("user_alice")
dna = generator.generate_dna(profile["vectors"])

# 3. Verify locally
verifier = LocalVerifier("user_alice")
verifier.establish_baseline(profile["vectors"])
verification_result = verifier.verify_dna(
    dna.__dict__,
    profile["vectors"]
)

# 4. Make access decision
engine = PolicyEngine()
decision = engine.evaluate_access(
    "user_alice",
    verification_result.__dict__
)

print(f"Access Decision: {decision.decision}")
print(f"Confidence: {decision.confidence_score:.2f}")
```

### Run Demo Workflow
```bash
python main.py
```

### Run All Tests
```bash
pytest tests/ -v --tb=short
```

---

## 📁 Struktur Folder

```
digital-dna/
├── agent/                           # Behavioral capture module
│   ├── __init__.py
│   └── agent.py                     # BehavioralCapture, behavioral vectors
│
├── generator/                       # DNA generation module
│   ├── __init__.py
│   └── dna_generator.py            # DNAGenerator, DigitalDNA, entropy
│
├── verification/                    # Local verification module
│   ├── __init__.py
│   └── local_verifier.py           # LocalVerifier, anomaly detection
│
├── federated/                       # Federated node module
│   ├── __init__.py
│   └── node.py                     # FederatedNode, ZKProof, consensus
│
├── policy/                          # Policy engine module
│   ├── __init__.py
│   └── access_control.py           # PolicyEngine, access decisions
│
├── tests/                           # Unit tests
│   ├── __init__.py
│   ├── test_agent.py               # Tests untuk agent module
│   ├── test_generator.py           # Tests untuk generator module
│   ├── test_verification.py        # Tests untuk verification module
│   ├── test_federated.py           # Tests untuk federated module
│   └── test_policy.py              # Tests untuk policy module
│
├── docs/                            # Documentation
│   ├── architecture.md              # System architecture
│   ├── roadmap.md                   # 3-month MVP roadmap
│   └── api.md                       # API documentation (future)
│
├── main.py                          # Main workflow runner
├── requirements.txt                 # Python dependencies
├── pyproject.toml                   # Project configuration
├── .gitignore                       # Git ignore rules
├── README.md                        # This file
└── CONTRIBUTING.md                  # Contribution guidelines
```

---

## 🧪 Testing

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Module Tests
```bash
pytest tests/test_agent.py -v
pytest tests/test_generator.py -v
pytest tests/test_verification.py -v
pytest tests/test_federated.py -v
pytest tests/test_policy.py -v
```

### Run with Coverage
```bash
pytest tests/ --cov=. --cov-report=html
```

### Test Output Example
```
tests/test_agent.py::TestBehavioralCapture::test_capture_keystroke_dynamics PASSED [ 10%]
tests/test_agent.py::TestBehavioralCapture::test_capture_cpu_memory_usage PASSED [ 20%]
tests/test_generator.py::TestDNAGenerator::test_generate_dna PASSED [ 30%]
tests/test_verification.py::TestLocalVerifier::test_verify_dna PASSED [ 40%]
tests/test_federated.py::TestFederatedNode::test_consensus_majority PASSED [ 50%]
tests/test_policy.py::TestPolicyEngine::test_safe_access_decision PASSED [ 60%]
```

---

## 🗺️ Roadmap

Lihat [docs/roadmap.md](docs/roadmap.md) untuk detail lengkap roadmap 3 bulan MVP.

### Phase 1: Foundation (Week 1-2) ✅
- [x] Behavioral capture dari semua dimensions
- [x] DNA generation dengan entropy
- [x] Local verification dengan anomaly detection

### Phase 2: Federated (Week 3-4)
- [ ] Real zero-knowledge proof implementation
- [ ] Optimize consensus mechanism
- [ ] Network resilience testing

### Phase 3: Enhancement (Week 5-8)
- [ ] Machine learning untuk adaptive policies
- [ ] Real network communication (gRPC/HTTP)
- [ ] Performance optimization
- [ ] Security audit dan penetration testing

### Phase 4: Production (Week 9-12)
- [ ] Production deployment
- [ ] Monitoring dan observability
- [ ] Documentation lengkap
- [ ] Community launch

---

## 🤝 Contributing

Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk panduan lengkap berkontribusi.

### Quick Contribution Steps
1. Fork repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push ke branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📚 Dokumentasi

- [Architecture](docs/architecture.md) - Detailed system design
- [Roadmap](docs/roadmap.md) - Development roadmap
- [Contributing](CONTRIBUTING.md) - Contribution guidelines

---

## 📝 License

Project ini dilisensikan di bawah MIT License. Lihat LICENSE file untuk details.

---

## 💬 Support

Untuk questions atau issues:
1. Open GitHub Issue
2. Diskusi di GitHub Discussions
3. Contact:
   - Email: muhammadagustriananda@gmail.com
   - Phone: [085756444803](https://wa.me/+6285756444803)/[087722604369](https://wa.me/+6287722604369)
   - Github: [KalloloCoder](https://github.com/KalloloCoder)

---

## 🙏 Acknowledgments

- Inspired by behavioral biometrics dan adaptive security
- Built with Python 3.11+
- Community contributions welcome!

---

**Last Updated**: November 14, 2025
**Version**: MVP 0.1.0








