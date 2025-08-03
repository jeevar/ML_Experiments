# 🛡️ Malicious Package Detector

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![ML](https://img.shields.io/badge/ML-Perceptron%20%7C%20AdalineSGD-orange.svg)](README.md)

A **two-stage machine learning system** for detecting malicious software packages in supply chains using **Perceptron** and **AdalineSGD** algorithms.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/[YOUR-USERNAME]/malicious-package-detector.git
cd malicious-package-detector

# Install dependencies
pip install -r requirements.txt

# Run the demo
python demo.py
```

## 🎯 Overview

Modern software development relies heavily on open-source packages from repositories like PyPI and NPM. However, attackers increasingly target these supply chains by publishing malicious packages that can compromise entire software ecosystems.

This project implements a novel two-stage detection system that combines:
- **Stage 1**: Fast heuristic filtering using Perceptron
- **Stage 2**: Nuanced behavioral analysis using AdalineSGD

## 🏗️ Architecture

```
                Incoming Package Metadata
                           │
                 ┌────────▼────────┐
                 │  Perceptron     │   ← Quick rule-based filtering
                 └────────┬────────┘
                          │
          ┌───────────────▼───────────────┐
          │ If flagged → Label as Risky   │
          │ Else       → Send to Adaline  │
          └───────────────┬───────────────┘
                          │
                 ┌────────▼────────┐
                 │   AdalineSGD    │   ← Learns soft patterns
                 └────────┬────────┘
                          │
                   Final Risk Score
```

### Stage 1: Perceptron (Fast Filter)
- **Purpose**: Acts as a high-speed gate to catch obvious threats
- **Features**: 
  - Suspicious keywords (login, crypto, hack, root)
  - Typosquat detection (similarity to popular packages)
  - Version anomalies (1337.42.0, 0.0.0)
  - Name entropy analysis
  - Short names with numbers

### Stage 2: AdalineSGD (Behavioral Analysis)
- **Purpose**: Learns subtle behavioral patterns
- **Features**:
  - Package file size analysis
  - Dependency count patterns
  - Author metadata entropy
  - Description semantic analysis
  - Name-description coherence scoring

## 📊 Dataset

The system integrates with [DataDog's malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset), which contains:
- **9,000+** verified malicious packages
- **100% human-vetted** samples
- **PyPI and NPM** ecosystems covered
- Real-world supply chain attacks

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd malicious-package-detector

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Run the interactive demo
python demo.py

# Or run the basic detection example
python malicious_package_detector.py
```

### Using with DataDog Dataset

```bash
# Run DataDog integration (requires git)
python datadog_integration.py
```

## 💻 Code Example

```python
from malicious_package_detector import MaliciousPackageDetector, PackageInfo

# Create detector
detector = MaliciousPackageDetector()

# Create sample packages
packages = [
    PackageInfo(
        name="crypto-stealth-miner",
        version="1337.0.0",
        description="stealth crypto mining backdoor",
        author="h4ck3r",
        ecosystem="pypi",
        is_malicious=True
    ),
    PackageInfo(
        name="numpy",
        version="1.24.0", 
        description="Fundamental package for array computing",
        author="numpy-team",
        ecosystem="pypi",
        is_malicious=False
    )
]

# Train the detector
detector.fit(packages)

# Make predictions
predictions, metadata = detector.predict(packages)

# Results
for pkg, pred in zip(packages, predictions):
    status = "🚨 MALICIOUS" if pred == 1 else "✅ SAFE"
    print(f"{pkg.name}: {status}")
```

## 📈 Performance

The two-stage approach typically achieves:
- **High precision** on obvious threats (Stage 1)
- **Improved recall** through behavioral analysis (Stage 2)
- **Better overall accuracy** than individual models
- **Reduced false positives** compared to single-stage systems

## 🔍 Features Deep Dive

### Heuristic Features (Stage 1)
1. **Suspicious Keywords**: Detects packages with names containing security-related terms
2. **Typosquat Detection**: Identifies packages similar to popular ones (e.g., "reqeusts" vs "requests")
3. **Version Anomalies**: Flags unusual version patterns like "1337.42.0" or "0.0.0"
4. **Name Entropy**: High randomness in package names often indicates malicious intent
5. **Pattern Matching**: Short names with embedded numbers

### Behavioral Features (Stage 2)
1. **File Size Analysis**: Unusual package sizes for their claimed functionality
2. **Dependency Patterns**: Suspicious dependency counts or relationships
3. **Author Analysis**: Entropy and patterns in author information
4. **Semantic Coherence**: Alignment between package name and description
5. **TF-IDF Analysis**: Text analysis of package descriptions

## 🧪 Demo Features

The interactive demo (`demo.py`) includes:

1. **Basic Demo**: Quick demonstration with synthetic data
2. **DataDog Analysis**: Real-world malicious package detection
3. **Feature Analysis**: Deep dive into feature extraction
4. **Model Comparison**: Performance comparison between approaches
5. **Help System**: Comprehensive documentation

## 📚 Technical Details

### Algorithms Used

**Perceptron**:
- Linear classifier for binary classification
- Fast training and prediction
- Ideal for rule-based features
- Acts as initial filter

**AdalineSGD**:
- Adaptive Linear Neuron with Stochastic Gradient Descent
- Continuous output with threshold
- Handles complex feature interactions
- Refines initial classifications

### Feature Engineering

The system uses sophisticated feature extraction:
- **Text Analysis**: TF-IDF vectorization of descriptions
- **Metadata Analysis**: Package size, dependencies, versioning
- **Similarity Metrics**: Edit distance for typosquat detection
- **Entropy Calculations**: Randomness analysis for suspicious patterns

## 🛠️ Files Structure

```
├── malicious_package_detector.py  # Core detection system
├── datadog_integration.py         # DataDog dataset integration
├── demo.py                        # Interactive demonstration
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

## ⚡ Real-World Applications

This system could be integrated into:
- **Package Managers**: Pre-installation security checks
- **CI/CD Pipelines**: Automated dependency scanning
- **Security Tools**: Supply chain monitoring
- **Enterprise Systems**: Internal package repositories

## 🚨 Limitations

- **Dataset Bias**: Trained on specific malicious patterns
- **Evasion**: Sophisticated attackers may bypass detection
- **False Positives**: Legitimate packages may be flagged
- **Performance**: Two-stage system adds computational overhead

## 🤝 Contributing

This is a demonstration project showcasing ML techniques for cybersecurity. Contributions for educational improvements are welcome.

## 📄 License

This project is for educational purposes. The DataDog dataset has its own Apache-2.0 license.

## 🔗 References

- [DataDog Malicious Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- [Supply Chain Security Research](https://securitylabs.datadoghq.com/)
- [Python Machine Learning by Sebastian Raschka](https://github.com/rasbt/python-machine-learning-book-3rd-edition)

---

**⚠️ Disclaimer**: This repository contains references to malicious software for research purposes. Do not run malicious packages on production systems.