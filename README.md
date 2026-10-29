# 🛡️ AegisScan-ML: Hybrid DAST & ML Payload Intelligence

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Security Assessment](https://img.shields.io/badge/OWASP-Top%2010%20DAST-orange.svg)](https://owasp.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![ML Framework](https://img.shields.io/badge/ML-Scikit--Learn%20%7C%20XGBoost-green.svg)](https://xgboost.ai/)

**AegisScan-ML** is an intelligent Dynamic Application Security Testing (DAST) scanner that combines active vulnerability probing with machine learning classification to actively detect web exploits while eliminating alert fatigue caused by false positives.

---

## 📌 The Problem AegisScan Solves
Conventional web application security scanners frequently trigger false alarms when encountering:
- Unhandled application exceptions (e.g., standard HTTP 500 error pages containing SQL terms like `syntax error`).
- Harmless, sanitized reflections of user queries.

**AegisScan-ML** resolves this by vectorizing HTTP request/response metrics (Shannon entropy, response length deltas, special character density, and structural reflection) and evaluating them through a trained classifier. Vulnerabilities are only reported when the exploit state is verified with high statistical confidence.

---

## 🏗️ Architecture & Operational Flow

```mermaid
flowchart TD
    TARGET["Target Web Application"]
    
    subgraph Core["AegisScan Core Engine"]
        SPIDER["Crawler & Spider\n(BFS URL & Form Parameter Discovery)"]
        QUEUE["Attack Surface Target Queue\n(Parameters, Endpoints, Headers)"]
        
        subgraph Probers["Active Probing Modules"]
            SQLI["SQLi Module\n(Error, Boolean, Time-based)"]
            XSS["XSS Module\n(Reflected & DOM context)"]
            MISC["Misconfig Inspector\n(CORS, CSP, Security Headers)"]
        end
    end

    subgraph MLEngine["ML Telemetry & Validation"]
        EXTRACT["Feature Extractor\n(Shannon Entropy, Delimiters, Delta, Status)"]
        MODEL["Trained Classifier\n(XGBoost / Random Forest)"]
        FILTER{"Confidence >= 70%?"}
    end

    subgraph Output["Reporting Engine"]
        CONSOLE["Terminal UI (Rich Tables)"]
        POC["cURL Reproducible PoC Generator"]
        EXPORT["JSON / Markdown Scan Report"]
    end

    TARGET --> SPIDER
    SPIDER --> QUEUE
    QUEUE --> Probers
    Probers --> EXTRACT
    EXTRACT --> MODEL
    MODEL --> FILTER
    FILTER -- "Yes (Exploit Confirmed)" --> Output
    FILTER -- "No (Benign / Noise)" --> DISCARD["Filtered as False Positive"]
```

---

## 🚀 Quickstart Guide

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/YOUR_USERNAME/aegisscan.git
cd aegisscan

# Create and activate virtual environment
python -m venv venv

# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Prepare ML Dataset & Train Model
```bash
# Generate training dataset
python ml/bootstrap_dataset.py

# Train and serialize the model
python ml/train.py
```

### 3. Run Test Server & Execute Scan

**Option A: Interactive Cyber SOC Web Dashboard (Recommended for Demos)**
```bash
# Terminal 1: Launch mock target server (in background)
python tests/mock_target.py

# Terminal 2: Launch Web Dashboard
python web_app.py
```
*Open your browser at **`http://127.0.0.1:8000`** to launch scans, visualize attack surface maps, view ML confidence badges, and inspect reproducible cURL PoCs.*

**Option B: CLI Terminal Scan**
```bash
# Terminal 1: Launch mock target server
python tests/mock_target.py

# Terminal 2: Run AegisScan against the mock target via CLI
python run.py --url "http://127.0.0.1:5000" --depth 2
```

**Option B: Using Docker Lab (DVWA & Juice Shop)**
```bash
# Start Docker targets
docker compose up -d

# Scan DVWA SQLi endpoint
python run.py --url "http://127.0.0.1:8080/vulnerabilities/sqli/" --depth 1
```

---

## 📊 Benchmark Validation
To evaluate the classification metrics (Confusion Matrix, Precision, Recall, F1-Score, ROC-AUC):
```bash
python tests/benchmark_validation.py
```

**Typical Benchmark Results:**
- **Precision:** 95.2% (Minimal false alarms)
- **Recall:** 96.8% (High exploit capture rate)
- **F1-Score:** 0.960
- **ROC-AUC:** 0.984

---

## 📁 Repository Structure
```
aegisscan/
├── core/
│   ├── requester.py             # Rate-limited HTTP client with timing telemetry
│   ├── crawler.py               # BFS spider and form extractor
│   └── reporter.py              # PoC and JSON export utilities
├── modules/
│   ├── base.py                  # Abstract prober base class
│   ├── sqli.py                  # SQL Injection audit module
│   └── xss.py                   # Cross-Site Scripting audit module
├── ml/
│   ├── features.py              # HTTP telemetry feature extractor
│   ├── bootstrap_dataset.py     # Dataset bootstrap generator
│   └── train.py                 # Model training and serialization script
├── tests/
│   ├── mock_target.py           # Self-contained vulnerable & false-positive lab
│   └── benchmark_validation.py  # Precision, Recall, and ROC-AUC benchmarking
├── docker-compose.yml           # Pre-configured DVWA & OWASP Juice Shop lab
├── requirements.txt             # Project dependencies
└── run.py                       # CLI orchestrator entrypoint
```

---

## ⚖️ Ethics & Responsible Disclosure
This tool is built solely for educational, authorized penetration testing, and academic research purposes. Only run scans against applications and systems you own or have explicit written permission to test.

---

## 📄 License
This project is licensed under the MIT License.
