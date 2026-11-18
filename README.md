# Enterprise SOC Log Analyzer & Incident Triage Engine

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: SOC](https://img.shields.io/badge/Domain-SOC%20Engineering-red.svg)]()

> **A high-performance security log parser and incident triage engine designed to ingest authentication streams, correlate logon failures, and detect credential stuffing and anomalous off-hours access.**

---

## 🏗️ System Architecture

```text
       Security Log Streams
(Windows Event Logs, Sysmon, Auth)
                │
                ▼
      [ Regex Ingestion Engine ]
                │
    ┌───────────┴───────────┐
    ▼                       ▼
Time-Window Correlator   Temporal Anomaly Detector
(Sliding Window = 60s)   (00:00 - 05:00 UTC)
    │                       │
    ▼                       ▼
Brute-Force Flagging     Off-Hours Access
    │                       │
    └───────────┬───────────┘
                ▼
     Structured SOC Alert Triage
  (Console / Markdown Incident Queue)
```

---

## 🚀 Quickstart

```bash
# Clone the repository
git clone https://github.com/enggr-bilal/soc-log-analyzer.git
cd soc-log-analyzer

# Run analyzer against sample data
python3 src/analyzer.py --log data/sample_auth.log --threshold 4
```

---

## 👨‍💻 Author
**Muhammad Bilal** — Cybersecurity Engineer & Data Scientist
