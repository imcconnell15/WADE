# WADE — Wide-Area Data Extraction

*A modular DFIR automation framework for staging, routing, and processing forensic artifacts at scale—built for austere ops, friendly to Splunk, and designed for real-world incident response.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Overview

WADE is a comprehensive forensic artifact processing pipeline that automatically:
- **Classifies** incoming evidence (E01, memory dumps, VM images, disk images, network configs)
- **Routes** artifacts through appropriate forensic tools (Volatility, Dissect, Hayabusa, Plaso, YARA, Bulk Extractor)
- **Enriches** data with metadata, host context, and case information
- **Outputs** normalized JSONL for Splunk ingestion and analysis

### Key Features

✅ **Idempotent & Auditable** — Deterministic installs, per-file JSON event logs, SQLite-backed deduplication  
✅ **Modular Architecture** — Independent classifiers, workers, and routing engine  
✅ **Configuration-Driven** — YAML + environment variables for flexible tool selection  
✅ **Online or Offline** — Works with pinned packages; air-gapped operation ready  
✅ **Ops-Friendly** — systemd units, logrotate policies, comprehensive logging  
✅ **Splunk-Native** — Direct integration with Splunk forwarders and indexes

---

## 🏗️ Architecture

```mermaid
graph TB
    A[Staging Directories] --> B[StagingDaemon]
    B --> C[Classifier Registry]
    C --> D[Tool Router]
    D --> E[Ticket Builder]
    E --> F[Queue]
    F --> G[Queue Runner]
    G --> H[Worker Dispatch]
    H --> I1[Volatility Worker]
    H --> I2[Dissect Worker]
    H --> I3[Hayabusa Worker]
    H --> I4[Plaso Worker]
    H --> I5[YARA Worker]
    H --> I6[Bulk Extractor Worker]
    I1 --> J[JSONL Output]
    I2 --> J
    I3 --> J
    I4 --> J
    I5 --> J
    I6 --> J
    J --> K[Splunk]
