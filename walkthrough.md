# SecureCyber IDS/IPS — Project Walkthrough

A complete technical walkthrough of the SecureCyber AI-powered Intrusion Detection and Prevention System.

---

## Project Overview

SecureCyber IDS/IPS is a real-time, multi-layer intrusion detection system designed for internal network security. It combines signature-based detection, machine learning classifiers, anomaly detection, and autonomous intelligence into a unified platform with a neon-themed dashboard.

**Tech Stack:** Python 3.10+ · FastAPI · XGBoost · Isolation Forest · Scapy · MongoDB · Redis · Prometheus · Grafana · Chart.js · Docker

---

## Architecture

The system follows a pipeline architecture with 10 execution phases:

```
Packet Capture / Simulation
        ↓
Feature Extraction (17 features + CIC flows)
        ↓
┌──────────────────────────────────────────┐
│         Multi-Layer Detection            │
│  Signatures │ XGBoost │ DDoS │ Anomaly   │
└──────────────────────────────────────────┘
        ↓
Drift Monitoring (Z-score)
        ↓
Risk Fusion (weighted composite scoring)
        ↓
Alert Processing Pipeline
  → Fusion → Dedup → MITRE → Incident Response → LLM
        ↓
RL Optimizer (Q-learning threshold tuning)
        ↓
WebSocket Broadcast → Dashboard (5 pages)
```

![System Architecture](docs/screenshots/architecture.png)

---

## Dashboard Pages

### 1. Dashboard — Real-Time Monitoring
The main page shows live network status (packet count, threats blocked, attack rate), 3D network topology, incident response cards, attack distribution chart, and attack timeline.

![Dashboard](docs/screenshots/dashboard.png)

### 2. Analytics — Threat Intelligence
Shows severity distribution (Critical/High/Medium/Low), attack trend timeline, MITRE ATT&CK coverage heatmap (14 tactics), top source IPs table, and signature effectiveness ranking.

![Analytics](docs/screenshots/analytics.png)

### 3. Incidents — Response Management
Displays incident timeline with severity badges, automated response actions per incident (block_source_ip, increase_monitoring, capture_traffic, notify_team), incident statistics, and playbook library.

![Incidents](docs/screenshots/incidents.png)

### 4. Models — AI/ML Management
Shows model version, health status, drift events count, shadow model status, RL threshold value, evaluation count, last RL action, auto-adjustment count, retraining history, and Q-table state.

![Models](docs/screenshots/models.png)

### 5. Settings — System Configuration
Displays feature toggles (RL Optimizer, Incident Response, Analytics, Auto Retrain, Kill Chain Detection), LLM Analyzer status (Ollama integration), signature database (32 rules with severity tags), and system configuration values.

![Settings](docs/screenshots/settings.png)

---

## Core Modules

### Detection Engines (`backend/app/detectors/`)

| Detector | File | Method |
|----------|------|--------|
| **Signature Engine** | `signature_engine.py` + `signatures.yaml` | 32 YAML rules matching regex patterns in payloads |
| **Rule-Based Detector** | `rule_based.py` | Wraps the signature engine for the detector interface |
| **XGBoost Classifier** | `xgboost_detector.py` | ML model trained on CICIDS dataset, threshold controlled by RL |
| **DDoS Detector** | `ddos_detector.py` | Rate-based heuristics (>100 pkt/s per source IP) |
| **Isolation Forest** | `isolation_forest.py` | Anomaly detection with adaptive thresholds |

### Intelligence Modules (`backend/app/`)

| Module | File | Function |
|--------|------|----------|
| **Risk Fusion** | `risk.py` | Weighted composite score: XGBoost (55%) + Anomaly (30%) + Drift (15%) |
| **Kill Chain Correlator** | `correlator.py` | 7-stage attack progression tracking per source IP |
| **MITRE ATT&CK** | `mitre_attack.py` | Maps alerts to 13 techniques across 14 tactics |
| **Incident Response** | `incident_response.py` | 8 attack-specific playbooks with auto/manual steps |
| **RL Optimizer** | `rl_optimizer.py` | Q-learning threshold tuning, evaluated every 50 alerts |
| **Drift Monitor** | `drift.py` | Feature distribution Z-score test with cooldown |
| **Model Updater** | `model_updater.py` | Shadow A/B retraining when drift exceeds threshold |
| **LLM Analyzer** | `llm_analyzer.py` | Ollama/Mistral integration for TP/FP classification |

### Infrastructure (`backend/app/`)

| Module | File | Function |
|--------|------|----------|
| **Sensors** | `sensors.py` | SensorWorker: packet processing pipeline orchestrator |
| **Packet Capture** | `packet_capture.py` | Scapy-based live capture with Npcap on Windows |
| **Features** | `features.py` | 17-feature extraction + CIC flow features |
| **Database** | `db.py` | MongoDB wrapper with automatic in-memory fallback |
| **Config** | `config.py` | Pydantic settings loaded from `.env` |
| **Cache** | `cache.py` | TTL-based in-memory cache |
| **Auth** | `auth.py` | JWT creation/validation |
| **Metrics** | `metrics.py` | Prometheus metrics collector |

---

## Detection Pipeline Flow

When a packet enters the system:

1. **Feature Extraction** — 17 features extracted (packet size, flags, ports, payload, timing stats)
2. **Baseline Update** — Rolling statistics updated for the sensor location
3. **Parallel Detection** — All 4 detectors run on the same packet simultaneously
4. **Drift Check** — Z-score test on feature distributions
5. **Risk Fusion** — Weighted composite score computed from all detector outputs
6. **Alert Fusion** — Multiple alerts from same packet merged into one (if enabled)
7. **Noise Suppression** — Anomaly/DDoS from private IPs filtered as likely false positives
8. **Deduplication** — SHA-1 hash prevents duplicate alerts within 30-second window
9. **MITRE Enrichment** — Alert mapped to MITRE ATT&CK techniques
10. **Incident Response** — Matched to one of 8 playbooks
11. **LLM Triage** — Async TP/FP classification (if Ollama available)
12. **RL Feedback** — Heuristic TP/FP fed to optimizer; LLM corrects if it disagrees
13. **Storage** — Alert persisted to MongoDB (or in-memory)
14. **Correlation** — Added to kill chain tracker; triggers kill chain alert if ≥3 stages
15. **Broadcast** — Sent to all WebSocket clients in real-time

---

## ML Training Pipeline

Pre-trained models ship in `models/cic/`. The training pipeline:

```
Raw CICIDS CSV
    ↓ preprocess_cic.py (clean, normalize, time-split)
Processed Features
    ↓ train_models.py (XGBoost binary classifier)
Model Artifacts
    ├── attack_classifier_xgb.json (185 KB)
    ├── le_binary.pkl
    ├── le_category.pkl
    ├── model_metadata.json
    └── model_metrics.json
```

Evaluation scripts: `evaluate_models.py`, `evaluate_cross_dataset.py`, `eval_holdout_days.py`, `tune_xgb_holdout.py`

---

## Deployment Options

### Local Development
```bash
python -m venv .venv && .\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
cd backend && python main.py
```

### Docker Compose (6 services)
```bash
docker compose up --build
# Backend, MongoDB, Redis, Prometheus, Grafana, Nginx
```

### Production
```bash
cd deploy && docker compose -f docker-compose.prod.yml up --build -d
```

---

## Monitoring Stack

- **Prometheus** (`monitoring/prometheus.yml`) — Scrapes `/metrics` every 15s
- **Grafana** (`monitoring/grafana_dashboard.json`) — Pre-built dashboards
- **Alert Rules** (`monitoring/alert_rules.yml`) — High alert rate, latency spike, drift, downtime
- **Application Logs** — `backend/logs/ids.log` + `backend/logs/audit.log`

---

## Test Suite

```bash
pytest                              # Full suite
pytest tests/test_integration.py    # End-to-end pipeline
pytest tests/test_api.py            # 20+ API endpoints
pytest tests/test_detectors.py      # All 4 detectors
pytest tests/test_risk_fusion.py    # Risk scoring
pytest tests/test_websocket.py      # WebSocket flows
```

The integration test validates: all API endpoints, signature detection → correlation → kill chain, incident response, RL optimizer, model updater drift detection, and MITRE ATT&CK enrichment.

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `backend/main.py` | Entry point (runs uvicorn) |
| `backend/app/main.py` | FastAPI app, all routes, lifespan, WebSocket |
| `backend/app/sensors.py` | SensorWorker — the packet processing pipeline |
| `backend/app/config.py` | All settings from `.env` |
| `backend/app/detectors/signatures.yaml` | 32 detection rules |
| `frontend/index.html` | Dashboard SPA (5 pages) |
| `frontend/script.js` | 65 KB client-side logic |
| `docker-compose.yml` | Full-stack deployment |
| `scripts/conference_demo.py` | 5-stage kill chain demo |
| `scripts/setup_env.ps1` | Windows one-click setup |

---

*Built as a B.Tech Capstone Project — SecureCyber IDS/IPS v2.0.0*