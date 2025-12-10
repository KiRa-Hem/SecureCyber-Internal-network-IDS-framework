# SecureCyber IDS/IPS

AI-powered intrusion detection and prevention for internal networks. A FastAPI backend drives real-time detection, mitigation, and metrics, while a neon-inspired dashboard streams events over WebSockets.

## Highlights
- Multi-layer detection: signature/rule-based, DDoS heuristics, RandomForest, and DNN models in `backend/app/detectors/`
- Real-time pipeline: sensor workers, correlator, mitigation engine, cache, and Prometheus metrics in `backend/app/`
- Dashboard: futuristic UI in `frontend/` with live alerts, topology view, packet inspector, and quick attack simulations
- Deployment ready: Docker Compose stack for backend, Redis, MongoDB, Prometheus, Grafana, and nginx fronting the static site
- Observability: `/metrics` for Prometheus plus prebuilt Grafana dashboard and alert rules in `monitoring/`
- Extensible: training scripts and pretrained artifacts in `models/` for retraining on KDD/CICIDS-style datasets

## Repository Layout
- `backend/` — FastAPI service, detectors, correlator, mitigation, config, and runtime entrypoint (`backend/main.py`)
- `frontend/` — static dashboard served by FastAPI or nginx
- `models/` — pretrained `.pth`/`.pkl` models plus `training_scripts/` for preprocessing and training
- `monitoring/` — Prometheus config, Grafana dashboard JSON, alert rules, nginx config for the compose stack
- `scripts/` — helper scripts (traffic simulation, attack simulation, environment setup, migrations)
- `tests/` — pytest suite for API, detectors, packet capture, and WebSocket flows
- `reference_ui/` — alternate/reference UI kept for design comparison

## Quickstart
### Option A: Docker Compose
1) Ensure Docker + Docker Compose are installed.  
2) Create `backend/.env` (see Configuration) or export environment variables.  
3) From the repo root:
```bash
docker compose up --build
```
4) Visit the dashboard at `http://localhost` (nginx). Backend API and docs live at `http://localhost:8000`.  
5) Prometheus: `http://localhost:9090`, Grafana: `http://localhost:3000` (default admin/admin unless changed).

### Option B: Local development (no containers)
```bash
python -m venv .venv
.\\.venv\\Scripts\\Activate  # PowerShell on Windows; use source .venv/bin/activate on Unix
pip install -r backend/requirements.txt
```
Create `backend/.env` (below), then run:
```bash
cd backend
python main.py  # runs uvicorn app.main:app on 0.0.0.0:8000
```
The dashboard and API are served from the same process at `http://localhost:8000`. Packet capture is disabled by default; enable it only on interfaces you control.

## Configuration
All runtime settings are managed via environment variables loaded from `backend/.env` (see `backend/app/config.py`). Example:
```env
# Core services
MONGO_USER=changeme
MONGO_PASSWORD=changeme
MONGO_CLUSTER=cluster-id.mongodb.net
MONGO_DB=Users
# Optional: override computed URI
# MONGODB_URI=mongodb://user:pass@host:27017/Users

# Packet capture
ENABLE_PACKET_CAPTURE=false
NETWORK_INTERFACE=auto
CAPTURE_FILTER=tcp or udp

# Redis cache/metrics
ENABLE_REDIS=false
REDIS_HOST=localhost
REDIS_PORT=6379

# Detection / mitigation
CONFIDENCE_THRESHOLD=0.7
ENABLE_REAL_MITIGATION=false
MITIGATION_CONFIRMATION_TOKEN=
BLOCKLIST_TTL_SECONDS=3600
SENSOR_LOCATIONS=edge,internal

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/ids.log
```
By default the system uses MongoDB for persistence; Redis is optional and can be disabled.

## How Detection Works
1) **Sensors** (`backend/app/sensors.py`) capture or simulate traffic per location, extract features, and push packets to detectors.  
2) **Detectors** combine rule-based signatures, DoS heuristics, RandomForest, and DNN models (`backend/app/detectors/`) to emit alerts with confidence scores.  
3) **Correlator** (`backend/app/correlator.py`) merges related alerts across sensors into higher-fidelity incidents.  
4) **Mitigation** (`backend/app/mitigation.py`) maintains blocklists and node isolation with TTLs; actions can be toggled off for dry runs.  
5) **Cache + Metrics** (`backend/app/cache.py`, `backend/app/metrics.py`) keep rolling stats, expose `/metrics`, and drive the live dashboard via WebSockets.  
6) **Frontend** (`frontend/`) receives `attack_detected` and `stats_update` messages over `/ws` to update the UI in real time.

## API & Realtime Interfaces
- `GET /` or `/dashboard` — serves the dashboard
- `GET /health` — liveness and build info
- `GET /api/alerts?limit=10&offset=0` — recent alerts from cache
- `GET /api/stats` — summarized counts and top attackers
- `GET /api/blocklist` — current blocklist
- `POST /api/block-ip` — body `{ "ip": "...", "reason": "...", "ttl_seconds": 3600 }`
- `POST /api/unblock-ip` — body `{ "ip": "..." }`
- `POST /api/simulate-attack` — inject a synthetic alert for UI/testing
- `GET /metrics` — Prometheus exposition format
- `WS /ws` — broadcasts `{type: "attack_detected" | "stats_update", data: ...}`

Examples:
```bash
curl -X POST http://localhost:8000/api/block-ip ^
  -H "Content-Type: application/json" ^
  -d "{\"ip\":\"203.0.113.5\",\"reason\":\"manual quarantine\",\"ttl_seconds\":1800}"

curl -X POST http://localhost:8000/api/simulate-attack ^
  -H "Content-Type: application/json" ^
  -d "{\"attack_type\":\"SQL Injection\",\"source_ip\":\"198.51.100.10\",\"target_ip\":\"10.0.0.5\",\"payload\":\"' OR '1'='1\"}"
```

## Frontend
The dashboard lives in `frontend/` and is served by FastAPI static routing or nginx in the compose stack. It includes:
- Live status tiles, alert list, packet inspector, and node inspector
- 3D-inspired network topology view with animated packet trails
- Quick simulation launcher to trigger sample attacks against the WebSocket feed

Customize styles in `frontend/style.css` and behaviors in `frontend/script.js`; the template uses Jinja2 when served via FastAPI.

## Models & Training
Pretrained RandomForest and DNN artifacts ship in `models/`. To retrain:
1) Prepare datasets (KDD Cup 99 or CICIDS) under `models/training_scripts/data/raw/`.  
2) Run preprocessing:
```bash
python models/training_scripts/preprocess_kdd.py --dataset kdd_10 --output-dir models/training_scripts/data/processed
```
3) Train and emit new artifacts:
```bash
python models/training_scripts/train_models.py --data-dir models/training_scripts/data/processed
```
Copy the resulting `.pth`/`.pkl` files into `models/` so the detectors load them at runtime.

## Monitoring
- Prometheus scrape config: `monitoring/prometheus.yml`
- Grafana dashboard JSON: `monitoring/grafana_dashboard.json`
- Alert rules: `monitoring/alert_rules.yml`
Metrics come from `GET /metrics`; the compose stack wires Prometheus and Grafana automatically.

## Testing
Run the suite from the repo root (tests add `backend/` to `PYTHONPATH`):
```bash
pytest
```

## License
MIT License. See `LICENSE` for details.
