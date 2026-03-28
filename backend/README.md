# SecureCyber IDS Backend

FastAPI backend for the SecureCyber IDS/IPS platform.

## What it provides
- REST APIs for alerts, stats, blocklist, isolation, simulation, and token issuance.
- WebSocket stream for real-time dashboard updates (`/ws`).
- Detection pipeline with rule-based, DoS, XGBoost, and Isolation Forest anomaly detection (dual pipeline).
- MongoDB-backed persistence with in-memory fallback.
- Prometheus metrics endpoint (`/metrics`).

## Run locally
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Server defaults to `http://localhost:8000`.

## Required security configuration
Set these in `backend/.env` or process environment:
- `API_TOKEN`
- `ADMIN_TOKEN`
- `JWT_SECRET`

By default, protected APIs and WebSocket access are denied if auth is not configured.
For local throwaway demos only, you can set:
- `AUTH_ALLOW_INSECURE_NO_AUTH=true`

## Demo login endpoint
`POST /api/login` requires:
- `DEMO_LOGIN_USERNAME`
- `DEMO_LOGIN_PASSWORD`

No hardcoded default credentials are shipped.

## Database
MongoDB is the primary datastore (`MONGODB_URI` or computed from `MONGO_*` vars).
Collections include:
- `alerts`
- `blocklist`
- `isolated_nodes`
- `audit_logs`
- `alert_feedback`

## Testing
From repo root:
```bash
pytest -q
```
