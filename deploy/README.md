# Production Deployment (Minimum Hardening)

## 1) TLS certificates
Place certificates in `deploy/certs/`:
- `fullchain.pem`
- `privkey.pem`

## 2) Environment
Create `.env` (or export) with:
```
MONGODB_URI=...
MONGO_DB=ids
API_TOKEN=...
ADMIN_TOKEN=...
JWT_SECRET=...
```

## 3) Start
```bash
cd deploy
docker compose -f docker-compose.prod.yml up --build -d
```

## 4) Rate limiting
Defined in `deploy/nginx.conf`:
- API: 30 req/s (burst 60)
- WS: 10 req/s (burst 20)

## 5) HA
For real HA, run multiple `backend` replicas behind a load balancer
and move cache to Redis. Compose here is a minimal baseline.
