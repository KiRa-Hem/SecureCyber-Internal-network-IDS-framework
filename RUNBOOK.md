# SecureCyber IDS/IPS — Windows Runbook

Step-by-step guide to deploy and run the system on Windows.

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB | 50+ GB SSD |
| OS | Windows 10 / Server 2019+ | Windows 10/11 / Server 2022+ |
| Python | 3.10+ | 3.10+ |

## Prerequisites

1. **Python 3.10+** — [python.org](https://python.org) (check "Add Python to PATH")
2. **Git** — [git-scm.com](https://git-scm.com/download/win)
3. **Npcap** — [nmap.org/npcap](https://nmap.org/npcap/) (select "WinPcap API-compatible Mode")
4. **MongoDB** (optional) — Local or [MongoDB Atlas](https://www.mongodb.com/atlas)

Verify:
```cmd
python --version
git --version
```

---

## Installation

### Step 1: Clone & Navigate
```powershell
git clone https://github.com/KiRa-Hem/SecureCyber-Internal-network-IDS-framework.git
cd SecureCyber-Internal-network-IDS-framework
```

### Step 2: Create Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> If you get an execution policy error:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### Step 3: Install Dependencies
```powershell
pip install --upgrade pip
pip install -r backend\requirements.txt
```

### Step 4: Create Directories
```powershell
mkdir backend\data -Force
mkdir backend\logs -Force
```

### Step 5: Configure Environment
```powershell
copy backend\.env.example backend\.env
```

Edit `backend\.env`:
```env
# Generate tokens: python -c "import secrets; print(secrets.token_hex(32))"
API_TOKEN=<your-token>
ADMIN_TOKEN=<your-token>
JWT_SECRET=<your-secret>

# Demo mode (no live capture needed)
ENABLE_PACKET_CAPTURE=false
ENABLE_SIMULATION=true

# OR live capture (requires Admin + Npcap)
# ENABLE_PACKET_CAPTURE=true
# NETWORK_INTERFACE=Wi-Fi
# ENABLE_SIMULATION=false
```

### Step 6: Set PYTHONPATH
```powershell
$env:PYTHONPATH = "$PWD\backend"
```

### Step 7: Start Server
```powershell
cd backend
python main.py
```

Server runs at **http://localhost:8000**

---

## Demo Mode

### Quick Demo (all-in-one)
```powershell
.\scripts\setup_env.ps1     # First-time only
.\scripts\run_demo.ps1      # Starts everything
```

### Conference Demo
```powershell
# In a separate terminal (with venv activated)
python scripts\conference_demo.py
```

### Traffic Simulator
```powershell
python scripts\traffic_simulator.py
```

---

## Docker Deployment

```powershell
# Create .env in project root with API_TOKEN, ADMIN_TOKEN, JWT_SECRET
docker compose up --build
```

Services: Backend (:8000), MongoDB (:27017), Redis (:6379), Prometheus (:9090), Grafana (:3000), Frontend (:80)

---

## Access Points

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |

---

## Testing

```powershell
cd <project-root>
$env:PYTHONPATH = "$PWD\backend"
pytest
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'app'` | Set `$env:PYTHONPATH = "$PWD\backend"` |
| MongoDB unavailable warning | Normal — system uses in-memory storage |
| Permission denied (capture) | Run PowerShell as Administrator |
| Npcap not found | Install from nmap.org/npcap with WinPcap mode |
| No alerts on dashboard | Set `ENABLE_SIMULATION=true` in `.env` |
| Execution policy error | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |

---

## Production Hardening

- [ ] Terminate TLS at reverse proxy
- [ ] Use strong random tokens (32+ bytes)
- [ ] Store secrets in a secrets manager
- [ ] Enable rate limiting (see `deploy/nginx.conf`)
- [ ] Use managed MongoDB with backups
- [ ] Schedule periodic model retraining
- [ ] Disable `ENABLE_SIMULATION` in production