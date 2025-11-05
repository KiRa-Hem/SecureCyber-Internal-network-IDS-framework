import asyncio
import json
import time
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from pydantic import BaseModel

from app.config import settings
from app.db import init_db
from app.packet_capture import PacketCapture
from app.sensors import SensorWorker
from app.mitigation import mitigation
from app.metrics import metrics_collector
from app.cache import cache_manager
from app.correlator import correlator
from app.detectors.rule_based import RuleBasedDetector
from app.detectors.random_forest import RandomForestDetector
from app.detectors.dnn import DNNDetector
from app.detectors.ddos_detector import DoSDetector

# Initialize database
init_db()

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

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        metrics_collector.update_connections(len(self.active_connections))
    
    def disconnect(self, websocket: WebSocket):
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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Templates
templates = Jinja2Templates(directory="frontend")

# Lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("Starting SecureCyber IDS/IPS System...")
    
    # Initialize detectors
    global detectors
    detectors = {
        "rule_based": RuleBasedDetector(),
        "random_forest": RandomForestDetector(),
        "dnn": DNNDetector(),
        "dos": DoSDetector()
    }
    
    # Initialize packet capture if enabled
    global packet_capture
    if settings.enable_packet_capture:
        packet_capture = PacketCapture(
            interface=settings.network_interface,
            capture_filter=settings.capture_filter
        )
        packet_capture.start_capture()
    
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
    
    # Stop packet capture
    if packet_capture:
        packet_capture.stop_capture()
    
    # Stop sensor workers
    for worker in sensor_workers.values():
        worker.stop()

app.router.lifespan_context = lifespan

# API endpoints
@app.get("/", response_class=HTMLResponse)
async def get(request: Request):
    """Root endpoint - directly to dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "version": "2.0.0",
        "packet_capture": "enabled" if packet_capture else "disabled",
        "detectors": list(detectors.keys())
    }

@app.post("/api/simulate-attack")
async def simulate_attack(request: SimulateAttackRequest):
    """Simulate an attack for testing purposes."""
    attack_data = {
        "id": f"sim-{int(time.time())}",
        "timestamp": int(time.time()),
        "source_ip": request.source_ip,
        "dest_ip": request.target_ip,
        "protocol": "TCP",
        "attack_types": [request.attack_type],
        "confidence": 0.95,
        "payload_snippet": request.payload,
        "path": ["router-1", "fw-1", "switch-1", "web-01"],
        "mitigation": {"action": "flagged", "by": "simulator"},
        "attacker_node": "router-1",
        "target_node": "web-01",
        "targeted_data": ["user_data"]
    }
    
    # Broadcast to all connected clients
    await manager.broadcast_alert(attack_data)
    
    return {"status": "success", "message": "Attack simulated"}

@app.get("/api/blocklist")
async def get_blocklist():
    """Get the current blocklist."""
    return {"blocklist": mitigation.get_blocklist()}

@app.post("/api/block-ip")
async def block_ip(request: BlockIPRequest):
    """Block an IP address."""
    if settings.enable_real_mitigation and settings.mitigation_confirmation_token:
        print(f"WARNING: Real mitigation enabled. Blocking IP: {request.ip}")
    
    success = mitigation.block_ip(request.ip, request.reason, request.ttl_seconds)
    if success:
        return {"status": "success", "message": f"IP {request.ip} blocked"}
    else:
        raise HTTPException(status_code=400, detail="Failed to block IP")

@app.post("/api/unblock-ip")
async def unblock_ip(request: UnblockIPRequest):
    """Unblock an IP address."""
    success = mitigation.unblock_ip(request.ip)
    if success:
        return {"status": "success", "message": f"IP {request.ip} unblocked"}
    else:
        raise HTTPException(status_code=400, detail="Failed to unblock IP")

@app.get("/api/alerts")
async def get_alerts(limit: int = 10, offset: int = 0):
    """Get recent alerts."""
    alerts = cache_manager.get("recent_alerts")
    if not alerts:
        alerts = []
    
    return {
        "alerts": alerts[offset:offset + limit],
        "total": len(alerts)
    }

@app.get("/api/stats")
async def get_stats():
    """Get current statistics."""
    return {
        "packets_analyzed": metrics_collector.packets_processed._value.get(),
        "threats_detected": metrics_collector.alerts_generated._value.get(),
        "active_hosts": 14,
        "sensor_status": {loc: "online" for loc in settings.sensor_locations},
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
    # Accept connection
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive
            data = await websocket.receive_text()
            # Process any incoming messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Metrics endpoint for Prometheus
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import generate_latest
    return generate_latest()

async def periodic_stats_update():
    """Periodically send stats updates to all connected clients."""
    while True:
        await asyncio.sleep(5)  # Send stats every 5 seconds
        
        # Get stats
        stats = {
            "packets_analyzed": metrics_collector.packets_processed._value.get(),
            "threats_detected": metrics_collector.alerts_generated._value.get(),
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

# Serve static files for frontend
@app.get("/{path:path}")
async def static_files(path: str):
    """Serve static files."""
    file_path = os.path.join("frontend", path)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return RedirectResponse(url="/")
