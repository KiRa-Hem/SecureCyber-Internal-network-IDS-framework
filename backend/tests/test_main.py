import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("API_TOKEN", "test-token")
os.environ.setdefault("ADMIN_TOKEN", "test-token")
os.environ.setdefault("ENABLE_PACKET_CAPTURE", "false")

from app.main import app

client = TestClient(app)
AUTH_HEADERS = {"Authorization": "Bearer test-token"}

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "<title>SecureCyber IDS Dashboard</title>" in response.text

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_block_ip():
    response = client.post(
        "/api/block-ip",
        headers=AUTH_HEADERS,
        json={"ip": "192.0.2.1", "reason": "Test block"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_unblock_ip():
    # First block an IP
    client.post(
        "/api/block-ip",
        headers=AUTH_HEADERS,
        json={"ip": "192.0.2.1", "reason": "Test block"}
    )
    
    # Then unblock it
    response = client.post(
        "/api/unblock-ip",
        headers=AUTH_HEADERS,
        json={"ip": "192.0.2.1"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_isolate_node():
    response = client.post(
        "/api/isolate-node",
        headers=AUTH_HEADERS,
        json={"node_id": "web-01", "reason": "Test isolation"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_remove_isolation():
    # First isolate a node
    client.post(
        "/api/isolate-node",
        headers=AUTH_HEADERS,
        json={"node_id": "web-01", "reason": "Test isolation"}
    )
    
    # Then remove isolation
    response = client.post(
        "/api/remove-isolation",
        headers=AUTH_HEADERS,
        json={"node_id": "web-01"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_get_blocklist():
    response = client.get("/api/blocklist", headers=AUTH_HEADERS)
    assert response.status_code == 200
    assert "blocklist" in response.json()

def test_get_isolated_nodes():
    response = client.get("/api/isolated-nodes", headers=AUTH_HEADERS)
    assert response.status_code == 200
    assert "isolated_nodes" in response.json()

def test_get_alerts():
    response = client.get("/api/alerts", headers=AUTH_HEADERS)
    assert response.status_code == 200
    assert "alerts" in response.json()

def test_get_stats():
    response = client.get("/api/stats", headers=AUTH_HEADERS)
    assert response.status_code == 200
    assert "packets_analyzed" in response.json()
    assert "threats_detected" in response.json()

# --- LLM endpoint tests ---

def test_llm_status():
    response = client.get("/api/llm-status", headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert "enabled" in data
    assert "model" in data
    assert "total_requests" in data

def test_llm_analyze_alert():
    response = client.post(
        "/api/llm-analyze",
        headers=AUTH_HEADERS,
        json={
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "protocol": "TCP",
            "attack_types": ["SQL Injection"],
            "confidence": 0.95,
            "payload_snippet": "' OR 1=1 --",
            "description": "SQL Injection detected",
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert data["verdict"] in {"true_positive", "false_positive", "uncertain"}
    assert "confidence" in data

def test_llm_analyze_payload():
    response = client.post(
        "/api/llm-payload",
        headers=AUTH_HEADERS,
        json={
            "payload": "<script>alert('XSS')</script>",
            "protocol": "TCP",
            "src_port": 12345,
            "dst_port": 80,
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "is_malicious" in data

