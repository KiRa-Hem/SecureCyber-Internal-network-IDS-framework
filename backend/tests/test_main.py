import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

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
        json={"ip": "192.0.2.1", "reason": "Test block"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_unblock_ip():
    # First block an IP
    client.post(
        "/api/block-ip",
        json={"ip": "192.0.2.1", "reason": "Test block"}
    )
    
    # Then unblock it
    response = client.post(
        "/api/unblock-ip",
        json={"ip": "192.0.2.1"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_isolate_node():
    response = client.post(
        "/api/isolate-node",
        json={"node_id": "web-01", "reason": "Test isolation"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_remove_isolation():
    # First isolate a node
    client.post(
        "/api/isolate-node",
        json={"node_id": "web-01", "reason": "Test isolation"}
    )
    
    # Then remove isolation
    response = client.post(
        "/api/remove-isolation",
        json={"node_id": "web-01"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_get_blocklist():
    response = client.get("/api/blocklist")
    assert response.status_code == 200
    assert "blocklist" in response.json()

def test_get_isolated_nodes():
    response = client.get("/api/isolated-nodes")
    assert response.status_code == 200
    assert "isolated_nodes" in response.json()

def test_get_alerts():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert "alerts" in response.json()

def test_get_stats():
    response = client.get("/api/stats")
    assert response.status_code == 200
    assert "packets_analyzed" in response.json()
    assert "threats_detected" in response.json()
