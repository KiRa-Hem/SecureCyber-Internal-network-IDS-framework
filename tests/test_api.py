import pytest
import os
import sys
from unittest.mock import patch

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app
import app.main as main_module

def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "version" in data
    assert "packet_capture" in data
    assert "detectors" in data

def test_get_blocklist(client, auth_headers):
    """Test get blocklist endpoint."""
    response = client.get("/api/blocklist", headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "blocklist" in data

def test_protected_api_requires_auth_configuration(client, monkeypatch):
    monkeypatch.setattr(main_module.settings, "API_TOKEN", None, raising=False)
    monkeypatch.setattr(main_module.settings, "ADMIN_TOKEN", None, raising=False)
    monkeypatch.setattr(main_module.settings, "JWT_SECRET", None, raising=False)
    monkeypatch.setattr(main_module.settings, "AUTH_ALLOW_INSECURE_NO_AUTH", False, raising=False)

    response = client.get("/api/blocklist")
    assert response.status_code == 503

def test_viewer_token_cannot_access_admin_endpoint(client, monkeypatch):
    monkeypatch.setattr(main_module.settings, "API_TOKEN", "viewer-token", raising=False)
    monkeypatch.setattr(main_module.settings, "ADMIN_TOKEN", "admin-token", raising=False)
    monkeypatch.setattr(main_module.settings, "JWT_SECRET", None, raising=False)
    monkeypatch.setattr(main_module.settings, "AUTH_ALLOW_INSECURE_NO_AUTH", False, raising=False)

    response = client.post(
        "/api/block-ip",
        headers={"Authorization": "Bearer viewer-token"},
        json={
            "ip": "192.168.1.100",
            "reason": "Test blocking",
            "ttl_seconds": 3600
        },
    )
    assert response.status_code == 403

def test_block_ip(client, auth_headers):
    """Test block IP endpoint."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.block_ip.return_value = True
        
        response = client.post(
            "/api/block-ip",
            headers=auth_headers,
            json={
                "ip": "192.168.1.100",
                "reason": "Test blocking",
                "ttl_seconds": 3600
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "IP 192.168.1.100 blocked" in data["message"]
        
        # Verify mitigation was called
        mock_mitigation.block_ip.assert_called_once_with("192.168.1.100", "Test blocking", 3600)

def test_block_ip_failure(client, auth_headers):
    """Test block IP endpoint with failure."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.block_ip.return_value = False
        
        response = client.post(
            "/api/block-ip",
            headers=auth_headers,
            json={
                "ip": "192.168.1.100",
                "reason": "Test blocking",
                "ttl_seconds": 3600
            }
        )
        
        assert response.status_code == 400
        assert "Failed to block IP" in response.json()["detail"]

def test_unblock_ip(client, auth_headers):
    """Test unblock IP endpoint."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.unblock_ip.return_value = True
        
        response = client.post(
            "/api/unblock-ip",
            headers=auth_headers,
            json={
                "ip": "192.168.1.100"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "IP 192.168.1.100 unblocked" in data["message"]
        
        # Verify mitigation was called
        mock_mitigation.unblock_ip.assert_called_once_with("192.168.1.100")

def test_unblock_ip_failure(client, auth_headers):
    """Test unblock IP endpoint with failure."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.unblock_ip.return_value = False
        
        response = client.post(
            "/api/unblock-ip",
            headers=auth_headers,
            json={
                "ip": "192.168.1.100"
            }
        )
        
        assert response.status_code == 400
        assert "Failed to unblock IP" in response.json()["detail"]

def test_get_alerts(client, auth_headers):
    """Test get alerts endpoint."""
    # Mock db
    with patch('app.main.db') as mock_db:
        mock_db.get_alerts.side_effect = [
            [
                {
                    "id": "alert-123",
                    "timestamp": 1634567890,
                    "source_ip": "192.168.1.100",
                    "dest_ip": "10.0.0.1",
                    "attack_types": ["sql_injection"],
                    "confidence": 0.95
                },
                {
                    "id": "alert-456",
                    "timestamp": 1634567891,
                    "source_ip": "192.168.1.101",
                    "dest_ip": "10.0.0.2",
                    "attack_types": ["xss"],
                    "confidence": 0.85
                }
            ],
            [
                {
                    "id": "alert-456",
                    "timestamp": 1634567891,
                    "source_ip": "192.168.1.101",
                    "dest_ip": "10.0.0.2",
                    "attack_types": ["xss"],
                    "confidence": 0.85
                }
            ]
        ]
        mock_db.count_alerts.return_value = 2
        
        response = client.get("/api/alerts", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total" in data
        assert len(data["alerts"]) == 2
        assert data["total"] == 2
        
        # Test pagination
        response = client.get("/api/alerts?limit=1&offset=1", headers=auth_headers)
        data = response.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["id"] == "alert-456"

def test_get_alerts_empty(client, auth_headers):
    """Test get alerts endpoint with no alerts."""
    # Mock db
    with patch('app.main.db') as mock_db:
        mock_db.get_alerts.return_value = []
        mock_db.count_alerts.return_value = 0
        
        response = client.get("/api/alerts", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total" in data
        assert len(data["alerts"]) == 0
        assert data["total"] == 0

def test_get_stats(client, auth_headers):
    """Test get stats endpoint."""
    # Mock metrics collector
    with patch('app.main.metrics_collector') as mock_metrics:
        mock_metrics.packets_processed_count = 1000
        mock_metrics.alerts_generated_count = 5
        
        response = client.get("/api/stats", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["packets_analyzed"] == 1000
        assert data["threats_detected"] == 5
        assert data["active_hosts"] == 14
        assert "sensor_status" in data
        assert "top_attackers" in data

def test_simulate_attack(client, auth_headers, monkeypatch):
    """Test simulate attack endpoint."""
    monkeypatch.setattr(main_module.settings, "ENABLE_SIMULATION", True, raising=False)
    monkeypatch.setattr(main_module.settings, "API_TOKEN", "test-token", raising=False)
    monkeypatch.setattr(main_module.settings, "ADMIN_TOKEN", "test-token", raising=False)
    monkeypatch.setattr(main_module.settings, "AUTH_ALLOW_INSECURE_NO_AUTH", False, raising=False)

    response = client.post(
        "/api/simulate-attack",
        headers=auth_headers,
        json={
            "attack_type": "SQL Injection",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1\r\nHost: example.com"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Attack simulated"

def test_metrics_endpoint(client, auth_headers):
    """Test Prometheus metrics endpoint."""
    # Mock metrics collector output
    with patch('app.main.metrics_collector') as mock_metrics:
        mock_metrics.get_metrics.return_value = b"# HELP ids_packets_processed_total Total number of packets processed\n"
        
        response = client.get("/metrics", headers=auth_headers)
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"

def test_root_redirect(client):
    """Test root endpoint redirects to login."""
    response = client.get("/")
    
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_dashboard(client):
    """Test dashboard endpoint."""
    response = client.get("/dashboard")
    
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
