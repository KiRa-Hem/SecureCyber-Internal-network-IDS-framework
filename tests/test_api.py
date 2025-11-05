import pytest
import os
import sys
from unittest.mock import Mock, patch

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app

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

def test_get_blocklist(client):
    """Test get blocklist endpoint."""
    response = client.get("/api/blocklist")
    
    assert response.status_code == 200
    data = response.json()
    assert "blocklist" in data

def test_block_ip(client):
    """Test block IP endpoint."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.block_ip.return_value = True
        
        response = client.post(
            "/api/block-ip",
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

def test_block_ip_failure(client):
    """Test block IP endpoint with failure."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.block_ip.return_value = False
        
        response = client.post(
            "/api/block-ip",
            json={
                "ip": "192.168.1.100",
                "reason": "Test blocking",
                "ttl_seconds": 3600
            }
        )
        
        assert response.status_code == 400
        assert "Failed to block IP" in response.json()["detail"]

def test_unblock_ip(client):
    """Test unblock IP endpoint."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.unblock_ip.return_value = True
        
        response = client.post(
            "/api/unblock-ip",
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

def test_unblock_ip_failure(client):
    """Test unblock IP endpoint with failure."""
    # Mock mitigation
    with patch('app.main.mitigation') as mock_mitigation:
        mock_mitigation.unblock_ip.return_value = False
        
        response = client.post(
            "/api/unblock-ip",
            json={
                "ip": "192.168.1.100"
            }
        )
        
        assert response.status_code == 400
        assert "Failed to unblock IP" in response.json()["detail"]

def test_get_alerts(client):
    """Test get alerts endpoint."""
    # Mock cache manager
    with patch('app.main.cache_manager') as mock_cache:
        mock_cache.get.return_value = [
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
        ]
        
        response = client.get("/api/alerts")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total" in data
        assert len(data["alerts"]) == 2
        assert data["total"] == 2
        
        # Test pagination
        response = client.get("/api/alerts?limit=1&offset=1")
        data = response.json()
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["id"] == "alert-456"

def test_get_alerts_empty(client):
    """Test get alerts endpoint with no alerts."""
    # Mock cache manager
    with patch('app.main.cache_manager') as mock_cache:
        mock_cache.get.return_value = None
        
        response = client.get("/api/alerts")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total" in data
        assert len(data["alerts"]) == 0
        assert data["total"] == 0

def test_get_stats(client):
    """Test get stats endpoint."""
    # Mock metrics collector
    with patch('app.main.metrics_collector') as mock_metrics:
        mock_metrics.packets_processed._value.get.return_value = 1000
        mock_metrics.alerts_generated._value.get.return_value = 5
        
        response = client.get("/api/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert data["packets_analyzed"] == 1000
        assert data["threats_detected"] == 5
        assert data["active_hosts"] == 14
        assert "sensor_status" in data
        assert "top_attackers" in data

def test_simulate_attack(client):
    """Test simulate attack endpoint."""
    response = client.post(
        "/api/simulate-attack",
        json={
            "attack_type": "sql_injection",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1\r\nHost: example.com"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Attack simulated"

def test_metrics_endpoint(client):
    """Test Prometheus metrics endpoint."""
    # Mock generate_latest
    with patch('app.main.generate_latest') as mock_generate:
        mock_generate.return_value = b"# HELP ids_packets_processed_total Total number of packets processed\n"
        
        response = client.get("/metrics")
        
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
