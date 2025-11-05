import json
import os
import sys

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app, manager


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


def test_websocket_connection(client):
    """Verify the WebSocket endpoint accepts connections without authentication."""
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text("ping")


@pytest.mark.asyncio
async def test_connection_manager_connect():
    """Test ConnectionManager connect method."""
    mock_websocket = AsyncMock()
    await manager.connect(mock_websocket)
    mock_websocket.accept.assert_called_once()
    assert mock_websocket in manager.active_connections


@pytest.mark.asyncio
async def test_connection_manager_disconnect():
    """Test ConnectionManager disconnect method."""
    mock_websocket = AsyncMock()
    await manager.connect(mock_websocket)
    manager.disconnect(mock_websocket)
    assert mock_websocket not in manager.active_connections


@pytest.mark.asyncio
async def test_connection_manager_broadcast_alert():
    """Test broadcasting an alert to multiple connections."""
    mock_websocket1 = AsyncMock()
    mock_websocket2 = AsyncMock()
    await manager.connect(mock_websocket1)
    await manager.connect(mock_websocket2)

    alert = {
        "id": "test-alert-123",
        "timestamp": 1634567890,
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "attack_types": ["sql_injection"],
        "confidence": 0.95,
    }

    await manager.broadcast_alert(alert)

    for mock_ws in (mock_websocket1, mock_websocket2):
        mock_ws.send_text.assert_called_once()
        message = json.loads(mock_ws.send_text.call_args[0][0])
        assert message["type"] == "attack_detected"
        assert message["data"] == alert


@pytest.mark.asyncio
async def test_connection_manager_broadcast_stats():
    """Test broadcasting stats to multiple connections."""
    mock_websocket1 = AsyncMock()
    mock_websocket2 = AsyncMock()
    await manager.connect(mock_websocket1)
    await manager.connect(mock_websocket2)

    stats = {
        "packets_analyzed": 1000,
        "threats_detected": 5,
        "active_hosts": 14,
        "sensor_status": {"edge": "online", "internal": "online"},
    }

    await manager.broadcast_stats(stats)

    for mock_ws in (mock_websocket1, mock_websocket2):
        mock_ws.send_text.assert_called_once()
        message = json.loads(mock_ws.send_text.call_args[0][0])
        assert message["type"] == "stats_update"
        assert message["data"] == stats


@pytest.mark.asyncio
async def test_connection_manager_broadcast_with_disconnected_websocket():
    """Ensure disconnected WebSockets are cleaned up."""
    mock_websocket1 = AsyncMock()
    mock_websocket2 = AsyncMock()
    mock_websocket2.send_text.side_effect = Exception("Connection closed")

    await manager.connect(mock_websocket1)
    await manager.connect(mock_websocket2)

    alert = {
        "id": "test-alert-123",
        "timestamp": 1634567890,
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "attack_types": ["sql_injection"],
        "confidence": 0.95,
    }

    await manager.broadcast_alert(alert)

    mock_websocket1.send_text.assert_called_once()
    mock_websocket2.send_text.assert_called_once()
    assert mock_websocket2 not in manager.active_connections
    assert mock_websocket1 in manager.active_connections


@pytest.mark.asyncio
async def test_connection_manager_broadcast_with_no_connections():
    """Broadcasting with no active connections should not error."""
    alert = {
        "id": "test-alert-123",
        "timestamp": 1634567890,
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "attack_types": ["sql_injection"],
        "confidence": 0.95,
    }

    await manager.broadcast_alert(alert)
