import pytest
import asyncio
import json
import os
import sys
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, AsyncMock

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app, manager
from app.auth.security import create_access_token

@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)

@pytest.fixture
def auth_token():
    """Create a valid authentication token."""
    return create_access_token(data={"sub": "testuser"})

def test_websocket_connection_without_token(client):
    """Test WebSocket connection without authentication token."""
    with client.websocket_connect("/ws") as websocket:
        # The connection should be closed immediately due to missing token
        pass
    # In a real test, we would check that the connection was closed with the correct code

def test_websocket_connection_with_invalid_token(client):
    """Test WebSocket connection with invalid authentication token."""
    with client.websocket_connect("/ws?token=invalid_token") as websocket:
        # The connection should be closed immediately due to invalid token
        pass
    # In a real test, we would check that the connection was closed with the correct code

def test_websocket_connection_with_valid_token(client, auth_token):
    """Test WebSocket connection with valid authentication token."""
    with client.websocket_connect(f"/ws?token={auth_token}") as websocket:
        # The connection should be established successfully
        data = websocket.receive_text()
        # The server might send initial data or wait for client data
        pass

def test_websocket_send_message(client, auth_token):
    """Test sending a message through WebSocket."""
    with client.websocket_connect(f"/ws?token={auth_token}") as websocket:
        # Send a message
        websocket.send_text("test message")
        
        # Receive response (if any)
        data = websocket.receive_text()
        # Parse and verify response
        response = json.loads(data)
        # Verify response structure
        assert "type" in response
        assert "data" in response

@pytest.mark.asyncio
async def test_connection_manager_connect():
    """Test ConnectionManager connect method."""
    # Create a mock WebSocket
    mock_websocket = AsyncMock()
    
    # Connect
    await manager.connect(mock_websocket)
    
    # Verify WebSocket was accepted and added to active connections
    mock_websocket.accept.assert_called_once()
    assert mock_websocket in manager.active_connections

@pytest.mark.asyncio
async def test_connection_manager_disconnect():
    """Test ConnectionManager disconnect method."""
    # Create a mock WebSocket
    mock_websocket = AsyncMock()
    
    # Connect first
    await manager.connect(mock_websocket)
    
    # Disconnect
    manager.disconnect(mock_websocket)
    
    # Verify WebSocket was removed from active connections
    assert mock_websocket not in manager.active_connections

@pytest.mark.asyncio
async def test_connection_manager_broadcast_alert():
    """Test ConnectionManager broadcast_alert method."""
    # Create mock WebSockets
    mock_websocket1 = AsyncMock()
    mock_websocket2 = AsyncMock()
    
    # Connect
    await manager.connect(mock_websocket1)
    await manager.connect(mock_websocket2)
    
    # Create alert
    alert = {
        "id": "test-alert-123",
        "timestamp": 1634567890,
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "attack_types": ["sql_injection"],
        "confidence": 0.95
    }
    
    # Broadcast alert
    await manager.broadcast_alert(alert)
    
    # Verify both WebSockets received the message
    mock_websocket1.send_text.assert_called_once()
    mock_websocket2.send_text.assert_called_once()
    
    # Verify message content
    message1 = json.loads(mock_websocket1.send_text.call_args[0][0])
    assert message1["type"] == "attack_detected"
    assert message1["data"] == alert

@pytest.mark.asyncio
async def test_connection_manager_broadcast_stats():
    """Test ConnectionManager broadcast_stats method."""
    # Create mock WebSockets
    mock_websocket1 = AsyncMock()
    mock_websocket2 = AsyncMock()
    
    # Connect
    await manager.connect(mock_websocket1)
    await manager.connect(mock_websocket2)
    
    # Create stats
    stats = {
        "packets_analyzed": 1000,
        "threats_detected": 5,
        "active_hosts": 14,
        "sensor_status": {"edge": "online", "internal": "online"}
    }
    
    # Broadcast stats
    await manager.broadcast_stats(stats)
    
    # Verify both WebSockets received the message
    mock_websocket1.send_text.assert_called_once()
    mock_websocket2.send_text.assert_called_once()
    
    # Verify message content
    message1 = json.loads(mock_websocket1.send_text.call_args[0][0])
    assert message1["type"] == "stats_update"
    assert message1["data"] == stats

@pytest.mark.asyncio
async def test_connection_manager_broadcast_with_disconnected_websocket():
    """Test ConnectionManager broadcast with a disconnected WebSocket."""
    # Create mock WebSockets
    mock_websocket1 = AsyncMock()
    mock_websocket2 = AsyncMock()
    mock_websocket2.send_text.side_effect = Exception("Connection closed")
    
    # Connect
    await manager.connect(mock_websocket1)
    await manager.connect(mock_websocket2)
    
    # Create alert
    alert = {
        "id": "test-alert-123",
        "timestamp": 1634567890,
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "attack_types": ["sql_injection"],
        "confidence": 0.95
    }
    
    # Broadcast alert
    await manager.broadcast_alert(alert)
    
    # Verify only the first WebSocket received the message
    mock_websocket1.send_text.assert_called_once()
    mock_websocket2.send_text.assert_called_once()
    
    # Verify the disconnected WebSocket was removed
    assert mock_websocket2 not in manager.active_connections
    assert mock_websocket1 in manager.active_connections

@pytest.mark.asyncio
async def test_connection_manager_broadcast_with_no_connections():
    """Test ConnectionManager broadcast with no active connections."""
    # Create alert
    alert = {
        "id": "test-alert-123",
        "timestamp": 1634567890,
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "attack_types": ["sql_injection"],
        "confidence": 0.95
    }
    
    # Broadcast alert
    await manager.broadcast_alert(alert)
    
    # Verify no errors were raised
    pass