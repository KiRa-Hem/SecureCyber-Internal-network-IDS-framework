import pytest
import os
import sys
import time
import threading
import queue
from unittest.mock import Mock, patch, MagicMock

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.packet_capture import PacketCapture

@pytest.fixture
def packet_capture():
    """Create a PacketCapture instance for testing."""
    return PacketCapture(interface="lo", capture_filter="tcp")

def test_packet_capture_initialization():
    """Test PacketCapture initialization."""
    capture = PacketCapture(interface="eth0", capture_filter="tcp")
    
    assert capture.interface == "eth0"
    assert capture.capture_filter == "tcp"
    assert capture.running is False
    assert capture.packet_queue.empty()
    assert len(capture.packet_callbacks) == 0

def test_packet_capture_start_stop(packet_capture):
    """Test starting and stopping packet capture."""
    # Mock the capture and processing threads
    with patch.object(packet_capture, '_capture_packets') as mock_capture, \
         patch.object(packet_capture, '_process_packets') as mock_process:
        
        # Start capture
        packet_capture.start_capture()
        
        # Verify capture is marked as running
        assert packet_capture.running is True
        
        # Verify threads were started
        mock_capture.assert_called_once()
        mock_process.assert_called_once()
        
        # Stop capture
        packet_capture.stop_capture()
        
        # Verify capture is marked as stopped
        assert packet_capture.running is False

def test_packet_capture_extract_packet_info():
    """Test packet information extraction."""
    capture = PacketCapture()
    
    # Mock a packet with IP and TCP layers
    mock_packet = Mock()
    mock_packet.__len__ = Mock(return_value=100)
    
    # Mock IP layer
    mock_ip = Mock()
    mock_ip.src = "192.168.1.100"
    mock_ip.dst = "10.0.0.1"
    mock_ip.proto = 6  # TCP
    mock_packet.__getitem__ = Mock(return_value=mock_ip)
    
    # Mock TCP layer
    mock_tcp = Mock()
    mock_tcp.sport = 12345
    mock_tcp.dport = 80
    mock_tcp.flags = "AP"
    mock_packet.__contains__ = Mock(side_effect=lambda layer: layer in [IP, TCP])
    
    # Mock Raw layer
    mock_raw = Mock()
    mock_raw.payload = b"GET /index.html HTTP/1.1\r\nHost: example.com"
    mock_packet.__getitem__ = Mock(side_effect=lambda layer: {
        IP: mock_ip,
        TCP: mock_tcp,
        Raw: mock_raw
    }[layer])
    
    # Extract packet info
    with patch('app.packet_capture.IP', IP), \
         patch('app.packet_capture.TCP', TCP), \
         patch('app.packet_capture.Raw', Raw):
        
        packet_info = capture._extract_packet_info(mock_packet)
        
        # Verify extracted information
        assert packet_info is not None
        assert packet_info['src_ip'] == "192.168.1.100"
        assert packet_info['dst_ip'] == "10.0.0.1"
        assert packet_info['protocol'] == 6
        assert packet_info['src_port'] == 12345
        assert packet_info['dst_port'] == 80
        assert packet_info['flags'] == "AP"
        assert packet_info['protocol_name'] == 'TCP'
        assert 'payload' in packet_info

def test_packet_capture_extract_http_info():
    """Test HTTP information extraction."""
    capture = PacketCapture()
    
    # Test HTTP method extraction
    payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0"
    method = capture._extract_http_method(payload)
    assert method == "GET"
    
    # Test HTTP host extraction
    host = capture._extract_http_host(payload)
    assert host == "example.com"
    
    # Test HTTP path extraction
    path = capture._extract_http_path(payload)
    assert path == "/index.html"

def test_packet_capture_add_callback(packet_capture):
    """Test adding packet callbacks."""
    # Create a mock callback
    callback = Mock()
    
    # Add callback
    packet_capture.add_packet_callback(callback)
    
    # Verify callback was added
    assert callback in packet_capture.packet_callbacks

def test_packet_capture_process_packets(packet_capture):
    """Test packet processing."""
    # Create a mock packet
    packet_info = {
        'timestamp': time.time(),
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'protocol': 'TCP'
    }
    
    # Add packet to queue
    packet_capture.packet_queue.put(packet_info)
    
    # Mock metrics collector
    with patch('app.packet_capture.metrics_collector') as mock_metrics:
        # Create a mock callback
        callback = Mock()
        packet_capture.add_packet_callback(callback)
        
        # Process packets
        packet_capture._process_packets()
        
        # Verify metrics were recorded
        mock_metrics.record_packet.assert_called_once()
        
        # Verify callback was called
        callback.assert_called_once_with(packet_info)

def test_packet_capture_auto_interface():
    """Test automatic interface selection."""
    # Mock get_if_list for Linux
    with patch('app.packet_capture.get_if_list') as mock_get_if_list:
        mock_get_if_list.return_value = ['lo', 'eth0', 'wlan0']
        
        capture = PacketCapture(interface="auto")
        assert capture.interface == "eth0"  # First non-loopback interface

def test_packet_capture_permission_error():
    """Test handling of permission errors."""
    capture = PacketCapture()
    
    # Mock sniff to raise PermissionError
    with patch('app.packet_capture.sniff', side_effect=PermissionError("Permission denied")):
        # Start capture
        capture.start_capture()
        
        # Verify capture is marked as stopped
        assert capture.running is False

def test_packet_capture_general_exception():
    """Test handling of general exceptions."""
    capture = PacketCapture()
    
    # Mock sniff to raise a general exception
    with patch('app.packet_capture.sniff', side_effect=Exception("General error")):
        # Start capture
        capture.start_capture()
        
        # Verify capture is marked as stopped
        assert capture.running is False
        