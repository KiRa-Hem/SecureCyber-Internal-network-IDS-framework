import pytest
import numpy as np
import pandas as pd
import os
import sys

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.detectors.rule_based import RuleBasedDetector
from app.detectors.random_forest import RandomForestDetector
from app.detectors.dnn import DNNDetector
from app.detectors.ddos_detector import DoSDetector

@pytest.fixture
def sample_packet():
    """Sample packet for testing."""
    return {
        'timestamp': 1634567890,
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'flags': 'AP',
        'payload': 'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0'
    }

@pytest.fixture
def malicious_packet():
    """Malicious packet for testing."""
    return {
        'timestamp': 1634567890,
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'flags': 'AP',
        'payload': 'GET /search?q=\' OR \'1\'=\'1\' -- HTTP/1.1\r\nHost: example.com'
    }

@pytest.fixture
def dos_packet():
    """DoS packet for testing."""
    return {
        'timestamp': 1634567890,
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'flags': 'S',
        'payload': ''
    }

def test_rule_based_detector_benign(sample_packet):
    """Test rule-based detector with benign packet."""
    detector = RuleBasedDetector()
    result = detector.detect(sample_packet)
    
    assert result is not None
    assert result['is_malicious'] is False
    assert result['attack_types'] == []

def test_rule_based_detector_malicious(malicious_packet):
    """Test rule-based detector with malicious packet."""
    detector = RuleBasedDetector()
    result = detector.detect(malicious_packet)
    
    assert result is not None
    assert result['is_malicious'] is True
    assert 'sql_injection' in result['attack_types']

def test_random_forest_detector_benign(sample_packet):
    """Test Random Forest detector with benign packet."""
    detector = RandomForestDetector()
    
    # Create a mock feature vector
    features = np.array([
        1,  # protocol (TCP)
        12345,  # src_port
        80,  # dst_port
        0,  # flags (numeric representation)
        0,  # payload length
        0,  # is_http
        0,  # has_sql_injection
        0,  # has_xss
        0   # has_command_injection
    ])
    
    result = detector.detect(features)
    
    assert result is not None
    assert 'is_malicious' in result
    assert 'confidence' in result
    assert 'attack_types' in result

def test_random_forest_detector_malicious(malicious_packet):
    """Test Random Forest detector with malicious packet."""
    detector = RandomForestDetector()
    
    # Create a mock feature vector
    features = np.array([
        1,  # protocol (TCP)
        12345,  # src_port
        80,  # dst_port
        0,  # flags (numeric representation)
        100,  # payload length
        1,  # is_http
        1,  # has_sql_injection
        0,  # has_xss
        0   # has_command_injection
    ])
    
    result = detector.detect(features)
    
    assert result is not None
    assert 'is_malicious' in result
    assert 'confidence' in result
    assert 'attack_types' in result

def test_dnn_detector_benign(sample_packet):
    """Test DNN detector with benign packet."""
    detector = DNNDetector()
    
    # Create a mock feature vector
    features = np.array([
        1,  # protocol (TCP)
        12345,  # src_port
        80,  # dst_port
        0,  # flags (numeric representation)
        0,  # payload length
        0,  # is_http
        0,  # has_sql_injection
        0,  # has_xss
        0   # has_command_injection
    ])
    
    result = detector.detect(features)
    
    assert result is not None
    assert 'is_malicious' in result
    assert 'confidence' in result
    assert 'attack_types' in result

def test_dnn_detector_malicious(malicious_packet):
    """Test DNN detector with malicious packet."""
    detector = DNNDetector()
    
    # Create a mock feature vector
    features = np.array([
        1,  # protocol (TCP)
        12345,  # src_port
        80,  # dst_port
        0,  # flags (numeric representation)
        100,  # payload length
        1,  # is_http
        1,  # has_sql_injection
        0,  # has_xss
        0   # has_command_injection
    ])
    
    result = detector.detect(features)
    
    assert result is not None
    assert 'is_malicious' in result
    assert 'confidence' in result
    assert 'attack_types' in result

def test_dos_detector_benign(sample_packet):
    """Test DoS detector with benign packet."""
    detector = DoSDetector()
    
    # Add a benign packet
    detector.add_packet(sample_packet)
    
    result = detector.detect(sample_packet['src_ip'])
    
    assert result is not None
    assert result['is_malicious'] is False
    assert result['attack_types'] == []

def test_dos_detector_malicious(dos_packet):
    """Test DoS detector with malicious packet."""
    detector = DoSDetector()
    
    # Add multiple packets from the same source in a short time
    for i in range(100):
        packet = dos_packet.copy()
        packet['timestamp'] = 1634567890 + i
        detector.add_packet(packet)
    
    result = detector.detect(dos_packet['src_ip'])
    
    assert result is not None
    assert result['is_malicious'] is True
    assert 'dos' in result['attack_types']

def test_dos_detector_threshold():
    """Test DoS detector threshold."""
    detector = DoSDetector(threshold=50)
    
    # Add packets below threshold
    for i in range(49):
        packet = {
            'timestamp': 1634567890 + i,
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'flags': 'S',
            'payload': ''
        }
        detector.add_packet(packet)
    
    result = detector.detect('192.168.1.100')
    assert result['is_malicious'] is False
    
    # Add one more packet to exceed threshold
    packet = {
        'timestamp': 1634567890 + 50,
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'flags': 'S',
        'payload': ''
    }
    detector.add_packet(packet)
    
    result = detector.detect('192.168.1.100')
    assert result['is_malicious'] is True
