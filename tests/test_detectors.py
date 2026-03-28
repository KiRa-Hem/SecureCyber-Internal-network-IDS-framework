import os
import sys

import pytest

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.detectors.rule_based import RuleBasedDetector
from app.detectors.xgboost_detector import XGBoostDetector
from app.detectors.ddos_detector import DoSDetector
from app.features import CICFlowFeatureExtractor


@pytest.fixture
def sample_packet():
    """Sample packet for testing."""
    return {
        "timestamp": 1634567890,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": 6,
        "protocol_name": "TCP",
        "flags": "AP",
        "payload": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0",
        "size": 512,
        "payload_len": 128,
        "header_len": 20,
    }


@pytest.fixture
def malicious_packet():
    """Malicious packet for testing."""
    return {
        "timestamp": 1634567890,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": 6,
        "protocol_name": "TCP",
        "flags": "AP",
        "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1\r\nHost: example.com",
        "size": 512,
        "payload_len": 128,
        "header_len": 20,
    }


def test_rule_based_detector_benign(sample_packet):
    detector = RuleBasedDetector()
    alert = detector.detect(sample_packet)

    assert alert is None


def test_rule_based_detector_malicious(malicious_packet):
    detector = RuleBasedDetector()
    alert = detector.detect(malicious_packet)

    assert alert is not None
    assert "SQL Injection" in alert["attacks"]
    assert alert["confidence"] >= 80


def test_xgboost_detector_predicts(sample_packet):
    detector = XGBoostDetector()
    if detector.model is None:
        pytest.skip("XGBoost model not available for prediction test.")
    features = CICFlowFeatureExtractor().extract(sample_packet)
    result = detector.predict(features)

    assert result is not None
    # prediction/is_attack are None — threshold decision is now in sensor pipeline
    assert result["prediction"] is None
    assert 0.0 <= result["confidence"] <= 1.0


def test_dos_detector_detects():
    detector = DoSDetector(threshold=5, window_seconds=5)

    source_ip = "192.0.2.1"
    for i in range(10):
        packet_data = {
            "source_ip": source_ip,
            "dest_ip": "10.0.1.10",
            "payload": "GET / HTTP/1.1",
            "path": ["router-1", "fw-1", "switch-1", "web-01"],
            "area_of_effect": {"nodes": ["web-01"], "radius": 1},
        }
        alert = detector.detect(packet_data)
        if i >= 5:
            assert alert is not None
            assert "DDoS" in alert["attacks"]
            assert alert["confidence"] >= 0.60


def test_dos_detector_legitimate():
    detector = DoSDetector(threshold=5, window_seconds=5)

    for i in range(10):
        packet_data = {
            "source_ip": f"10.0.1.{i+100}",
            "dest_ip": "10.0.1.10",
            "payload": "GET / HTTP/1.1",
            "path": ["router-1", "fw-1", "switch-1", "web-01"],
            "area_of_effect": {"nodes": ["web-01"], "radius": 0},
        }
        alert = detector.detect(packet_data)
        assert alert is None
