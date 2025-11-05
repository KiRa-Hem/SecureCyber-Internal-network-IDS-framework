import pytest
from app.detectors.rule_based import RuleBasedDetector
from app.detectors.ddos_detector import DoSDetector

class TestRuleBasedDetector:
    def setup_method(self):
        self.detector = RuleBasedDetector()
    
    def test_sql_injection_detection(self):
        packet_data = {
            "source_ip": "192.0.2.1",
            "dest_ip": "10.0.1.10",
            "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1",
            "path": ["router-1", "fw-1", "switch-1", "web-01"],
            "area_of_effect": {"nodes": ["web-01"], "radius": 1}
        }
        
        alert = self.detector.detect(packet_data)
        
        assert alert is not None
        assert "SQL Injection" in alert["attacks"]
        assert alert["confidence"] >= 80
    
    def test_xss_detection(self):
        packet_data = {
            "source_ip": "192.0.2.1",
            "dest_ip": "10.0.1.10",
            "payload": "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
            "path": ["router-1", "fw-1", "switch-1", "web-01"],
            "area_of_effect": {"nodes": ["web-01"], "radius": 1}
        }
        
        alert = self.detector.detect(packet_data)
        
        assert alert is not None
        assert "XSS" in alert["attacks"]
        assert alert["confidence"] >= 80
    
    def test_legitimate_traffic(self):
        packet_data = {
            "source_ip": "10.0.1.100",
            "dest_ip": "10.0.1.10",
            "payload": "GET /index.html HTTP/1.1",
            "path": ["router-1", "fw-1", "switch-1", "web-01"],
            "area_of_effect": {"nodes": ["web-01"], "radius": 0}
        }
        
        alert = self.detector.detect(packet_data)
        
        assert alert is None

class TestDoSDetector:
    def setup_method(self):
        self.detector = DoSDetector(threshold=5, window_seconds=5)
    
    def test_ddos_detection(self):
        # Send multiple requests from the same IP in a short time
        source_ip = "192.0.2.1"
        
        for i in range(10):
            packet_data = {
                "source_ip": source_ip,
                "dest_ip": "10.0.1.10",
                "payload": "GET / HTTP/1.1",
                "path": ["router-1", "fw-1", "switch-1", "web-01"],
                "area_of_effect": {"nodes": ["web-01"], "radius": 1}
            }
            
            alert = self.detector.detect(packet_data)
            
            # Should detect DDoS after threshold is exceeded
            if i >= 5:
                assert alert is not None
                assert "DDoS" in alert["attacks"]
                assert alert["confidence"] >= 60
    
    def test_legitimate_traffic(self):
        # Send requests from different IPs
        for i in range(10):
            packet_data = {
                "source_ip": f"10.0.1.{i+100}",
                "dest_ip": "10.0.1.10",
                "payload": "GET / HTTP/1.1",
                "path": ["router-1", "fw-1", "switch-1", "web-01"],
                "area_of_effect": {"nodes": ["web-01"], "radius": 0}
            }
            
            alert = self.detector.detect(packet_data)
            
            # Should not detect DDoS for legitimate traffic
            assert alert is None
