import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from app.sensors import SensorWorker
from app.detectors.rule_based import RuleBasedDetector

class TestSensorWorker:
    def setup_method(self):
        self.websocket_manager = MagicMock()
        detectors = {"rule_based": RuleBasedDetector()}
        self.worker = SensorWorker("edge", self.websocket_manager, detectors)
    
    @pytest.mark.asyncio
    async def test_packet_processing(self):
        # Mock the broadcast_alert method
        self.websocket_manager.broadcast_alert = AsyncMock()
        
        # Create a malicious packet
        packet_data = {
            "source_ip": "192.0.2.1",
            "dest_ip": "10.0.1.10",
            "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1",
            "sensor_location": "edge",
            "path": ["router-1", "fw-1", "switch-1", "web-01"],
            "area_of_effect": {"nodes": ["web-01"], "radius": 1}
        }
        
        # Process the packet
        self.worker._process_packet(packet_data)
        await asyncio.sleep(0)
        
        # Check if an alert was broadcast
        self.websocket_manager.broadcast_alert.assert_called()
        
        # Get the alert that was broadcast
        call_args = self.websocket_manager.broadcast_alert.call_args[0][0]
        assert "SQL Injection" in call_args["attacks"]
        assert call_args["confidence"] >= 80
