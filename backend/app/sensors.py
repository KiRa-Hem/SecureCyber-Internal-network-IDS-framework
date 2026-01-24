import asyncio
import json
import random
import time
import logging
import numbers
from typing import Dict, Any, Optional, List
from datetime import datetime

from app.packet_capture import PacketCapture
from app.detectors.rule_based import RuleBasedDetector
from app.detectors.ddos_detector import DoSDetector
from app.detectors.random_forest import RandomForestDetector
from app.detectors.dnn import DNNDetector
from app.features import FeatureExtractor
from app.correlator import correlator
from app.mitigation import mitigation
from app.cache import cache_manager
from app.metrics import metrics_collector
from app.db import db
from app.config import settings

logger = logging.getLogger(__name__)

class SensorWorker:
    def __init__(self, location: str, manager, detectors: Dict[str, Any]):
        self.location = location
        self.manager = manager
        self.detectors = detectors
        self.running = False
        self.packet_capture = None
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'start_time': time.time()
        }
        self.feature_extractor = FeatureExtractor()
    
    async def start(self):
        """Start the sensor worker."""
        self.running = True
        logger.info(f"Sensor worker at {self.location} started")
        
        # Start packet capture if enabled
        if hasattr(settings, 'enable_packet_capture') and settings.enable_packet_capture:
            self.packet_capture = PacketCapture(
                interface=getattr(settings, 'network_interface', 'auto'),
                capture_filter=getattr(settings, 'capture_filter', 'tcp or udp')
            )
            self.packet_capture.add_packet_callback(self._process_packet)
            self.packet_capture.start_capture()
        
        # Run main loop
        while self.running:
            try:
                # Simulate traffic only when explicitly enabled
                if not self.packet_capture and settings.enable_simulation:
                    await self._simulate_traffic()
                
                # Send periodic stats update
                if random.random() < 0.01:  # 1% chance per iteration
                    await self._send_stats_update()
                
                # Small delay to prevent high CPU usage
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in sensor worker {self.location}: {e}")
                await asyncio.sleep(1)  # Prevent rapid error loops
    
    def stop(self):
        """Stop the sensor worker."""
        self.running = False
        logger.info(f"Sensor worker at {self.location} stopped")
        
        if self.packet_capture:
            self.packet_capture.stop_capture()
    
    def _process_packet(self, packet_info: Dict[str, Any]):
        """Process a captured packet through detectors."""
        try:
            start_time = time.time()
            
            # Update packet count
            self.stats['packets_processed'] += 1
            metrics_collector.record_packet(self.location)
            
            # Process through detectors
            alerts = []
            
            # Rule-based detection
            if 'rule_based' in self.detectors:
                rule_alert = self.detectors['rule_based'].detect(packet_info)
                if rule_alert:
                    alerts.append(rule_alert)
            
            # DoS detection
            if 'dos' in self.detectors:
                dos_alert = self.detectors['dos'].detect(packet_info)
                if dos_alert:
                    alerts.append(dos_alert)
            
            features = self.feature_extractor.extract(packet_info)

            # RandomForest detection
            rf_detector = self.detectors.get('random_forest')
            if rf_detector and getattr(rf_detector, "model", None) is not None:
                rf_result = rf_detector.predict(features)
                if rf_result and rf_result['prediction'] == 1:
                    rf_alert = {
                        'id': f"rf-{int(time.time())}",
                        'timestamp': int(time.time()),
                        'source_ip': packet_info.get('src_ip', 'unknown'),
                        'dest_ip': packet_info.get('dst_ip', 'unknown'),
                        'protocol': packet_info.get('protocol_name', 'TCP'),
                        'attack_types': ['RandomForest Detection'],
                        'confidence': rf_result['confidence'],
                        'payload_snippet': packet_info.get('payload', '')[:100],
                        'path': [self.location, 'unknown'],
                        'mitigation': {'action': 'flagged', 'by': 'random_forest'},
                        'attacker_node': self.location,
                        'target_node': 'unknown',
                        'targeted_data': []
                    }
                    alerts.append(rf_alert)
                    metrics_collector.record_prediction('random_forest', 'attack')
                else:
                    metrics_collector.record_prediction('random_forest', 'normal')
            
            # DNN detection
            dnn_detector = self.detectors.get('dnn')
            if dnn_detector and getattr(dnn_detector, "model", None) is not None:
                dnn_result = dnn_detector.predict(features)
                if dnn_result and dnn_result['prediction'] == 1:
                    dnn_alert = {
                        'id': f"dnn-{int(time.time())}",
                        'timestamp': int(time.time()),
                        'source_ip': packet_info.get('src_ip', 'unknown'),
                        'dest_ip': packet_info.get('dst_ip', 'unknown'),
                        'protocol': packet_info.get('protocol_name', 'TCP'),
                        'attack_types': ['DNN Detection'],
                        'confidence': dnn_result['confidence'],
                        'payload_snippet': packet_info.get('payload', '')[:100],
                        'path': [self.location, 'unknown'],
                        'mitigation': {'action': 'flagged', 'by': 'dnn'},
                        'attacker_node': self.location,
                        'target_node': 'unknown',
                        'targeted_data': []
                    }
                    alerts.append(dnn_alert)
                    metrics_collector.record_prediction('dnn', 'attack')
                else:
                    metrics_collector.record_prediction('dnn', 'normal')
            
            # Record latency
            latency = time.time() - start_time
            metrics_collector.record_latency(latency, self.location)
            
            # Process alerts
            for alert in alerts:
                self._process_alert(alert)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_alert(self, alert: Dict[str, Any]):
        """Process a detected alert."""
        queue: List[Dict[str, Any]] = [alert]
        try:
            while queue:
                current = queue.pop(0)
                sanitized = self._sanitize_for_storage(current)

                mitigation_action = sanitized.get('mitigation', {}).get('action', 'flagged')
                if mitigation_action == 'block' and 'source_ip' in sanitized:
                    mitigation.block_ip(
                        sanitized['source_ip'],
                        f"Automatic block by {self.location} sensor",
                        300  # 5 minutes
                    )
                    metrics_collector.record_mitigation('block')

                db.store_alert(sanitized)

                self.stats['alerts_generated'] += 1
                metrics_collector.record_alert(sanitized.get('attack_types', ['unknown'])[0])

                recent_alerts = cache_manager.get('recent_alerts') or []
                recent_alerts.insert(0, sanitized)
                if len(recent_alerts) > 100:
                    recent_alerts.pop()
                cache_manager.set('recent_alerts', recent_alerts, 300)

                is_correlated_event = (
                    str(sanitized.get("id", "")).startswith("corr-")
                    or bool(sanitized.get("correlated_events"))
                )
                if not is_correlated_event:
                    correlated_alert = correlator.add_event(sanitized)
                    if correlated_alert:
                        queue.append(correlated_alert)

                asyncio.create_task(self.manager.broadcast_alert(sanitized))

        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    async def _simulate_traffic(self):
        """Simulate network traffic for demo purposes."""
        # Generate a random packet
        packet_info = {
            'timestamp': time.time(),
            'src_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'dst_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'protocol': random.choice(['TCP', 'UDP']),
            'src_port': random.randint(1, 65535),
            'dst_port': random.choice([80, 443, 22, 21, 25, 53, 3389]),
            'size': random.randint(64, 1500)
        }
        
        # Occasionally generate attack traffic
        if random.random() < 0.05:  # 5% chance
            attack_types = ['SQL Injection', 'XSS', 'DoS', 'Port Scan']
            attack_type = random.choice(attack_types)
            
            packet_info.update({
                'src_ip': random.choice([
                    "203.0.113.45", "198.51.100.77", "192.0.2.123",
                    "203.0.113.88", "198.51.100.99", "192.0.2.200"
                ]),
                'payload': self._generate_attack_payload(attack_type)
            })
        
        # Process the simulated packet
        self._process_packet(packet_info)
    
    def _generate_attack_payload(self, attack_type: str) -> str:
        """Generate a sample attack payload."""
        payloads = {
            'SQL Injection': "SELECT * FROM users WHERE id=' OR '1'='1';--",
            'XSS': "<script>alert('XSS')</script>",
            'DoS': "SYN flood pattern",
            'Port Scan': "Port scan detected on multiple ports"
        }
        return payloads.get(attack_type, "Suspicious activity detected")
    
    async def _send_stats_update(self):
        """Send statistics update to WebSocket clients."""
        uptime = time.time() - self.stats['start_time']
        
        stats = {
            'packets_analyzed': self.stats['packets_processed'],
            'threats_detected': self.stats['alerts_generated'],
            'active_hosts': 14,
            'sensor_status': {self.location: "online"},
            'top_attackers': [
                {"ip": "203.0.113.45", "count": 120},
                {"ip": "198.51.100.77", "count": 85},
                {"ip": "192.0.2.123", "count": 65}
            ]
        }
        
        await self.manager.broadcast_stats(stats)

    def _sanitize_for_storage(self, data: Any) -> Any:
        """Clamp integers to Mongo-safe range and convert numpy types."""
        max_int = 2**63 - 1
        min_int = -2**63

        if isinstance(data, dict):
            return {key: self._sanitize_for_storage(value) for key, value in data.items()}
        if isinstance(data, list):
            return [self._sanitize_for_storage(value) for value in data]
        if isinstance(data, numbers.Integral):
            value = int(data)
            if value > max_int:
                return max_int
            if value < min_int:
                return min_int
            return value
        return data
