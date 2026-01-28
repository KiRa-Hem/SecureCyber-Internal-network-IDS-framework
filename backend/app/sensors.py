import asyncio
import json
import random
import time
import logging
import numbers
from typing import Dict, Any, Optional, List
from datetime import datetime

from app.packet_capture import PacketCapture
from app.features import get_feature_extractor
from app.correlator import correlator
from app.mitigation import mitigation
from app.cache import cache_manager
from app.metrics import metrics_collector
from app.db import db
from app.config import settings
from app.alert_fusion import fuse_alerts
from app.drift import drift_monitor

logger = logging.getLogger(__name__)

class SensorWorker:
    def __init__(self, location: str, manager, detectors: Dict[str, Any]):
        self.location = location
        self.manager = manager
        self.detectors = detectors
        self.running = False
        self.packet_capture = None
        self.loop = None
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'start_time': time.time()
        }
        self.feature_extractor = get_feature_extractor()
    
    async def start(self):
        """Start the sensor worker."""
        self.running = True
        self.loop = asyncio.get_running_loop()
        logger.info(f"Sensor worker at {self.location} started")
        
        # Start packet capture if enabled (single capture per host)
        primary_location = None
        if hasattr(settings, 'sensor_locations') and settings.sensor_locations:
            primary_location = settings.sensor_locations[0]
        should_capture = (
            hasattr(settings, 'enable_packet_capture')
            and settings.enable_packet_capture
            and (primary_location is None or self.location == primary_location)
        )
        if should_capture:
            self.packet_capture = PacketCapture(
                interface=getattr(settings, 'network_interface', 'auto'),
                capture_filter=getattr(settings, 'capture_filter', 'tcp or udp')
            )
            self.packet_capture.add_packet_callback(self._process_packet)
            self.packet_capture.start_capture()
        elif hasattr(settings, 'enable_packet_capture') and settings.enable_packet_capture:
            logger.info(
                "Skipping packet capture for %s; capture handled by %s",
                self.location,
                primary_location or "primary sensor",
            )
        
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

            # XGBoost detection
            xgb_detector = self.detectors.get('xgboost')
            if xgb_detector and getattr(xgb_detector, "model", None) is not None:
                xgb_result = xgb_detector.predict(features)
                xgb_is_attack = xgb_result and xgb_result.get("is_attack", xgb_result.get("prediction") == 1)
                if xgb_is_attack:
                    xgb_alert = {
                        'id': f"xgb-{int(time.time())}",
                        'timestamp': int(time.time()),
                        'source_ip': packet_info.get('src_ip', 'unknown'),
                        'dest_ip': packet_info.get('dst_ip', 'unknown'),
                        'protocol': packet_info.get('protocol_name', 'TCP'),
                        'attack_types': ['XGBoost Detection'],
                        'confidence': xgb_result['confidence'],
                        'payload_snippet': packet_info.get('payload', '')[:100],
                        'path': [self.location, 'unknown'],
                        'mitigation': {'action': 'flagged', 'by': 'xgboost'},
                        'attacker_node': self.location,
                        'target_node': 'unknown',
                        'targeted_data': []
                    }
                    alerts.append(xgb_alert)
                    metrics_collector.record_prediction('xgboost', 'attack')
                else:
                    metrics_collector.record_prediction('xgboost', 'normal')

            # Isolation Forest anomaly detection
            anomaly_detector = self.detectors.get('anomaly')
            if anomaly_detector:
                anomaly_result = anomaly_detector.predict(features)
                if anomaly_result:
                    if anomaly_result.get("is_anomaly"):
                        score = anomaly_result.get("score")
                        threshold = anomaly_result.get("threshold")
                        score_text = f"{score:.4f}" if isinstance(score, (int, float)) else "n/a"
                        threshold_text = f"{threshold:.4f}" if isinstance(threshold, (int, float)) else "n/a"
                        anomaly_alert = {
                            'id': f"anom-{int(time.time())}",
                            'timestamp': int(time.time()),
                            'source_ip': packet_info.get('src_ip', 'unknown'),
                            'dest_ip': packet_info.get('dst_ip', 'unknown'),
                            'protocol': packet_info.get('protocol_name', 'TCP'),
                            'attack_types': ['Anomaly'],
                            'confidence': anomaly_result.get('confidence', 0.8),
                            'payload_snippet': packet_info.get('payload', '')[:100],
                            'description': f"Isolation Forest score {score_text} below threshold {threshold_text}",
                            'path': packet_info.get('path', []),
                            'mitigation': {'action': 'flagged', 'by': 'isolation-forest'},
                            'attacker_node': self.location,
                            'target_node': packet_info.get('target_node', 'unknown'),
                            'targeted_data': []
                        }
                        alerts.append(anomaly_alert)
                        metrics_collector.record_prediction('anomaly', 'attack')
                    else:
                        metrics_collector.record_prediction('anomaly', 'normal')

            # Drift monitoring (non-blocking)
            drift_alert = drift_monitor.update(features)
            if drift_alert:
                drift_alert.update({
                    "source_ip": packet_info.get('src_ip', 'unknown'),
                    "dest_ip": packet_info.get('dst_ip', 'unknown'),
                    "protocol": packet_info.get('protocol_name', 'TCP'),
                    "payload_snippet": packet_info.get('payload', '')[:100],
                    "path": packet_info.get('path', []),
                    "attacker_node": self.location,
                    "target_node": packet_info.get('target_node', 'unknown'),
                })
                alerts.append(drift_alert)
                metrics_collector.record_drift_alert()
            
            # Record latency
            latency = time.time() - start_time
            metrics_collector.record_latency(latency, self.location)
            
            # Fuse + process alerts
            if settings.ALERT_FUSION_ENABLED and len(alerts) > 1:
                alerts = fuse_alerts(alerts)
                metrics_collector.record_fused_alert()
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

                # Deduplicate alerts within a time window
                dedup_key = self._dedup_key(sanitized)
                if dedup_key:
                    existing = cache_manager.get(dedup_key)
                    if existing:
                        metrics_collector.record_deduped_alert()
                        continue
                    cache_manager.set(dedup_key, True, settings.ALERT_DEDUP_WINDOW_SECONDS)

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

                if self.loop and self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.manager.broadcast_alert(sanitized),
                        self.loop,
                    )
                else:
                    try:
                        asyncio.create_task(self.manager.broadcast_alert(sanitized))
                    except RuntimeError as exc:
                        logger.error("Unable to dispatch alert broadcast: %s", exc)

        except Exception as e:
            logger.error(f"Error processing alert: {e}")

    def _dedup_key(self, alert: Dict[str, Any]) -> Optional[str]:
        attacks = alert.get("attack_types") or alert.get("attacks") or []
        if isinstance(attacks, str):
            attacks = [attacks]
        attacks_key = ",".join(sorted(map(str, attacks))) if attacks else "unknown"
        src = alert.get("source_ip") or alert.get("src_ip") or "unknown"
        dst = alert.get("dest_ip") or alert.get("dst_ip") or "unknown"
        target = alert.get("target_node") or "unknown"
        return f"alert:{attacks_key}:{src}:{dst}:{target}"
    
    async def _simulate_traffic(self):
        """Simulate network traffic for demo purposes."""
        # Generate a random packet
        protocol = random.choice(["TCP", "UDP"])
        if protocol == "TCP":
            flags = random.choice(["S", "SA", "PA", "FA", "R", ""])
            header_len = random.choice([20, 24, 32])
            tcp_window = random.randint(1024, 65535)
        else:
            flags = ""
            header_len = 8
            tcp_window = None

        size = random.randint(64, 1500)
        payload_len = max(0, size - header_len)

        packet_info = {
            'timestamp': time.time(),
            'src_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'dst_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'protocol': protocol,
            'protocol_name': protocol,
            'src_port': random.randint(1, 65535),
            'dst_port': random.choice([80, 443, 22, 21, 25, 53, 3389]),
            'size': size,
            'flags': flags,
            'header_len': header_len,
            'payload_len': payload_len,
            'tcp_window': tcp_window,
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
