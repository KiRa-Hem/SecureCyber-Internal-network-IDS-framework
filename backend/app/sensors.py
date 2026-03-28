import asyncio
import json
import random
import time
import logging
import numbers
import hashlib
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
from app.baseline import baseline_manager
from app.adaptive_threshold import adaptive_thresholds
from app.risk import risk_engine
from app.rl_optimizer import rl_optimizer
from app.incident_response import incident_engine
from app.mitre_attack import map_alert as mitre_map_alert
from app.model_updater import model_updater
from app.llm_analyzer import llm_analyzer

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
            metrics_collector.record_packet("rule_based")
            
            # Process through detectors
            alerts = []
            xgb_result: Optional[Dict[str, Any]] = None
            xgb_is_attack = False
            anomaly_result: Optional[Dict[str, Any]] = None

            features = self.feature_extractor.extract(packet_info)
            baseline_manager.update(self.location, features)

            # Rule-based detection
            if 'rule_based' in self.detectors:
                rule_alert = self.detectors['rule_based'].detect(packet_info)
                if rule_alert:
                    rule_alert.setdefault("feature_snapshot", features)
                    alerts.append(rule_alert)
            
            # DoS detection
            if 'dos' in self.detectors:
                dos_alert = self.detectors['dos'].detect(packet_info)
                if dos_alert:
                    dos_alert.setdefault("feature_snapshot", features)
                    alerts.append(dos_alert)

            # XGBoost detection — single threshold path via RL optimizer
            xgb_detector = self.detectors.get('xgboost')
            if xgb_detector and getattr(xgb_detector, "model", None) is not None:
                xgb_result = xgb_detector.predict(features)
                xgb_confidence = xgb_result.get("confidence", 0) if xgb_result else 0
                # Unified threshold: RL optimizer is the single source of truth
                threshold = rl_optimizer.current_threshold
                xgb_is_attack = bool(xgb_confidence >= threshold)
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
                        'targeted_data': [],
                        'feature_snapshot': features,
                    }
                    alerts.append(xgb_alert)
                    metrics_collector.record_prediction('xgboost', 'malicious')
                else:
                    metrics_collector.record_prediction('xgboost', 'benign')

            # Isolation Forest anomaly detection
            anomaly_detector = self.detectors.get('anomaly')
            if anomaly_detector:
                anomaly_result = anomaly_detector.predict(features)
                if anomaly_result:
                    score = anomaly_result.get("score")
                    adaptive_threshold = None
                    if score is not None:
                        adaptive_threshold = adaptive_thresholds.update(self.location, float(score))
                        if adaptive_threshold is not None:
                            anomaly_result["threshold"] = adaptive_threshold
                            anomaly_result["is_anomaly"] = score < adaptive_threshold

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
                            'targeted_data': [],
                            'feature_snapshot': features,
                        }
                        alerts.append(anomaly_alert)
                        metrics_collector.record_prediction('anomaly', 'malicious')
                    else:
                        metrics_collector.record_prediction('anomaly', 'benign')

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
                # Feed drift to model updater for autonomous retraining
                model_updater.record_drift(drift_alert)

            # Combined risk scoring across XGBoost + anomaly + drift.
            risk_assessment = risk_engine.evaluate(
                xgb_result=xgb_result,
                xgb_is_attack=xgb_is_attack,
                anomaly_result=anomaly_result,
                drift_alert=drift_alert,
            )
            if risk_engine.should_emit_alert(risk_assessment):
                component_scores = risk_assessment.get("components", {})
                description = (
                    "Composite risk score {:.3f} (xgb={:.3f}, anomaly={:.3f}, drift={:.3f}, signals={})".format(
                        float(risk_assessment.get("score", 0.0)),
                        float(component_scores.get("xgboost", {}).get("score", 0.0)),
                        float(component_scores.get("anomaly", {}).get("score", 0.0)),
                        float(component_scores.get("drift", {}).get("score", 0.0)),
                        int(risk_assessment.get("signal_count", 0)),
                    )
                )
                risk_alert = {
                    "id": f"risk-{int(time.time())}",
                    "timestamp": int(time.time()),
                    "source_ip": packet_info.get("src_ip", "unknown"),
                    "dest_ip": packet_info.get("dst_ip", "unknown"),
                    "protocol": packet_info.get("protocol_name", "TCP"),
                    "attack_types": ["Composite Risk"],
                    "confidence": float(risk_assessment.get("score", 0.0)),
                    "payload_snippet": packet_info.get("payload", "")[:100],
                    "description": description,
                    "path": packet_info.get("path", []),
                    "mitigation": {
                        "action": "block" if risk_engine.should_auto_block(risk_assessment) else "flagged",
                        "by": "risk-fusion",
                    },
                    "attacker_node": self.location,
                    "target_node": packet_info.get("target_node", "unknown"),
                    "targeted_data": [],
                    "feature_snapshot": features,
                    "risk_assessment": risk_assessment,
                }
                alerts.append(risk_alert)

            # Persist risk metadata on all alerts for analyst visibility + mitigation gating.
            for alert in alerts:
                alert.setdefault("risk_assessment", risk_assessment)
            
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
    # Private IP prefixes used for noise suppression
    _PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                         '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                         '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                         '172.29.', '172.30.', '172.31.', '127.', '169.254.')
    _NOISE_TYPES = {'Anomaly', 'DDoS', 'DDoS Flood', 'Drift'}

    def _is_noise_alert(self, alert: Dict[str, Any]) -> bool:
        """Return True if this alert is a false-positive noise detection from a private IP."""
        attack_types = alert.get('attack_types') or alert.get('attacks') or []
        if not attack_types:
            return False
        primary = attack_types[0]
        if primary not in self._NOISE_TYPES:
            return False
        src_ip = str(alert.get('source_ip', ''))
        return src_ip.startswith(self._PRIVATE_PREFIXES)

    def _process_alert(self, alert: Dict[str, Any]):
        """Process a detected alert."""
        # Suppress noise: Anomaly/DDoS from private IPs are almost always false positives
        if self._is_noise_alert(alert):
            logger.debug("Noise alert suppressed for %s (%s)",
                         alert.get('source_ip'), (alert.get('attack_types') or ['?'])[0])
            return

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

                mitigation_action = str(
                    sanitized.get('mitigation', {}).get('action', 'flagged')
                ).strip().lower()
                if mitigation_action in {'block', 'blocked'} and 'source_ip' in sanitized:
                    if self._should_auto_block(sanitized):
                        mitigation.block_ip(
                            sanitized['source_ip'],
                            f"Automatic block by {self.location} sensor",
                            int(getattr(settings, "RISK_AUTOBLOCK_TTL_SECONDS", 300) or 300),
                        )
                        metrics_collector.record_mitigation('block_ip')
                    else:
                        logger.debug(
                            "Automatic block skipped for %s due to risk mitigation gate.",
                            sanitized.get("source_ip", "unknown"),
                        )
                        mitigation_payload = sanitized.get("mitigation")
                        if isinstance(mitigation_payload, dict):
                            mitigation_payload["action"] = "flagged"
                            mitigation_payload["note"] = "auto_block_skipped_by_gate"

                # Enrich with MITRE ATT&CK mapping
                mitre_map_alert(sanitized)

                # Generate incident response
                incident = incident_engine.analyze_threat(sanitized)
                if incident:
                    sanitized["incident"] = incident

                # Fire-and-forget LLM analysis (never blocks detection pipeline)
                # Phase 3: LLM verdict feeds back into RL optimizer
                if llm_analyzer.is_available:
                    heuristic_tp = self._classify_alert(sanitized)
                    async def _llm_enrich(alert_copy, mgr, heuristic_was_tp):
                        try:
                            verdict = await llm_analyzer.analyze_alert(alert_copy)
                            alert_copy["llm_verdict"] = verdict
                            await mgr.broadcast_alert({
                                "type": "llm_update",
                                "alert_id": alert_copy.get("id"),
                                "llm_verdict": verdict,
                            })
                            # Feed LLM verdict into RL optimizer
                            llm_tp = verdict.get("verdict") == "true_positive"
                            if llm_tp != heuristic_was_tp:
                                # Correct the heuristic: undo + apply LLM verdict
                                rl_optimizer.record_alert(is_true_positive=not heuristic_was_tp)
                                rl_optimizer.record_alert(is_true_positive=llm_tp)
                                logger.debug(
                                    "RL corrected by LLM: heuristic=%s → llm=%s for %s",
                                    heuristic_was_tp, llm_tp, alert_copy.get("id"),
                                )
                        except Exception as exc:
                            logger.debug("LLM enrichment failed: %s", exc)
                    if self.loop and self.loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            _llm_enrich(sanitized.copy(), self.manager, heuristic_tp),
                            self.loop,
                        )
                    else:
                        try:
                            asyncio.create_task(
                                _llm_enrich(sanitized.copy(), self.manager, heuristic_tp)
                            )
                        except RuntimeError:
                            pass

                # Feed to RL optimizer — heuristic provides immediate feedback;
                # LLM asynchronously corrects if it disagrees (Phase 3).
                is_tp = self._classify_alert(sanitized)
                rl_optimizer.record_alert(is_true_positive=is_tp)

                db.store_alert(sanitized)

                self.stats['alerts_generated'] += 1
                metrics_collector.record_alert(sanitized.get('attack_types', ['unknown'])[0])

                # Analytics: track source IP, severity, and MITRE techniques
                src_ip = sanitized.get('source_ip', '')
                if src_ip:
                    metrics_collector.record_alert_source(src_ip)
                # Infer severity from attack type for analytics tracking
                attack_types = sanitized.get('attack_types', [])
                primary_attack = attack_types[0] if attack_types else 'unknown'
                sev = 'medium'
                critical_types = {'Kill Chain Detected', 'Ransomware C2 Callback', 'Log4Shell Exploit', 'C2 Beacon Communication', 'Credential Dumping', 'DDoS', 'SQL Injection', 'Command Injection'}
                high_types = {'Cross-Site Scripting', 'SMB Exploitation', 'SSH Brute Force', 'Lateral Movement', 'Data Exfiltration', 'FTP Brute Force Signature', 'Path Traversal'}
                if primary_attack in critical_types:
                    sev = 'critical'
                elif primary_attack in high_types:
                    sev = 'high'
                elif primary_attack in {'Drift', 'Anomaly'}:
                    sev = 'low'
                metrics_collector.record_severity(sev)
                # Track MITRE techniques from enriched alert
                for tid in (sanitized.get('mitre_techniques') or []):
                    if tid:
                        metrics_collector.record_mitre_technique(tid)
                # Also check mitre_attack list for tactic-level tracking
                for mapping in (sanitized.get('mitre_attack') or []):
                    tid = mapping.get('technique_id', '') if isinstance(mapping, dict) else ''
                    if tid:
                        metrics_collector.record_mitre_technique(tid)

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

    # ---------------------------------------------------------------- TP/FP heuristic
    _SIGNATURE_ATTACK_TYPES = {
        'SQL Injection', 'Cross-Site Scripting', 'Command Injection',
        'Log4Shell Exploit', 'Path Traversal', 'FTP Brute Force Signature',
        'SMB Exploitation', 'C2 Beacon Communication', 'Credential Dumping',
        'SSH Brute Force', 'Ransomware C2 Callback',
    }

    def _classify_alert(self, alert: Dict[str, Any]) -> bool:
        """Heuristic TP/FP classification for RL feedback (immediate fallback).

        Returns True (likely true positive) if the alert was confirmed by a
        signature-based detector.  Returns False for anomaly-only /
        drift-only alerts which are more likely to be false positives.

        Phase 3: This heuristic provides instant RL feedback. When the LLM
        async result arrives and disagrees, the RL optimizer is corrected
        via the _llm_enrich() callback.
        """
        attack_types = set(alert.get('attack_types') or alert.get('attacks') or [])
        # Signature-confirmed attacks are very likely true positives
        if attack_types & self._SIGNATURE_ATTACK_TYPES:
            return True
        # DDoS with high confidence is likely real
        if 'DDoS' in attack_types:
            confidence = alert.get('confidence', 0)
            if isinstance(confidence, (int, float)) and confidence >= 0.80:
                return True
        # Anomaly-only and Drift-only detections are uncertain — treat as FP
        # so the RL agent learns to raise thresholds for noisy signals
        if attack_types <= {'Anomaly', 'Drift', 'Composite Risk', 'XGBoost Detection'}:
            return False
        # Default: assume true positive for unknown attack types
        return True

    def _should_auto_block(self, alert: Dict[str, Any]) -> bool:
        source_ip = str(alert.get("source_ip", "")).strip()
        if not source_ip or source_ip.lower() == "unknown":
            return False

        assessment = alert.get("risk_assessment")
        if not isinstance(assessment, dict):
            return False
        return risk_engine.should_auto_block(assessment)

    def _dedup_key(self, alert: Dict[str, Any]) -> Optional[str]:
        attacks = alert.get("attack_types") or alert.get("attacks") or []
        if isinstance(attacks, str):
            attacks = [attacks]
        attacks_key = ",".join(sorted(map(str, attacks))) if attacks else "unknown"
        src = alert.get("source_ip") or alert.get("src_ip") or "unknown"
        dst = alert.get("dest_ip") or alert.get("dst_ip") or "unknown"
        target = alert.get("target_node") or "unknown"
        proto = alert.get("protocol") or alert.get("protocol_name") or "unknown"
        src_port = alert.get("src_port") or "na"
        dst_port = alert.get("dst_port") or "na"
        payload = alert.get("payload_snippet") or alert.get("payload") or ""
        payload_bytes = str(payload).encode("utf-8", errors="ignore")
        payload_hash = hashlib.sha1(payload_bytes).hexdigest()[:8] if payload_bytes else "nopayload"
        return f"alert:{attacks_key}:{src}:{dst}:{target}:{proto}:{src_port}:{dst_port}:{payload_hash}"
    
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
