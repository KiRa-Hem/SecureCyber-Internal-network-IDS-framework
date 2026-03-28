import time
import collections
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CollectorRegistry
import logging

logger = logging.getLogger(__name__)

# Create a custom registry
registry = CollectorRegistry()

# Define metrics
packets_processed = Counter(
    'ids_packets_processed_total',
    'Total number of packets processed',
    ['detector'],
    registry=registry
)

alerts_generated = Counter(
    'ids_alerts_generated_total',
    'Total number of alerts generated',
    ['attack_type'],
    registry=registry
)

detection_latency = Histogram(
    'ids_detection_latency_seconds',
    'Time taken to detect threats',
    ['detector'],
    buckets=[0.001, 0.01, 0.1, 0.5, 1.0, 5.0],
    registry=registry
)

active_connections = Gauge(
    'ids_active_connections',
    'Number of active WebSocket connections',
    registry=registry
)

blocked_ips = Gauge(
    'ids_blocked_ips',
    'Number of currently blocked IPs',
    registry=registry
)

mitigation_actions = Counter(
    'ids_mitigation_actions_total',
    'Total number of mitigation actions taken',
    ['action'],
    registry=registry
)

model_predictions = Counter(
    'ids_model_predictions_total',
    'Total number of predictions made by ML models',
    ['model', 'prediction'],
    registry=registry
)

drift_alerts = Counter(
    'ids_drift_alerts_total',
    'Total number of drift alerts generated',
    registry=registry
)

deduped_alerts = Counter(
    'ids_deduped_alerts_total',
    'Total number of alerts skipped due to deduplication',
    registry=registry
)

fused_alerts = Counter(
    'ids_fused_alerts_total',
    'Total number of fused alerts generated',
    registry=registry
)

class MetricsCollector:
    def __init__(self):
        self.start_time = time.time()
        self._packets_processed = 0
        self._alerts_generated = 0
        # Analytics tracking
        self._attack_type_counts: dict = {}
        self._hourly_buckets: dict = {}
        self._source_ip_counts: dict = {}
        self._mitre_technique_hits: dict = {}
        self._severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    def record_packet(self, detector='unknown'):
        """Record a processed packet."""
        packets_processed.labels(detector=detector).inc()
        self._packets_processed += 1
    
    def record_alert(self, attack_type='unknown'):
        """Record a generated alert."""
        alerts_generated.labels(attack_type=attack_type).inc()
        self._alerts_generated += 1
        # Analytics: track attack type distribution
        self._attack_type_counts[attack_type] = self._attack_type_counts.get(attack_type, 0) + 1
        # Analytics: track hourly bucket
        hour_key = time.strftime("%Y-%m-%d %H:00")
        self._hourly_buckets[hour_key] = self._hourly_buckets.get(hour_key, 0) + 1
        # Prune old hourly buckets (keep last 48)
        if len(self._hourly_buckets) > 48:
            keys = sorted(self._hourly_buckets.keys())
            for old_key in keys[:-48]:
                del self._hourly_buckets[old_key]

    def record_alert_source(self, source_ip: str):
        """Track source IP frequency for analytics."""
        self._source_ip_counts[source_ip] = self._source_ip_counts.get(source_ip, 0) + 1

    def record_mitre_technique(self, technique_id: str):
        """Track MITRE ATT&CK technique hits."""
        self._mitre_technique_hits[technique_id] = self._mitre_technique_hits.get(technique_id, 0) + 1

    def record_severity(self, severity: str):
        """Track alert severity distribution."""
        if severity in self._severity_counts:
            self._severity_counts[severity] += 1

    def record_latency(self, latency, detector='unknown'):
        """Record detection latency."""
        detection_latency.labels(detector=detector).observe(latency)
    
    def update_connections(self, count):
        """Update active connections count."""
        active_connections.set(count)
    
    def update_blocked_ips(self, count):
        """Update blocked IPs count."""
        blocked_ips.set(count)
    
    def record_mitigation(self, action='unknown'):
        """Record a mitigation action."""
        mitigation_actions.labels(action=action).inc()
    
    def record_prediction(self, model='unknown', prediction='unknown'):
        """Record a model prediction."""
        model_predictions.labels(model=model, prediction=prediction).inc()

    def record_drift_alert(self):
        drift_alerts.inc()

    def record_deduped_alert(self):
        deduped_alerts.inc()

    def record_fused_alert(self):
        fused_alerts.inc()
    
    def get_metrics(self):
        """Get all metrics in Prometheus format."""
        return generate_latest(registry)

    def get_analytics(self) -> dict:
        """Return aggregated analytics data for the dashboard."""
        top_ips = sorted(
            self._source_ip_counts.items(), key=lambda x: x[1], reverse=True
        )[:20]
        return {
            "attack_type_distribution": dict(self._attack_type_counts),
            "hourly_attack_counts": dict(self._hourly_buckets),
            "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "mitre_technique_hits": dict(self._mitre_technique_hits),
            "severity_distribution": dict(self._severity_counts),
            "total_packets": self._packets_processed,
            "total_alerts": self._alerts_generated,
        }

    @property
    def packets_processed_count(self):
        return self._packets_processed
    
    @property
    def alerts_generated_count(self):
        return self._alerts_generated

# Global metrics collector instance
metrics_collector = MetricsCollector()
