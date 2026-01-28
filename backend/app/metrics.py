import time
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
    
    def record_packet(self, detector='unknown'):
        """Record a processed packet."""
        packets_processed.labels(detector=detector).inc()
        self._packets_processed += 1
    
    def record_alert(self, attack_type='unknown'):
        """Record a generated alert."""
        alerts_generated.labels(attack_type=attack_type).inc()
        self._alerts_generated += 1
    
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
    
    @property
    def packets_processed_count(self):
        return self._packets_processed
    
    @property
    def alerts_generated_count(self):
        return self._alerts_generated

# Global metrics collector instance
metrics_collector = MetricsCollector()
