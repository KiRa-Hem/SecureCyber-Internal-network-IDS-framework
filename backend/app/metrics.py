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

class MetricsCollector:
    def __init__(self):
        self.start_time = time.time()
    
    def record_packet(self, detector='unknown'):
        """Record a processed packet."""
        packets_processed.labels(detector=detector).inc()
    
    def record_alert(self, attack_type='unknown'):
        """Record a generated alert."""
        alerts_generated.labels(attack_type=attack_type).inc()
    
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
    
    def get_metrics(self):
        """Get all metrics in Prometheus format."""
        return generate_latest(registry)

# Global metrics collector instance
metrics_collector = MetricsCollector()