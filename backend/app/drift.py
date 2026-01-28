import time
from collections import deque
from typing import Dict, Any, Optional

from app.config import settings
from app.model_metadata import load_model_metadata


class DriftMonitor:
    def __init__(self):
        self.window = deque(maxlen=settings.DRIFT_WINDOW_SIZE)
        self.baseline = self._load_baseline()
        self.last_alert_ts = 0.0

    def _load_baseline(self) -> Dict[str, Dict[str, float]]:
        meta = load_model_metadata()
        baseline = meta.get("baseline_stats") or {}
        if not isinstance(baseline, dict):
            return {}
        return baseline

    def update(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not settings.DRIFT_ENABLED or not self.baseline:
            return None
        if not isinstance(features, dict):
            return None

        self.window.append(features)
        if len(self.window) < max(50, settings.DRIFT_MIN_FEATURES * 5):
            return None

        # Compute current mean for each baseline feature
        drifted = []
        for name, stats in self.baseline.items():
            if name not in features:
                continue
            values = [float(item.get(name, 0.0)) for item in self.window if isinstance(item, dict)]
            if not values:
                continue
            current_mean = sum(values) / max(len(values), 1)
            baseline_mean = float(stats.get("mean", 0.0))
            baseline_std = float(stats.get("std", 1.0)) or 1.0
            z = abs(current_mean - baseline_mean) / baseline_std
            if z >= settings.DRIFT_Z_THRESHOLD:
                drifted.append({"feature": name, "z": round(z, 2)})

        if len(drifted) < settings.DRIFT_MIN_FEATURES:
            return None

        now = time.time()
        if now - self.last_alert_ts < settings.DRIFT_COOLDOWN_SECONDS:
            return None
        self.last_alert_ts = now

        return {
            "id": f"drift-{int(now)}",
            "timestamp": int(now),
            "attack_types": ["Drift"],
            "confidence": 0.6,
            "description": f"Feature drift detected in {len(drifted)} features",
            "drift_features": drifted[:10],
            "mitigation": {"action": "flagged", "by": "drift-monitor"},
        }


drift_monitor = DriftMonitor()
