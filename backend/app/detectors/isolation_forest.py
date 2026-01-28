import logging
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

from app.config import settings
from app.model_metadata import load_model_metadata
from app.model_registry import resolve_model_dir

try:
    from sklearn.ensemble import IsolationForest
    from joblib import load as joblib_load
except Exception:  # pragma: no cover - optional dependency path
    IsolationForest = None
    joblib_load = None

logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """Isolation Forest anomaly detector with a tunable score threshold."""

    def __init__(self, model_path: Optional[str] = None):
        default_path = resolve_model_dir() / "anomaly_isoforest.joblib"
        self.model_path = Path(model_path) if model_path else default_path
        self.model = None
        self.feature_names: list[str] = []
        self.threshold: Optional[float] = None
        self.contamination: float = float(getattr(settings, "ANOMALY_CONTAMINATION", 0.01))
        self.warmup_samples: int = int(getattr(settings, "ANOMALY_WARMUP_SAMPLES", 2000))
        self._buffer: list[list[float]] = []

        self._load_metadata()
        self._load_model()

    def _load_metadata(self) -> None:
        metadata = load_model_metadata()
        feature_columns = metadata.get("feature_columns")
        if feature_columns:
            self.feature_names = list(feature_columns)

        thresholds = metadata.get("thresholds") or {}
        iso_thresholds = thresholds.get("isolation_forest") or thresholds.get("anomaly") or {}
        threshold_value = iso_thresholds.get("score_threshold")
        if threshold_value is None:
            threshold_value = thresholds.get("anomaly_score_threshold")

        if threshold_value is None:
            threshold_value = getattr(settings, "ANOMALY_SCORE_THRESHOLD", None)

        if threshold_value is not None:
            try:
                self.threshold = float(threshold_value)
            except (TypeError, ValueError):
                self.threshold = None

    def _load_model(self) -> None:
        if IsolationForest is None or joblib_load is None:
            logger.error("scikit-learn/joblib unavailable; Isolation Forest disabled.")
            return

        if self.model_path.exists():
            try:
                self.model = joblib_load(self.model_path)
                logger.info("Isolation Forest model loaded from %s", self.model_path)
            except Exception as exc:
                logger.warning("Failed to load Isolation Forest model (%s).", exc)
                self.model = None

    @staticmethod
    def _coerce_float(value: Any) -> float:
        if value is None:
            return 0.0
        if isinstance(value, (int, float, np.number)):
            return float(value)
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _row_from_payload(self, feature_payload: Dict[str, Any]) -> list[float]:
        if not self.feature_names:
            self.feature_names = list(feature_payload.keys())
        return [self._coerce_float(feature_payload.get(name)) for name in self.feature_names]

    def _fit_from_buffer(self) -> None:
        if IsolationForest is None:
            return
        if len(self._buffer) < self.warmup_samples:
            return
        data = np.array(self._buffer, dtype=np.float32)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
        )
        self.model.fit(data)
        scores = self.model.decision_function(data)
        if self.threshold is None:
            try:
                self.threshold = float(np.quantile(scores, self.contamination))
            except Exception:
                self.threshold = 0.0
        logger.info(
            "Isolation Forest warmed up with %d samples. Threshold=%.6f",
            len(self._buffer),
            self.threshold,
        )
        self._buffer = []

    def predict(self, feature_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if IsolationForest is None:
            logger.warning("Isolation Forest unavailable.")
            return None

        row = self._row_from_payload(feature_payload)

        if self.model is None:
            if self.warmup_samples > 0:
                self._buffer.append(row)
                if len(self._buffer) >= self.warmup_samples:
                    self._fit_from_buffer()
            return None

        data = np.array([row], dtype=np.float32)
        score = float(self.model.decision_function(data)[0])
        threshold = self.threshold if self.threshold is not None else 0.0
        is_anomaly = bool(score < threshold)
        confidence = 0.8
        if is_anomaly:
            delta = max(0.0, threshold - score)
            denom = max(abs(threshold), 1e-6)
            confidence = min(0.99, max(0.5, delta / denom))

        return {
            "is_anomaly": is_anomaly,
            "score": score,
            "threshold": threshold,
            "confidence": confidence,
        }
