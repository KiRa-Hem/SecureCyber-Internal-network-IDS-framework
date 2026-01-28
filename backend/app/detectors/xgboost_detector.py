import logging
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

from app.config import settings
from app.model_metadata import load_model_metadata
from app.model_registry import resolve_model_dir

try:
    import xgboost as xgb
except Exception:  # pragma: no cover - optional dependency path
    xgb = None

logger = logging.getLogger(__name__)


class XGBoostDetector:
    def __init__(self, model_path: Optional[str] = None):
        default_path = resolve_model_dir() / "attack_classifier_xgb.json"
        self.model_path = Path(model_path) if model_path else default_path
        self.model = None
        self.feature_names: list[str] = []
        self.excluded_features: set[str] = set()
        self.threshold: Optional[float] = None
        self._warned_feature_mismatch = False

        self._load_metadata()
        self._load_model()

    def _load_metadata(self) -> None:
        metadata = load_model_metadata()
        feature_columns = metadata.get("feature_columns")
        if feature_columns:
            self.feature_names = list(feature_columns)
        excluded = metadata.get("excluded_features") or []
        if excluded:
            self.excluded_features = set(str(item) for item in excluded)
            if self.feature_names:
                self.feature_names = [
                    name for name in self.feature_names if name not in self.excluded_features
                ]

        thresholds = metadata.get("thresholds") or {}
        xgb_thresholds = thresholds.get("xgboost") or {}
        threshold_value = xgb_thresholds.get("best_f1_threshold")
        if threshold_value is None:
            threshold_value = thresholds.get("best_f1_threshold")

        if threshold_value is not None:
            try:
                self.threshold = float(threshold_value)
            except (TypeError, ValueError):
                self.threshold = None

    def _load_model(self) -> None:
        if xgb is None:
            logger.error("xgboost is not installed; XGBoost detector disabled.")
            return

        if self.model_path.exists():
            self.model = xgb.Booster()
            self.model.load_model(str(self.model_path))
            logger.info("XGBoost model loaded from %s", self.model_path)
        else:
            logger.warning("XGBoost model file not found at %s", self.model_path)
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

    def predict(self, feature_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.model:
            logger.warning("XGBoost model not loaded")
            return None

        if not self.feature_names:
            # Fall back to payload order if metadata is unavailable.
            self.feature_names = list(feature_payload.keys())

        if not self._warned_feature_mismatch:
            payload_keys = set(feature_payload.keys())
            expected = set(self.feature_names)
            missing = expected - payload_keys
            extra = payload_keys - expected
            if missing or extra:
                logger.warning(
                    "Feature mismatch detected. Missing=%s Extra=%s. Using metadata feature list only.",
                    sorted(missing),
                    sorted(extra),
                )
            self._warned_feature_mismatch = True

        row = [self._coerce_float(feature_payload.get(name)) for name in self.feature_names]
        data = np.array([row], dtype=np.float32)
        dmatrix = xgb.DMatrix(data, feature_names=self.feature_names)

        proba = float(self.model.predict(dmatrix)[0])
        threshold = self.threshold if self.threshold is not None else settings.CONFIDENCE_THRESHOLD
        is_attack = bool(proba >= threshold)

        return {
            "prediction": int(is_attack),
            "is_attack": is_attack,
            "probabilities": {
                "normal": float(1 - proba),
                "attack": proba,
            },
            "confidence": proba,
        }
