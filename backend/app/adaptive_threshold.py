from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from app.cache import cache_manager
from app.config import settings

logger = logging.getLogger(__name__)


class AdaptiveThresholdManager:
    """Maintain rolling score distributions per location for adaptive thresholds."""

    def _key(self, location: str) -> str:
        return f"anomaly_scores:{location}"

    def update(self, location: str, score: float) -> Optional[float]:
        if not settings.ADAPTIVE_ANOMALY_ENABLED:
            return None
        key = self._key(location)
        window = settings.ADAPTIVE_ANOMALY_WINDOW

        scores = cache_manager.get(key) or []
        scores.append(float(score))
        if len(scores) > window:
            scores = scores[-window:]
        cache_manager.set(key, scores, 3600)

        if len(scores) < settings.ADAPTIVE_ANOMALY_MIN_SAMPLES:
            return None

        try:
            threshold = float(np.quantile(scores, settings.ADAPTIVE_ANOMALY_QUANTILE))
        except Exception:
            threshold = None
        return threshold


adaptive_thresholds = AdaptiveThresholdManager()
