from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.cache import cache_manager
from app.config import settings
from app.model_metadata import load_model_metadata

logger = logging.getLogger(__name__)


class BaselineManager:
    """Maintain per-location EWMA baseline for feature values."""

    def __init__(self) -> None:
        metadata = load_model_metadata()
        self.feature_names = list(metadata.get("feature_columns") or [])

    def _key(self, location: str) -> str:
        return f"baseline:{location}"

    def update(self, location: str, features: Dict[str, Any]) -> None:
        if not self.feature_names:
            self.feature_names = list(features.keys())
        alpha = settings.BASELINE_ALPHA
        data = cache_manager.get(self._key(location)) or {
            "count": 0,
            "mean": {},
            "var": {},
        }

        count = int(data.get("count", 0))
        mean = dict(data.get("mean") or {})
        var = dict(data.get("var") or {})

        for name in self.feature_names:
            if name not in features:
                continue
            try:
                value = float(features.get(name))
            except Exception:
                continue

            if count == 0:
                mean[name] = value
                var[name] = 0.0
                continue

            prev_mean = float(mean.get(name, value))
            new_mean = (1 - alpha) * prev_mean + alpha * value
            # EWMA variance update (approx)
            prev_var = float(var.get(name, 0.0))
            new_var = (1 - alpha) * (prev_var + alpha * (value - prev_mean) ** 2)

            mean[name] = new_mean
            var[name] = new_var

        data["count"] = count + 1
        data["mean"] = mean
        data["var"] = var
        cache_manager.set(self._key(location), data, 3600)

    def get(self, location: str) -> Optional[Dict[str, Any]]:
        return cache_manager.get(self._key(location))


baseline_manager = BaselineManager()
