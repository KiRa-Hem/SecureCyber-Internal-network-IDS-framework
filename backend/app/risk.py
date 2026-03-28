import logging
from typing import Any, Dict, Optional

from app.config import settings

logger = logging.getLogger(__name__)


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_confidence(value: Any) -> float:
    score = _coerce_float(value, 0.0)
    if score > 1.0:
        if score <= 100.0:
            score = score / 100.0
        else:
            score = 1.0
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return score


class RiskFusionEngine:
    """Weighted risk scorer for dual-pipeline + drift signals."""

    SIGNALS = ("xgboost", "anomaly", "drift")

    def _weights(self) -> Dict[str, float]:
        raw = {
            "xgboost": _coerce_float(getattr(settings, "RISK_WEIGHT_XGBOOST", 0.55), 0.55),
            "anomaly": _coerce_float(getattr(settings, "RISK_WEIGHT_ANOMALY", 0.30), 0.30),
            "drift": _coerce_float(getattr(settings, "RISK_WEIGHT_DRIFT", 0.15), 0.15),
        }
        return {name: max(0.0, weight) for name, weight in raw.items()}

    def evaluate(
        self,
        *,
        xgb_result: Optional[Dict[str, Any]] = None,
        xgb_is_attack: bool = False,
        anomaly_result: Optional[Dict[str, Any]] = None,
        drift_alert: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        min_component_score = _coerce_float(getattr(settings, "RISK_MIN_COMPONENT_SCORE", 0.5), 0.5)
        weights = self._weights()

        xgb_available = isinstance(xgb_result, dict)
        xgb_score = _normalize_confidence((xgb_result or {}).get("confidence")) if xgb_available else 0.0
        xgb_active = bool(xgb_is_attack or xgb_score >= min_component_score)

        anomaly_available = isinstance(anomaly_result, dict)
        anomaly_is_anomaly = bool((anomaly_result or {}).get("is_anomaly")) if anomaly_available else False
        anomaly_confidence = _normalize_confidence((anomaly_result or {}).get("confidence")) if anomaly_available else 0.0
        anomaly_score = anomaly_confidence if anomaly_is_anomaly else 0.0
        anomaly_active = anomaly_is_anomaly

        drift_available = isinstance(drift_alert, dict)
        drift_score = _normalize_confidence((drift_alert or {}).get("confidence", 0.6)) if drift_available else 0.0
        drift_active = drift_available and drift_score >= 0.0

        components = {
            "xgboost": {
                "available": xgb_available,
                "active": xgb_active,
                "score": xgb_score,
                "weight": weights["xgboost"],
            },
            "anomaly": {
                "available": anomaly_available,
                "active": anomaly_active,
                "score": anomaly_score,
                "weight": weights["anomaly"],
            },
            "drift": {
                "available": drift_available,
                "active": drift_active,
                "score": drift_score,
                "weight": weights["drift"],
            },
        }

        available_weight = sum(
            item["weight"] for item in components.values() if item["available"] and item["weight"] > 0.0
        )
        weighted_sum = sum(
            item["score"] * item["weight"]
            for item in components.values()
            if item["available"] and item["weight"] > 0.0
        )
        score = (weighted_sum / available_weight) if available_weight > 0.0 else 0.0

        active_signals = [name for name, item in components.items() if item["active"]]

        return {
            "score": max(0.0, min(1.0, score)),
            "signal_count": len(active_signals),
            "signals": active_signals,
            "components": components,
            "threshold": _coerce_float(getattr(settings, "RISK_ALERT_THRESHOLD", 0.75), 0.75),
            "autoblock_threshold": _coerce_float(getattr(settings, "RISK_AUTOBLOCK_THRESHOLD", 0.92), 0.92),
        }

    def should_emit_alert(self, assessment: Dict[str, Any]) -> bool:
        if not bool(getattr(settings, "RISK_SCORING_ENABLED", True)):
            return False
        score = _coerce_float(assessment.get("score"), 0.0)
        threshold = _coerce_float(getattr(settings, "RISK_ALERT_THRESHOLD", 0.75), 0.75)
        min_signals = max(1, int(getattr(settings, "RISK_ALERT_MIN_SIGNALS", 1)))
        return score >= threshold and int(assessment.get("signal_count", 0)) >= min_signals

    def should_auto_block(self, assessment: Dict[str, Any]) -> bool:
        if not bool(getattr(settings, "RISK_SCORING_ENABLED", True)):
            return False
        if not bool(getattr(settings, "RISK_AUTOBLOCK_ENABLED", False)):
            return False
        if not bool(getattr(settings, "ENABLE_REAL_MITIGATION", False)):
            return False
        score = _coerce_float(assessment.get("score"), 0.0)
        threshold = _coerce_float(getattr(settings, "RISK_AUTOBLOCK_THRESHOLD", 0.92), 0.92)
        min_signals = max(1, int(getattr(settings, "RISK_AUTOBLOCK_MIN_SIGNALS", 2)))
        return score >= threshold and int(assessment.get("signal_count", 0)) >= min_signals


risk_engine = RiskFusionEngine()
