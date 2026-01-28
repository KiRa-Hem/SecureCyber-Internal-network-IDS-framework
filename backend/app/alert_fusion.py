import time
import uuid
from typing import Any, Dict, List, Tuple


WEIGHTS = {
    "rule-based-detector": 0.7,
    "dos-detector": 0.9,
    "xgboost": 0.8,
    "isolation-forest": 0.5,
    "unknown": 0.6,
}


def _detector_name(alert: Dict[str, Any]) -> str:
    mitigation = alert.get("mitigation", {}) if isinstance(alert.get("mitigation"), dict) else {}
    return str(mitigation.get("by") or alert.get("detector") or "unknown")


def _confidence(alert: Dict[str, Any]) -> float:
    try:
        return float(alert.get("confidence", 0.5))
    except Exception:
        return 0.5


def _merge_mitigation(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not alerts:
        return {"action": "flagged", "by": "fusion"}
    priority = {"blocked": 2, "block": 2, "flagged": 1}
    best = max(alerts, key=lambda a: priority.get(a.get("mitigation", {}).get("action", "flagged"), 0))
    mitigation = dict(best.get("mitigation", {}))
    mitigation["by"] = "fusion"
    return mitigation


def fuse_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fuse alerts from multiple detectors into a single enriched alert."""
    if not alerts:
        return []
    if len(alerts) == 1:
        return alerts

    attack_types = []
    detectors = []
    confidences = []

    for alert in alerts:
        attacks = alert.get("attack_types") or alert.get("attacks") or []
        if isinstance(attacks, str):
            attacks = [attacks]
        for attack in attacks:
            if attack not in attack_types:
                attack_types.append(attack)
        detector = _detector_name(alert)
        detectors.append(detector)
        confidences.append((_confidence(alert), WEIGHTS.get(detector, WEIGHTS["unknown"])))

    weighted_scores = [score * weight for score, weight in confidences]
    fusion_score = max(weighted_scores) if weighted_scores else 0.5

    base = max(alerts, key=_confidence)
    fused = dict(base)
    fused["id"] = f"fused-{uuid.uuid4()}"
    fused["timestamp"] = int(time.time())
    fused["attack_types"] = attack_types
    fused["attacks"] = attack_types
    fused["confidence"] = max(_confidence(alert) for alert in alerts)
    fused["fusion_score"] = fusion_score
    fused["detectors"] = detectors
    fused["mitigation"] = _merge_mitigation(alerts)
    fused["correlated_events"] = fused.get("correlated_events", [])
    return [fused]
