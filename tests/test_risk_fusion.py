import os
import sys
from unittest.mock import MagicMock

import pytest

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.risk import risk_engine
from app.sensors import SensorWorker
import app.risk as risk_module
import app.sensors as sensors_module


def test_risk_fusion_weighted_score_and_alert(monkeypatch):
    monkeypatch.setattr(risk_module.settings, "RISK_SCORING_ENABLED", True, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_WEIGHT_XGBOOST", 0.5, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_WEIGHT_ANOMALY", 0.3, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_WEIGHT_DRIFT", 0.2, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_ALERT_THRESHOLD", 0.8, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_ALERT_MIN_SIGNALS", 2, raising=False)

    assessment = risk_engine.evaluate(
        xgb_result={"confidence": 0.9},
        xgb_is_attack=True,
        anomaly_result={"is_anomaly": True, "confidence": 0.8},
        drift_alert={"confidence": 0.6},
    )

    assert assessment["signal_count"] == 3
    assert assessment["signals"] == ["xgboost", "anomaly", "drift"]
    assert assessment["score"] == pytest.approx(0.81, rel=1e-3)
    assert risk_engine.should_emit_alert(assessment) is True


def test_risk_fusion_autoblock_requires_explicit_flags(monkeypatch):
    monkeypatch.setattr(risk_module.settings, "RISK_SCORING_ENABLED", True, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_AUTOBLOCK_ENABLED", True, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_AUTOBLOCK_THRESHOLD", 0.9, raising=False)
    monkeypatch.setattr(risk_module.settings, "RISK_AUTOBLOCK_MIN_SIGNALS", 2, raising=False)

    assessment = {"score": 0.95, "signal_count": 2}

    # Mitigation must still be explicitly enabled in runtime settings.
    monkeypatch.setattr(risk_module.settings, "ENABLE_REAL_MITIGATION", False, raising=False)
    assert risk_engine.should_auto_block(assessment) is False

    monkeypatch.setattr(risk_module.settings, "ENABLE_REAL_MITIGATION", True, raising=False)
    assert risk_engine.should_auto_block(assessment) is True


def test_sensor_worker_gate_blocks_only_risk_backed_alerts(monkeypatch):
    worker = SensorWorker("edge", MagicMock(), {})

    monkeypatch.setattr(sensors_module.settings, "ENABLE_REAL_MITIGATION", True, raising=False)
    monkeypatch.setattr(sensors_module.settings, "RISK_SCORING_ENABLED", True, raising=False)
    monkeypatch.setattr(sensors_module.settings, "RISK_AUTOBLOCK_ENABLED", True, raising=False)
    monkeypatch.setattr(sensors_module.settings, "RISK_AUTOBLOCK_THRESHOLD", 0.9, raising=False)
    monkeypatch.setattr(sensors_module.settings, "RISK_AUTOBLOCK_MIN_SIGNALS", 2, raising=False)

    no_risk_alert = {
        "source_ip": "192.0.2.10",
        "mitigation": {"action": "block", "by": "dos-detector"},
    }
    assert worker._should_auto_block(no_risk_alert) is False

    risk_backed_alert = {
        "source_ip": "192.0.2.10",
        "mitigation": {"action": "block", "by": "risk-fusion"},
        "risk_assessment": {"score": 0.95, "signal_count": 3},
    }
    assert worker._should_auto_block(risk_backed_alert) is True
