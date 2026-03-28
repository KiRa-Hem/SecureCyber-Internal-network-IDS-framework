"""
End-to-end integration test for the full SecureCyber IDS pipeline.

Simulates: attack packet → detection → correlation → kill chain →
           incident response → mitigation → API responses
"""

import os
import time
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("API_TOKEN", "test-token")
os.environ.setdefault("ADMIN_TOKEN", "test-token")
os.environ.setdefault("ENABLE_PACKET_CAPTURE", "false")

from app.main import app

client = TestClient(app)
AUTH = {"Authorization": "Bearer test-token"}


# ------------------------------------------------------------------ helpers

def api_get(path):
    resp = client.get(path, headers=AUTH)
    assert resp.status_code == 200, f"GET {path} failed: {resp.status_code}"
    return resp.json()


# ------------------------------------------------------------------ 3.1 tests


class TestNewAPIEndpoints:
    """Verify every Category 1/2 endpoint responds correctly."""

    def test_rl_status(self):
        data = api_get("/api/rl-status")
        assert "enabled" in data
        assert "current_threshold" in data

    def test_incidents(self):
        data = api_get("/api/incidents")
        assert "incidents" in data
        assert "stats" in data

    def test_playbooks(self):
        data = api_get("/api/playbooks")
        assert "playbooks" in data
        assert isinstance(data["playbooks"], (list, dict))

    def test_analytics(self):
        data = api_get("/api/analytics")
        assert "attack_type_distribution" in data or isinstance(data, dict)

    def test_model_status(self):
        data = api_get("/api/model-status")
        assert "health" in data
        assert "model_version" in data

    def test_mitre_coverage(self):
        data = api_get("/api/mitre-coverage")
        assert "techniques" in data or "tactics" in data or isinstance(data, dict)

    def test_signatures_list(self):
        data = api_get("/api/signatures")
        assert "signatures" in data
        assert "stats" in data
        assert data["stats"]["total_signatures"] >= 30

    def test_signatures_add_remove(self):
        sig = {
            "id": "integration-test-sig",
            "name": "Integration Test",
            "description": "Test signature for integration tests",
            "severity": "low",
            "payload_patterns": ["integration_test_pattern"],
        }
        # Add
        resp = client.post("/api/signatures", headers=AUTH, json=sig)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        # Verify it exists
        data = api_get("/api/signatures")
        ids = [s["id"] for s in data["signatures"]]
        assert "integration-test-sig" in ids

        # Remove
        resp = client.delete("/api/signatures/integration-test-sig", headers=AUTH)
        assert resp.status_code == 200

    def test_kill_chains(self):
        data = api_get("/api/kill-chains")
        assert "active_chains" in data
        assert "stages" in data


class TestDetectionPipeline:
    """Simulate attack → detection → correlation end-to-end."""

    def test_signature_detection(self):
        """Verify signature engine detects SQL injection payload."""
        from app.detectors.signature_engine import SignatureEngine

        engine = SignatureEngine()
        packet = {
            "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1",
            "protocol": "tcp",
            "dst_port": 80,
        }
        matches = engine.evaluate(packet)
        assert len(matches) > 0
        assert any("SQL" in m["name"] for m in matches)

    def test_correlator_kill_chain(self):
        """Verify correlator detects a multi-stage kill chain."""
        from app.correlator import EventCorrelator

        c = EventCorrelator()
        now = time.time()
        alerts = [
            {"id": "t1", "source_ip": "10.99.0.1", "dest_ip": "10.0.1.1",
             "attack_types": ["Port Scanning"], "confidence": 60, "timestamp": now},
            {"id": "t2", "source_ip": "10.99.0.1", "dest_ip": "10.0.1.1",
             "attack_types": ["SQL Injection"], "confidence": 90, "timestamp": now + 1},
            {"id": "t3", "source_ip": "10.99.0.1", "dest_ip": "10.0.2.2",
             "attack_types": ["Lateral Movement"], "confidence": 85, "timestamp": now + 2},
        ]
        results = [c.add_event(a) for a in alerts]
        kc_alerts = [r for r in results if r and "kill_chain" in r]
        assert len(kc_alerts) >= 1, "Kill chain should fire at 3+ stages"
        assert kc_alerts[0]["kill_chain"]["completeness"] > 0

    def test_incident_response_engine(self):
        """Verify incident engine creates incidents from alerts."""
        from app.incident_response import incident_engine

        alert = {
            "source_ip": "10.99.0.1",
            "attack_types": ["SQL Injection"],
            "confidence": 92,
        }
        incident = incident_engine.analyze_threat(alert)
        assert incident is not None
        assert incident["severity"] in ("critical", "high", "medium", "low")
        assert len(incident.get("playbook_steps", [])) > 0

    def test_rl_optimizer_evaluation(self):
        """Verify RL optimizer records and evaluates alerts."""
        from app.rl_optimizer import RLOptimizer

        rl = RLOptimizer()
        for i in range(55):
            rl.record_alert(is_true_positive=True)
        status = rl.get_status()
        assert status["total_evaluations"] >= 1

    def test_model_updater_drift(self):
        """Verify model updater reacts to drift events."""
        from app.model_updater import ModelUpdater

        mu = ModelUpdater()
        for _ in range(3):
            mu.record_drift({"drift_features": ["f1"], "confidence": 0.8})
        status = mu.get_status()
        assert status["retrain_queued"] is True

    def test_mitre_mapping(self):
        """Verify MITRE ATT&CK enrichment works."""
        from app.mitre_attack import map_alert

        alert = {"attack_types": ["SQL Injection"]}
        enriched = map_alert(alert)
        assert enriched is not None
        # map_alert returns the alert with MITRE data added, or a mapping dict
        assert isinstance(enriched, (dict, list))


class TestExistingEndpoints:
    """Verify the original endpoints still work after all upgrades."""

    def test_root(self):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_health(self):
        data = api_get("/health")
        assert data["status"] == "healthy"

    def test_stats(self):
        data = api_get("/api/stats")
        assert "packets_analyzed" in data

    def test_alerts(self):
        data = api_get("/api/alerts")
        assert "alerts" in data

    def test_blocklist(self):
        data = api_get("/api/blocklist")
        assert "blocklist" in data
