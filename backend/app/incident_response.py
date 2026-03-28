"""
Incident Response & Playbook Engine.

Provides attack-specific response playbooks with prioritized steps,
automated narrative generation, and incident timeline tracking.
"""

import logging
import time
import uuid
from collections import deque
from typing import Any, Dict, List, Optional

from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Playbook definitions
# ---------------------------------------------------------------------------

PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "SQL Injection": {
        "severity": "critical",
        "mitre_id": "T1190",
        "steps": [
            {"action": "block_source_ip", "priority": 1, "automated": True,
             "description": "Block the source IP at the firewall to stop ongoing injection attempts."},
            {"action": "isolate_target", "priority": 2, "automated": True,
             "description": "Isolate the targeted web server to prevent data exfiltration."},
            {"action": "scan_database", "priority": 3, "automated": False,
             "description": "Audit database logs for unauthorized queries or data extraction."},
            {"action": "patch_application", "priority": 4, "automated": False,
             "description": "Deploy parameterized query patches and input validation updates."},
            {"action": "notify_team", "priority": 5, "automated": True,
             "description": "Alert the security operations team with incident details."},
        ],
    },
    "Cross-Site Scripting": {
        "severity": "high",
        "mitre_id": "T1059.007",
        "steps": [
            {"action": "block_source_ip", "priority": 1, "automated": True,
             "description": "Block the source IP to prevent further XSS payload delivery."},
            {"action": "sanitize_output", "priority": 2, "automated": False,
             "description": "Review and enforce output encoding on affected endpoints."},
            {"action": "invalidate_sessions", "priority": 3, "automated": True,
             "description": "Invalidate active sessions that may have been compromised."},
            {"action": "scan_stored_xss", "priority": 4, "automated": False,
             "description": "Search the database for stored XSS payloads in user-generated content."},
            {"action": "notify_team", "priority": 5, "automated": True,
             "description": "Alert the security operations team with incident details."},
        ],
    },
    "DDoS Flood": {
        "severity": "critical",
        "mitre_id": "T1498",
        "steps": [
            {"action": "enable_rate_limiting", "priority": 1, "automated": True,
             "description": "Activate aggressive rate limiting on edge routers and load balancers."},
            {"action": "activate_scrubbing", "priority": 2, "automated": True,
             "description": "Enable upstream traffic scrubbing / CDN-based DDoS protection."},
            {"action": "block_source_network", "priority": 3, "automated": True,
             "description": "Block the source IP range at the network perimeter."},
            {"action": "scale_infrastructure", "priority": 4, "automated": False,
             "description": "Scale backend infrastructure to absorb residual traffic."},
            {"action": "notify_team", "priority": 5, "automated": True,
             "description": "Alert the NOC and security operations team."},
        ],
    },
    "FTP Brute Force Signature": {
        "severity": "high",
        "mitre_id": "T1110",
        "steps": [
            {"action": "block_source_ip", "priority": 1, "automated": True,
             "description": "Block the brute-forcing IP address immediately."},
            {"action": "enforce_lockout", "priority": 2, "automated": True,
             "description": "Enable account lockout after 5 failed attempts."},
            {"action": "reset_credentials", "priority": 3, "automated": False,
             "description": "Force password reset for targeted accounts."},
            {"action": "enable_mfa", "priority": 4, "automated": False,
             "description": "Enable multi-factor authentication on the FTP service."},
            {"action": "notify_team", "priority": 5, "automated": True,
             "description": "Alert the security team with brute force attempt details."},
        ],
    },
    "Command Injection": {
        "severity": "critical",
        "mitre_id": "T1059",
        "steps": [
            {"action": "block_source_ip", "priority": 1, "automated": True,
             "description": "Block the source IP to stop command execution attempts."},
            {"action": "isolate_target", "priority": 2, "automated": True,
             "description": "Isolate the compromised server from the network."},
            {"action": "forensic_snapshot", "priority": 3, "automated": False,
             "description": "Capture a forensic image of the affected system."},
            {"action": "audit_processes", "priority": 4, "automated": False,
             "description": "Review running processes and connections for backdoors."},
            {"action": "notify_team", "priority": 5, "automated": True,
             "description": "Escalate to incident response team for full investigation."},
        ],
    },
    "Log4Shell Exploit": {
        "severity": "critical",
        "mitre_id": "T1190",
        "steps": [
            {"action": "block_source_ip", "priority": 1, "automated": True,
             "description": "Block the source IP sending JNDI payloads."},
            {"action": "isolate_target", "priority": 2, "automated": True,
             "description": "Isolate Java-based services from the network."},
            {"action": "patch_log4j", "priority": 3, "automated": False,
             "description": "Update Log4j to the latest patched version across all services."},
            {"action": "scan_indicators", "priority": 4, "automated": False,
             "description": "Scan for indicators of compromise (reverse shells, crypto miners)."},
            {"action": "notify_team", "priority": 5, "automated": True,
             "description": "Escalate to CISO with full CVE-2021-44228 impact report."},
        ],
    },
    "Path Traversal": {
        "severity": "high",
        "mitre_id": "T1083",
        "steps": [
            {"action": "block_source_ip", "priority": 1, "automated": True,
             "description": "Block the source IP attempting directory traversal."},
            {"action": "audit_file_access", "priority": 2, "automated": False,
             "description": "Check access logs for successful file reads (passwd, shadow, etc.)."},
            {"action": "harden_web_server", "priority": 3, "automated": False,
             "description": "Configure web server to prevent path-based escapes."},
            {"action": "notify_team", "priority": 4, "automated": True,
             "description": "Alert the security operations team."},
        ],
    },
    "Drift": {
        "severity": "medium",
        "mitre_id": "TA0001",
        "steps": [
            {"action": "increase_monitoring", "priority": 1, "automated": True,
             "description": "Increase detection sensitivity for novel patterns."},
            {"action": "capture_samples", "priority": 2, "automated": True,
             "description": "Capture traffic samples for offline analysis."},
            {"action": "trigger_retrain", "priority": 3, "automated": True,
             "description": "Queue model retraining with recent data."},
            {"action": "notify_team", "priority": 4, "automated": True,
             "description": "Notify the ML ops team about potential concept drift."},
        ],
    },
}

# Fallback playbook for unknown attack types
DEFAULT_PLAYBOOK: Dict[str, Any] = {
    "severity": "medium",
    "mitre_id": "TA0001",
    "steps": [
        {"action": "block_source_ip", "priority": 1, "automated": True,
         "description": "Block the suspicious source IP as a precaution."},
        {"action": "increase_monitoring", "priority": 2, "automated": True,
         "description": "Elevate monitoring level for the affected network segment."},
        {"action": "capture_traffic", "priority": 3, "automated": True,
         "description": "Initiate packet capture for forensic analysis."},
        {"action": "notify_team", "priority": 4, "automated": True,
         "description": "Alert the security team for manual investigation."},
    ],
}


# ---------------------------------------------------------------------------
# Incident Response Engine
# ---------------------------------------------------------------------------

class IncidentResponseEngine:
    """Generates playbook-driven incident responses for detected threats."""

    DEDUP_COOLDOWN_SECONDS = 60  # Same (IP, attack) won't create a new incident within this window

    def __init__(self):
        self.incidents: deque = deque(maxlen=settings.IR_MAX_INCIDENTS)
        self.incident_count: int = 0
        self._dedup_map: Dict[str, float] = {}  # key → last_incident_time

    # ------------------------------------------------------------------ core

    def analyze_threat(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an alert and produce an incident response with playbook steps."""
        if not settings.IR_ENABLED:
            return {}

        attack_types = (
            alert.get("attack_types")
            or alert.get("attacks")
            or ["Unknown"]
        )
        primary_attack = attack_types[0] if attack_types else "Unknown"
        source_ip = alert.get("source_ip", "unknown")

        # Deduplication: skip if same (IP, attack) was recently processed
        dedup_key = f"{source_ip}|{primary_attack}"
        now = time.time()
        last_time = self._dedup_map.get(dedup_key, 0)
        if now - last_time < self.DEDUP_COOLDOWN_SECONDS:
            return {}  # Suppress duplicate incident
        self._dedup_map[dedup_key] = now

        # Evict stale dedup entries every 200 incidents to prevent memory growth
        if len(self._dedup_map) > 500:
            cutoff = now - self.DEDUP_COOLDOWN_SECONDS * 2
            self._dedup_map = {k: v for k, v in self._dedup_map.items() if v > cutoff}

        playbook = self._resolve_playbook(primary_attack)
        severity = playbook["severity"]
        steps = playbook["steps"]

        narrative = self._generate_narrative(alert, primary_attack, severity)

        self.incident_count += 1
        incident = {
            "id": f"INC-{self.incident_count:05d}",
            "timestamp": int(time.time()),
            "alert_id": alert.get("id", ""),
            "attack_type": primary_attack,
            "all_attack_types": attack_types,
            "severity": severity,
            "source_ip": source_ip,
            "target_ip": alert.get("dest_ip", alert.get("dst_ip", "unknown")),
            "target_node": alert.get("target_node", "unknown"),
            "confidence": alert.get("confidence", 0),
            "narrative": narrative,
            "playbook_steps": steps,
            "status": "active",
            "mitre_id": playbook.get("mitre_id", ""),
        }

        self.incidents.appendleft(incident)
        logger.info("Incident %s created for %s from %s",
                     incident["id"], primary_attack, incident["source_ip"])
        return incident

    # ------------------------------------------------------------------ query

    def get_active_incidents(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(self.incidents)[:limit]

    def get_playbook(self, attack_type: str) -> Dict[str, Any]:
        return self._resolve_playbook(attack_type)

    def get_all_playbooks(self) -> Dict[str, Dict[str, Any]]:
        return {**PLAYBOOKS}

    def get_stats(self) -> Dict[str, Any]:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for inc in self.incidents:
            sev = inc.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1
        return {
            "total_incidents": self.incident_count,
            "active_incidents": len(self.incidents),
            "severity_breakdown": severity_counts,
        }

    # ---------------------------------------------------------------- helpers

    def _resolve_playbook(self, attack_type: str) -> Dict[str, Any]:
        if attack_type in PLAYBOOKS:
            return PLAYBOOKS[attack_type]
        # Fuzzy match
        lower = attack_type.lower()
        for key, pb in PLAYBOOKS.items():
            if key.lower() in lower or lower in key.lower():
                return pb
        return DEFAULT_PLAYBOOK

    def _generate_narrative(
        self, alert: Dict[str, Any], attack_type: str, severity: str
    ) -> str:
        src = alert.get("source_ip", "unknown")
        dst = alert.get("dest_ip", alert.get("dst_ip", "unknown"))
        target_node = alert.get("target_node", "unknown")
        confidence = alert.get("confidence", 0)
        if isinstance(confidence, float) and confidence <= 1.0:
            confidence = int(confidence * 100)

        lines = [
            f"🚨 {severity.upper()} SEVERITY — {attack_type} detected.",
            f"Source: {src} → Target: {dst} (node: {target_node}).",
            f"Detection confidence: {confidence}%.",
        ]

        playbook = self._resolve_playbook(attack_type)
        automated = [s for s in playbook["steps"] if s.get("automated")]
        manual = [s for s in playbook["steps"] if not s.get("automated")]

        if automated:
            lines.append(
                f"Automated actions: {', '.join(s['action'] for s in automated)}."
            )
        if manual:
            lines.append(
                f"Manual review required: {', '.join(s['action'] for s in manual)}."
            )

        return " ".join(lines)


# Global instance
incident_engine = IncidentResponseEngine()
