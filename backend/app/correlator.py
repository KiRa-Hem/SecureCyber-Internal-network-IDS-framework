"""
Event Correlator with Kill Chain Detection.

Tracks same-source and same-target attack patterns,
and detects multi-stage kill chain progressions:
Reconnaissance → Exploitation → Lateral Movement → Exfiltration.
"""

import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Kill chain stage definitions
# ---------------------------------------------------------------------------

KILL_CHAIN_STAGES = {
    "reconnaissance": {
        "order": 1,
        "attack_types": [
            "Port Scanning", "Vulnerability Scanner", "Directory Enumeration",
            "Subdomain Enumeration", "Reconnaissance", "Anomaly",
        ],
        "tags": ["reconnaissance", "scanning"],
    },
    "weaponization": {
        "order": 2,
        "attack_types": [
            "Web Shell Upload", "Deserialization Attack",
        ],
        "tags": ["webshell", "deserialization"],
    },
    "exploitation": {
        "order": 3,
        "attack_types": [
            "SQL Injection", "Cross-Site Scripting", "Command Injection",
            "Log4Shell Exploit", "Path Traversal", "SSRF Attack",
            "XXE Injection", "SMB Exploitation",
        ],
        "tags": ["injection", "exploit", "rce"],
    },
    "credential_access": {
        "order": 4,
        "attack_types": [
            "FTP Brute Force Signature", "SSH Brute Force", "RDP Brute Force",
            "Credential Dumping", "Pass-the-Hash Attack", "Brute Force",
        ],
        "tags": ["bruteforce", "credential"],
    },
    "lateral_movement": {
        "order": 5,
        "attack_types": [
            "Lateral Movement", "ARP Spoofing",
        ],
        "tags": ["lateral_movement", "mitm"],
    },
    "command_and_control": {
        "order": 6,
        "attack_types": [
            "C2 Beacon Communication", "Ransomware C2 Callback",
            "DNS Tunneling", "ICMP Tunneling",
        ],
        "tags": ["c2", "tunneling"],
    },
    "exfiltration": {
        "order": 7,
        "attack_types": [
            "Data Exfiltration", "Cloud Data Exfiltration",
            "Email Data Exfiltration", "Cryptocurrency Mining",
        ],
        "tags": ["exfiltration", "cryptomining"],
    },
}


def classify_stage(alert: Dict[str, Any]) -> Optional[str]:
    """Classify an alert into a kill chain stage."""
    attack_types = (
        alert.get("attack_types")
        or alert.get("attacks")
        or []
    )
    tags = alert.get("tags") or []

    for stage_name, stage_def in KILL_CHAIN_STAGES.items():
        for atype in attack_types:
            if atype in stage_def["attack_types"]:
                return stage_name
        for tag in tags:
            if tag in stage_def["tags"]:
                return stage_name
    return None


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class EventCorrelator:
    def __init__(self, window_seconds: int = None):
        self.window_seconds = window_seconds or settings.correlation_window_seconds
        self.events_by_source = defaultdict(list)
        self.events_by_target = defaultdict(list)
        self.correlated_events = []

        # Kill chain tracking per source IP
        self._kill_chains: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"stages": {}, "first_seen": None, "last_seen": None, "alerts": []}
        )
        self._kill_chain_alerts: List[Dict[str, Any]] = []

    def add_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Add an event, check for correlations AND kill chain progression.
        Returns a correlated/kill-chain event if found, None otherwise.
        """
        source_ip = event.get("source_ip", "")
        target_ip = event.get("dest_ip", "")
        timestamp = datetime.fromtimestamp(event.get("timestamp", time.time()))

        if not source_ip or not target_ip:
            return None

        # Add to source and target event lists
        self.events_by_source[source_ip].append((timestamp, event))
        self.events_by_target[target_ip].append((timestamp, event))

        # Clean old events
        self._clean_old_events()

        # Track kill chain stage
        kill_chain_alert = self._track_kill_chain(event, source_ip, timestamp)
        if kill_chain_alert:
            self._kill_chain_alerts.append(kill_chain_alert)
            return kill_chain_alert

        # Check for standard correlations
        correlated_event = self._check_correlations(event, source_ip, target_ip)
        if correlated_event:
            self.correlated_events.append(correlated_event)
            return correlated_event

        return None

    def _clean_old_events(self):
        """Remove events older than the correlation window."""
        cutoff = datetime.now() - timedelta(seconds=self.window_seconds)

        for source_ip in list(self.events_by_source.keys()):
            self.events_by_source[source_ip] = [
                (ts, event) for ts, event in self.events_by_source[source_ip]
                if ts > cutoff
            ]
            if not self.events_by_source[source_ip]:
                del self.events_by_source[source_ip]

        for target_ip in list(self.events_by_target.keys()):
            self.events_by_target[target_ip] = [
                (ts, event) for ts, event in self.events_by_target[target_ip]
                if ts > cutoff
            ]
            if not self.events_by_target[target_ip]:
                del self.events_by_target[target_ip]

        # Clean old kill chains
        for ip in list(self._kill_chains.keys()):
            chain = self._kill_chains[ip]
            if chain["last_seen"] and chain["last_seen"] < cutoff:
                del self._kill_chains[ip]

    # -------------------------------------------------------- kill chain

    def _track_kill_chain(
        self, event: Dict[str, Any], source_ip: str, timestamp: datetime
    ) -> Optional[Dict[str, Any]]:
        """Track kill chain stage progression and emit alert when threshold met."""
        stage = classify_stage(event)
        if not stage:
            return None

        chain = self._kill_chains[source_ip]
        if chain["first_seen"] is None:
            chain["first_seen"] = timestamp
        chain["last_seen"] = timestamp

        # Record this stage
        if stage not in chain["stages"]:
            chain["stages"][stage] = {
                "first_seen": timestamp,
                "alert_count": 0,
                "attack_types": set(),
            }
        chain["stages"][stage]["alert_count"] += 1
        attack_types = event.get("attack_types") or event.get("attacks") or []
        chain["stages"][stage]["attack_types"].update(attack_types)
        chain["alerts"].append(event.get("id", ""))

        # Compute kill chain completeness
        completed_stages = set(chain["stages"].keys())
        total_stages = len(KILL_CHAIN_STAGES)
        completeness = len(completed_stages) / total_stages

        # Check if we should emit a kill chain alert (≥3 different stages)
        if len(completed_stages) >= 3:
            # Only emit if we haven't already for this level of completeness
            prev_alert_stages = chain.get("_last_alert_stages", 0)
            if len(completed_stages) > prev_alert_stages:
                chain["_last_alert_stages"] = len(completed_stages)
                return self._build_kill_chain_alert(source_ip, chain, completeness)

        return None

    def _build_kill_chain_alert(
        self, source_ip: str, chain: Dict, completeness: float
    ) -> Dict[str, Any]:
        """Build an alert for kill chain detection."""
        stages_ordered = sorted(
            chain["stages"].items(),
            key=lambda x: KILL_CHAIN_STAGES.get(x[0], {}).get("order", 99),
        )
        stage_names = [s[0] for s in stages_ordered]
        all_attack_types = set()
        for _, info in stages_ordered:
            all_attack_types.update(info["attack_types"])

        severity = "critical" if completeness >= 0.6 else "high"
        confidence = min(99, int(completeness * 100 + 20))

        description = (
            f"Kill chain detected from {source_ip}: "
            f"{' → '.join(stage_names)} "
            f"({int(completeness * 100)}% complete, "
            f"{len(chain['alerts'])} related alerts)"
        )

        return {
            "id": f"kc-{int(time.time())}",
            "timestamp": int(time.time()),
            "source_ip": source_ip,
            "dest_ip": "multiple",
            "attack_types": ["Kill Chain Detected"],
            "attacks": list(all_attack_types),
            "confidence": confidence,
            "severity": severity,
            "payload_snippet": description,
            "description": description,
            "path": [],
            "mitigation": {
                "action": "block" if completeness >= 0.5 else "flagged",
                "by": "kill-chain-detector",
            },
            "kill_chain": {
                "source_ip": source_ip,
                "completeness": round(completeness, 2),
                "stages": {
                    name: {
                        "attack_types": list(info["attack_types"]),
                        "alert_count": info["alert_count"],
                    }
                    for name, info in stages_ordered
                },
                "total_alerts": len(chain["alerts"]),
            },
            "correlated_events": chain["alerts"][-20:],
        }

    # -------------------------------------------------------- standard correlation

    def _check_correlations(
        self, event: Dict[str, Any], source_ip: str, target_ip: str
    ) -> Optional[Dict[str, Any]]:
        """Check for correlations with existing events."""
        correlated_events = []

        for ts, existing_event in self.events_by_source.get(source_ip, []):
            if existing_event["id"] != event["id"]:
                correlated_events.append(existing_event)

        for ts, existing_event in self.events_by_target.get(target_ip, []):
            if existing_event["id"] != event["id"]:
                correlated_events.append(existing_event)

        if correlated_events:
            attack_types = set(event.get("attacks", []) or event.get("attack_types", []))
            for existing_event in correlated_events:
                attack_types.update(
                    existing_event.get("attacks", [])
                    or existing_event.get("attack_types", [])
                )

            base_confidence = event.get("confidence", 50)
            confidence_boost = min(20, len(correlated_events) * 5)
            confidence = min(99, base_confidence + confidence_boost)

            correlated_event = {
                "id": f"corr-{int(time.time())}",
                "timestamp": int(time.time()),
                "source_ip": source_ip,
                "dest_ip": target_ip,
                "attacks": list(attack_types),
                "attack_types": list(attack_types),
                "confidence": confidence,
                "payload_snippet": f"Correlated event: {len(correlated_events) + 1} related events",
                "path": event.get("path", []),
                "mitigation": {
                    "action": "blocked" if confidence > 80 else "flagged",
                    "by": "correlation-engine",
                },
                "correlated_events": [e["id"] for e in correlated_events] + [event["id"]],
            }
            return correlated_event

        return None

    # -------------------------------------------------------- query API

    def get_kill_chains(self) -> List[Dict[str, Any]]:
        """Return active kill chain tracking data."""
        chains = []
        for ip, chain in self._kill_chains.items():
            if not chain["stages"]:
                continue
            stages_ordered = sorted(
                chain["stages"].items(),
                key=lambda x: KILL_CHAIN_STAGES.get(x[0], {}).get("order", 99),
            )
            completeness = len(chain["stages"]) / len(KILL_CHAIN_STAGES)
            chains.append({
                "source_ip": ip,
                "completeness": round(completeness, 2),
                "stages": {
                    name: {
                        "attack_types": list(info["attack_types"]),
                        "alert_count": info["alert_count"],
                    }
                    for name, info in stages_ordered
                },
                "total_alerts": len(chain["alerts"]),
            })
        chains.sort(key=lambda x: x["completeness"], reverse=True)
        return chains

    def get_kill_chain_alerts(self) -> List[Dict[str, Any]]:
        """Return kill chain alert history."""
        return list(reversed(self._kill_chain_alerts[-20:]))


# Global correlator instance
correlator = EventCorrelator()