import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from app.detectors.signature_engine import SignatureEngine


class RuleBasedDetector:
    """Signature-driven detection engine that wraps predefined regex/network signatures."""

    def __init__(self, signature_file: Optional[str] = None):
        self.engine = SignatureEngine(signature_file)

    def detect(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect attacks based on packet metadata/payload using configurable signatures.
        Returns alert data if an attack is detected, None otherwise.
        """
        matches = self.engine.evaluate(packet_data)
        if not matches:
            return None

        attacks = [match["name"] for match in matches]
        confidence = max(match["confidence"] for match in matches)
        payload = packet_data.get("payload", "")
        payload_snippet = payload[:512] if isinstance(payload, str) else str(payload)[:512]

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": int(datetime.now().timestamp()),
            "source_ip": packet_data.get("source_ip") or packet_data.get("src_ip", ""),
            "dest_ip": packet_data.get("dest_ip") or packet_data.get("dst_ip", ""),
            "attacks": attacks,
            "attack_types_short": [attack.split()[0] for attack in attacks],
            "confidence": confidence,
            "payload_snippet": payload_snippet,
            "path": packet_data.get("path", []),
            "area_of_effect": packet_data.get("area_of_effect", {"nodes": [], "radius": 0}),
            "mitigation": {"action": "flagged", "by": "rule-based-detector"},
            "packets_analyzed": 1,
            "signatures": matches,
        }
        return alert
