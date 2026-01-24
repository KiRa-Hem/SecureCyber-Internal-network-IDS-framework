import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

SEVERITY_CONFIDENCE = {
    "critical": 98,
    "high": 92,
    "medium": 80,
    "low": 65,
}

DEFAULT_SIGNATURES = [
    {
        "id": "sqli-basic",
        "name": "SQL Injection",
        "description": "Detects common SQL keywords and boolean bypass operators in HTTP payloads.",
        "severity": "high",
        "tags": ["web", "injection"],
        "protocol": "tcp",
        "dst_ports": [80, 443, 8080],
        "payload_patterns": [
            r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b",
            r"(?i)\bOR\s+1=1\b",
            r"(?i)(['\"]\s*or\s*['\"])",
            r"(?i)--",
        ],
    },
    {
        "id": "xss-basic",
        "name": "Cross-Site Scripting",
        "description": "Detects script tags or javascript URIs commonly used in reflected XSS attacks.",
        "severity": "medium",
        "tags": ["web", "injection"],
        "protocol": "tcp",
        "dst_ports": [80, 443, 8080],
        "payload_patterns": [
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)on\w+\s*=",
            r"(?i)javascript:",
        ],
    },
    {
        "id": "cmd-injection",
        "name": "Command Injection",
        "description": "Detects shell metacharacters combined with system utilities.",
        "severity": "high",
        "tags": ["system", "execution"],
        "payload_patterns": [
            r"(?i)[;&|]+\s*(?:cat|ls|bash|sh|powershell|whoami|wget|curl)\b",
            r"(?i);\s*rm\s+-rf",
        ],
    },
    {
        "id": "log4shell",
        "name": "Log4Shell Exploit",
        "description": "Detects JNDI lookups indicative of CVE-2021-44228.",
        "severity": "critical",
        "tags": ["java", "rce"],
        "payload_patterns": [
            r"(?i)\$\{jndi:(?:ldap|rmi|dns|http)[^}]+\}",
        ],
    },
    {
        "id": "path-traversal",
        "name": "Path Traversal",
        "description": "Detects attempts to escape web roots via ../ sequences.",
        "severity": "medium",
        "tags": ["filesystem"],
        "payload_patterns": [
            r"\.\./\.\./",
            r"(?i)etc/passwd",
            r"(?i)windows[/\\]system32",
        ],
    },
    {
        "id": "ftp-bruteforce",
        "name": "FTP Brute Force Signature",
        "description": "Flags repeated FTP login attempts flagged upstream.",
        "severity": "medium",
        "tags": ["bruteforce"],
        "field_equals": {"service": "ftp"},
        "metadata": {"category": "bruteforce"},
    },
]


@dataclass
class SignatureDefinition:
    id: str
    name: str
    description: str
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    protocol: Optional[str] = None
    src_ports: List[int] = field(default_factory=list)
    dst_ports: List[int] = field(default_factory=list)
    payload_patterns: List[str] = field(default_factory=list)
    field_equals: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    compiled_patterns: List[re.Pattern] = field(init=False, default_factory=list)

    def __post_init__(self):
        self.severity = (self.severity or "medium").lower()
        self.compiled_patterns = []
        for pattern in self.payload_patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern))
            except re.error as exc:
                logger.warning("Invalid regex for signature %s: %s", self.id, exc)


class SignatureEngine:
    """Loads YAML-defined signatures and evaluates packets against them."""

    def __init__(self, signature_path: Optional[str | Path] = None):
        default_path = Path(__file__).with_name("signatures.yaml")
        self.signature_path = Path(signature_path) if signature_path else default_path
        self.signatures: List[SignatureDefinition] = []
        self._load_signatures()

    def _load_signatures(self):
        if self.signature_path.exists():
            with open(self.signature_path, "r", encoding="utf-8") as handle:
                raw_data = yaml.safe_load(handle) or []
            logger.info("Loaded %d signatures from %s", len(raw_data), self.signature_path)
        else:
            logger.warning(
                "Signature file %s not found; falling back to built-in defaults.",
                self.signature_path,
            )
            raw_data = DEFAULT_SIGNATURES

        self.signatures = [SignatureDefinition(**entry) for entry in raw_data]

    def evaluate(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches = []
        for signature in self.signatures:
            evidence = self._match_signature(signature, packet)
            if not evidence:
                continue
            match_payload = {
                "id": signature.id,
                "name": signature.name,
                "severity": signature.severity,
                "confidence": SEVERITY_CONFIDENCE.get(signature.severity, 70),
                "tags": signature.tags,
                "description": signature.description,
                "evidence": evidence,
                "metadata": signature.metadata,
            }
            matches.append(match_payload)
        return matches

    def _match_signature(
        self,
        signature: SignatureDefinition,
        packet: Dict[str, Any],
    ) -> List[str]:
        protocol = (
            packet.get("protocol")
            or packet.get("protocol_name")
            or packet.get("protocol_type")
        )
        if signature.protocol and protocol:
            if protocol.lower() != signature.protocol.lower():
                return []

        if signature.src_ports:
            src_port = packet.get("src_port") or packet.get("source_port")
            if src_port is not None and src_port not in signature.src_ports:
                return []

        if signature.dst_ports:
            dst_port = packet.get("dst_port") or packet.get("dest_port")
            if dst_port is not None and dst_port not in signature.dst_ports:
                return []

        for field, expected in signature.field_equals.items():
            actual = packet.get(field)
            if actual is None or str(actual).lower() != str(expected).lower():
                return []

        evidence: List[str] = []
        payload = packet.get("payload", "")
        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8", errors="ignore")
            except Exception:  # pragma: no cover - fallback
                payload = str(payload)

        if signature.compiled_patterns:
            for pattern in signature.compiled_patterns:
                if pattern.search(payload):
                    evidence.append(pattern.pattern)
        else:
            # Signatures without payload patterns rely only on metadata/fields.
            evidence.append("metadata-match")

        return evidence if evidence else []
