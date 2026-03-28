"""
MITRE ATT&CK Framework mapping for IDS alerts.

Maps detected attack types to ATT&CK technique IDs, tactics,
and enriches alerts with framework-aligned metadata.
"""

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique mapping
# ---------------------------------------------------------------------------

TECHNIQUE_MAP: Dict[str, Dict[str, Any]] = {
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "SQL injection via web application input fields.",
        "severity_weight": 0.95,
    },
    "Cross-Site Scripting": {
        "technique_id": "T1059.007",
        "technique_name": "JavaScript Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Client-side script injection via reflected/stored XSS.",
        "severity_weight": 0.80,
    },
    "Command Injection": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "OS command injection through unsanitized inputs.",
        "severity_weight": 0.95,
    },
    "Log4Shell Exploit": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "JNDI injection exploiting CVE-2021-44228 (Log4Shell).",
        "severity_weight": 1.00,
    },
    "Path Traversal": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Directory traversal to access restricted files.",
        "severity_weight": 0.75,
    },
    "DDoS Flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Volumetric flood attack to degrade service availability.",
        "severity_weight": 0.90,
    },
    "DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Denial of service via traffic flooding.",
        "severity_weight": 0.90,
    },
    "FTP Brute Force Signature": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Credential stuffing or brute force against FTP service.",
        "severity_weight": 0.80,
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Automated credential guessing against authentication services.",
        "severity_weight": 0.80,
    },
    "Drift": {
        "technique_id": "T1036",
        "technique_name": "Masquerading",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Feature drift may indicate novel or evasive attack patterns.",
        "severity_weight": 0.60,
    },
    "Lateral Movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "description": "Movement between network hosts using valid credentials.",
        "severity_weight": 0.90,
    },
    "Data Exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Data transfer to external command and control servers.",
        "severity_weight": 0.95,
    },
    "Reconnaissance": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "description": "Network scanning and service enumeration.",
        "severity_weight": 0.50,
    },
}

# All recognized MITRE tactics for the heatmap
ALL_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance"},
    {"id": "TA0042", "name": "Resource Development"},
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]


def map_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich an alert dict with MITRE ATT&CK metadata."""
    attack_types = (
        alert.get("attack_types")
        or alert.get("attacks")
        or []
    )
    mappings: List[Dict[str, Any]] = []
    for attack in attack_types:
        mapping = TECHNIQUE_MAP.get(attack)
        if mapping:
            mappings.append(mapping)
        else:
            # Fuzzy match
            lower = attack.lower()
            for key, value in TECHNIQUE_MAP.items():
                if key.lower() in lower or lower in key.lower():
                    mappings.append(value)
                    break

    if mappings:
        alert["mitre_attack"] = mappings
        alert["mitre_techniques"] = list({m["technique_id"] for m in mappings})
        alert["mitre_tactics"] = list({m["tactic"] for m in mappings})
    return alert


def get_technique_coverage() -> Dict[str, Any]:
    """Return the full technique map for dashboard display."""
    return {
        "techniques": TECHNIQUE_MAP,
        "tactics": ALL_TACTICS,
    }
