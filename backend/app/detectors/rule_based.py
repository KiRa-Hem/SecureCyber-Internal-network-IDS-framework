import re
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

class RuleBasedDetector:
    def __init__(self):
        # SQL Injection patterns
        self.sqli_patterns = [
            r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b",
            r"(?i)\b(OR|AND)\s+\d+\s*=\s*\d+",
            r"(?i)\b(WAITFOR\s+DELAY|SLEEP\()\b",
            r"(?i)\b(EXEC|EXECUTE|EXECSP)\b",
            r"(?i)\b(XP_|SP_)\w+\b",
            r"(?i)([';]|--|\/\*|\*\/)"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(?i)<script[^>]*>.*?<\/script>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            r"(?i)<iframe[^>]*>",
            r"(?i)<object[^>]*>",
            r"(?i)<embed[^>]*>",
            r"(?i)expression\s*\("
        ]
        
        # Command Injection patterns
        self.cmd_injection_patterns = [
            r"(?i)[;&|]\s*\b(\w+)?\s*(\$\w+|\(.+\)|`.*`)",
            r"(?i)\b(nc|netcat|nmap|telnet|curl|wget)\b",
            r"(?i)\b(\/usr\/bin\/|\/bin\/)\w+\b",
            r"(?i)\|(\s*\w+\s*)+\|",
            r"(?i);(\s*\w+\s*)+;",
            r"(?i)&(\s*\w+\s*)+&"
        ]
        
        # Log4j patterns
        self.log4j_patterns = [
            r"(?i)\$\{jndi:(ldap|rmi|dns):[^}]+\}",
            r"(?i)\$\{env:[^}]+\}",
            r"(?i)\$\{sys:[^}]+\}",
            r"(?i)\$\{java:[^}]+\}"
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"(?i)%2e%2e%2f",
            r"(?i)%2e%2e\\",
            r"(?i)..\/..\/",
            r"(?i)etc\/passwd",
            r"(?i)windows\/system32"
        ]
    
    def detect(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect attacks based on packet payload using rule-based patterns.
        Returns alert data if an attack is detected, None otherwise.
        """
        payload = packet_data.get("payload", "")
        source_ip = packet_data.get("source_ip", "")
        dest_ip = packet_data.get("dest_ip", "")
        
        if not payload:
            return None
        
        detected_attacks = []
        confidence = 0
        
        # Check for SQL Injection
        for pattern in self.sqli_patterns:
            if re.search(pattern, payload):
                detected_attacks.append("SQL Injection")
                confidence = max(confidence, 85)
        
        # Check for XSS
        for pattern in self.xss_patterns:
            if re.search(pattern, payload):
                detected_attacks.append("XSS")
                confidence = max(confidence, 80)
        
        # Check for Command Injection
        for pattern in self.cmd_injection_patterns:
            if re.search(pattern, payload):
                detected_attacks.append("Command Injection")
                confidence = max(confidence, 90)
        
        # Check for Log4j
        for pattern in self.log4j_patterns:
            if re.search(pattern, payload):
                detected_attacks.append("Log4j Exploit")
                confidence = max(confidence, 95)
        
        # Check for Path Traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, payload):
                detected_attacks.append("Path Traversal")
                confidence = max(confidence, 85)
        
        # If any attacks were detected, create an alert
        if detected_attacks:
            # Truncate payload snippet for privacy
            payload_snippet = payload[:512] if len(payload) > 512 else payload
            
            return {
                "id": str(uuid.uuid4()),
                "timestamp": int(datetime.now().timestamp()),
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "attacks": detected_attacks,
                "attack_types_short": [attack.split()[0] for attack in detected_attacks],
                "confidence": confidence,
                "payload_snippet": payload_snippet,
                "path": packet_data.get("path", []),
                "area_of_effect": packet_data.get("area_of_effect", {"nodes": [], "radius": 0}),
                "mitigation": {"action": "flagged", "by": "rule-based-detector"},
                "packets_analyzed": 1
            }
        
        return None