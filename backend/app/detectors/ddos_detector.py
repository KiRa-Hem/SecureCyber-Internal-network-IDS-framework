import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

class DoSDetector:
    def __init__(self, threshold: int = 100, window_seconds: int = 10):
        self.threshold = threshold  # requests per second
        self.window_seconds = window_seconds
        self.ip_request_counts = defaultdict(lambda: deque())
        self.ip_total_requests = defaultdict(int)
    
    def detect(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect DDoS attacks based on request rate.
        Returns alert data if an attack is detected, None otherwise.
        """
        source_ip = packet_data.get("source_ip") or packet_data.get("src_ip") or ""
        dest_ip = packet_data.get("dest_ip") or packet_data.get("dst_ip") or ""
        timestamp = datetime.now()
        
        if not source_ip:
            return None
        
        # Add current request to the deque for this IP
        self.ip_request_counts[source_ip].append(timestamp)
        
        # Remove requests older than the window
        window_start = timestamp - timedelta(seconds=self.window_seconds)
        while self.ip_request_counts[source_ip] and self.ip_request_counts[source_ip][0] < window_start:
            self.ip_request_counts[source_ip].popleft()
        
        # Count requests in the current window
        requests_in_window = len(self.ip_request_counts[source_ip])
        
        # Update total requests
        self.ip_total_requests[source_ip] += 1
        
        # Check if threshold is exceeded
        if requests_in_window >= self.threshold:
            # Calculate confidence based on how much the threshold is exceeded
            overage = requests_in_window - self.threshold
            confidence = min(95, 60 + overage * 5)
            
            return {
                "id": str(uuid.uuid4()),
                "timestamp": int(timestamp.timestamp()),
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "attacks": ["DDoS"],
                "attack_types_short": ["DDoS"],
                "confidence": confidence,
                "payload_snippet": f"High request count: {requests_in_window} in {self.window_seconds}s",
                "path": packet_data.get("path", []),
                "area_of_effect": packet_data.get("area_of_effect", {"nodes": [], "radius": 0}),
                "mitigation": {"action": "blocked", "by": "dos-detector"},
                "packets_analyzed": self.ip_total_requests[source_ip]
            }
        
        return None
    
    def get_top_attackers(self, limit: int = 5) -> list:
        """Return the top attacker IPs based on total requests."""
        sorted_ips = sorted(self.ip_total_requests.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "count": count} for ip, count in sorted_ips[:limit]]
