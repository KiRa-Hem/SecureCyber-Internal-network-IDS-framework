import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from app.config import settings

class EventCorrelator:
    def __init__(self, window_seconds: int = None):
        self.window_seconds = window_seconds or settings.correlation_window_seconds
        self.events_by_source = defaultdict(list)
        self.events_by_target = defaultdict(list)
        self.correlated_events = []
    
    def add_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Add an event and check for correlations.
        Returns a correlated event if found, None otherwise.
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
        
        # Check for correlations
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
    
    def _check_correlations(self, event: Dict[str, Any], source_ip: str, target_ip: str) -> Optional[Dict[str, Any]]:
        """Check for correlations with existing events."""
        correlated_events = []
        
        # Check for events from the same source
        for ts, existing_event in self.events_by_source.get(source_ip, []):
            if existing_event["id"] != event["id"]:  # Don't correlate with self
                correlated_events.append(existing_event)
        
        # Check for events against the same target
        for ts, existing_event in self.events_by_target.get(target_ip, []):
            if existing_event["id"] != event["id"]:  # Don't correlate with self
                correlated_events.append(existing_event)
        
        # If we have correlated events, create a correlated alert
        if correlated_events:
            # Extract all unique attack types
            attack_types = set(event.get("attacks", []))
            for existing_event in correlated_events:
                attack_types.update(existing_event.get("attacks", []))
            
            # Calculate confidence boost based on number of correlated events
            base_confidence = event.get("confidence", 50)
            confidence_boost = min(20, len(correlated_events) * 5)
            confidence = min(99, base_confidence + confidence_boost)
            
            # Create correlated event
            correlated_event = {
                "id": f"corr-{int(time.time())}",
                "timestamp": int(time.time()),
                "source_ip": source_ip,
                "dest_ip": target_ip,
                "attacks": list(attack_types),
                "attack_types_short": [attack.split()[0] for attack in attack_types],
                "confidence": confidence,
                "payload_snippet": f"Correlated event: {len(correlated_events) + 1} related events",
                "path": event.get("path", []),
                "area_of_effect": event.get("area_of_effect", {"nodes": [], "radius": 0}),
                "mitigation": {
                    "action": "blocked" if confidence > 80 else "flagged",
                    "by": "correlation-engine"
                },
                "packets_analyzed": sum(e.get("packets_analyzed", 0) for e in correlated_events) + event.get("packets_analyzed", 0),
                "correlated_events": [e["id"] for e in correlated_events] + [event["id"]]
            }
            
            return correlated_event
        
        return None

# Global correlator instance
correlator = EventCorrelator()