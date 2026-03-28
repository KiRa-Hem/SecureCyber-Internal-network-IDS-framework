import time
import logging
from typing import Dict, List, Any
from app.db import db
from app.config import settings

logger = logging.getLogger(__name__)


class MitigationEngine:
    def __init__(self):
        self.blocklist = {}  # In-memory blocklist for quick access
        self.isolated_nodes = {}  # In-memory isolated nodes for quick access
    
    def block_ip(self, ip: str, reason: str, ttl_seconds: int = None) -> bool:
        """
        Block an IP address.
        Returns True if successful, False otherwise.
        """
        if ttl_seconds is None:
            ttl_seconds = settings.blocklist_ttl_seconds
        
        # Add to in-memory blocklist
        self.blocklist[ip] = {
            "timestamp": int(time.time()),
            "reason": reason,
            "expires_at": int(time.time()) + ttl_seconds
        }
        
        # Add to database
        db.add_to_blocklist(ip, reason, ttl_seconds)
        
        logger.info("IP %s blocked: %s", ip, reason)
        return True
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address.
        Returns True if successful, False otherwise.
        """
        if ip in self.blocklist:
            del self.blocklist[ip]
        
        # Remove from database
        db.remove_from_blocklist(ip)
        
        logger.info("IP %s unblocked", ip)
        return True
    
    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if an IP is blocked.
        Returns True if blocked, False otherwise.
        """
        # Check in-memory blocklist first
        if ip in self.blocklist:
            # Check if expired
            if self.blocklist[ip]["expires_at"] > int(time.time()):
                return True
            else:
                # Remove expired entry
                del self.blocklist[ip]
        
        # Check database
        return db.is_blocked(ip)
    
    def isolate_node(self, node_id: str, reason: str, ttl_seconds: int = None) -> bool:
        """
        Isolate a network node.
        Returns True if successful, False otherwise.
        """
        if ttl_seconds is None:
            ttl_seconds = settings.blocklist_ttl_seconds
        
        # Add to in-memory isolated nodes
        self.isolated_nodes[node_id] = {
            "timestamp": int(time.time()),
            "reason": reason,
            "expires_at": int(time.time()) + ttl_seconds
        }
        
        # Add to database
        db.isolate_node(node_id, reason, ttl_seconds)
        
        logger.info("Node %s isolated: %s", node_id, reason)
        return True
    
    def remove_isolation(self, node_id: str) -> bool:
        """
        Remove isolation from a network node.
        Returns True if successful, False otherwise.
        """
        if node_id in self.isolated_nodes:
            del self.isolated_nodes[node_id]
        
        # Remove from database
        db.remove_isolation(node_id)
        
        logger.info("Node %s isolation removed", node_id)
        return True
    
    def is_node_isolated(self, node_id: str) -> bool:
        """
        Check if a node is isolated.
        Returns True if isolated, False otherwise.
        """
        # Check in-memory isolated nodes first
        if node_id in self.isolated_nodes:
            # Check if expired
            if self.isolated_nodes[node_id]["expires_at"] > int(time.time()):
                return True
            else:
                # Remove expired entry
                del self.isolated_nodes[node_id]
        
        # Check database
        return db.is_isolated(node_id)
    
    def get_blocklist(self) -> List[Dict[str, Any]]:
        """Get the current blocklist."""
        # Refresh from database
        db_blocklist = db.get_blocklist()
        
        # Update in-memory blocklist
        self.blocklist = {item["ip"]: item for item in db_blocklist}
        
        return db_blocklist
    
    def get_isolated_nodes(self) -> List[Dict[str, Any]]:
        """Get the currently isolated nodes."""
        # Refresh from database
        db_isolated = db.get_isolated_nodes()
        
        # Update in-memory isolated nodes
        self.isolated_nodes = {item["node_id"]: item for item in db_isolated}
        
        return db_isolated
    
    def apply_mitigation(self, alert_data: Dict[str, Any]) -> bool:
        """
        Apply mitigation based on alert data.
        Returns True if mitigation was applied, False otherwise.
        """
        action = alert_data.get("mitigation", {}).get("action", "")
        source_ip = alert_data.get("source_ip", "")
        
        if action == "blocked" and source_ip:
            return self.block_ip(source_ip, "Automatic mitigation based on alert")
        
        return False

# Global mitigation engine instance
mitigation = MitigationEngine()