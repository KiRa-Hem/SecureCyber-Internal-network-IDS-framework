import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import websockets


ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
ENV_FILE = BACKEND_DIR / ".env"
PORT = 8010


def parse_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def http_get(url: str, token: str | None = None) -> tuple[int, bytes]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url=url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.status, response.read()


def http_post_json(url: str, payload: dict, token: str) -> tuple[int, bytes]:
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(url=url, method="POST", headers=headers, data=data)
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.status, response.read()


async def ws_ping(token: str) -> None:
    uri = f"ws://127.0.0.1:{PORT}/ws?token={token}"
    async with websockets.connect(uri, open_timeout=5) as ws:
        await ws.send("ping")
        await asyncio.sleep(0.2)


def main() -> int:
    if not ENV_FILE.exists():
        print("SMOKE_FAIL|missing backend/.env")
        return 1

    env_values = parse_env(ENV_FILE)
    api_token = env_values.get("API_TOKEN", "")
    admin_token = env_values.get("ADMIN_TOKEN", "")
    if not api_token or not admin_token:
        print("SMOKE_FAIL|missing API_TOKEN or ADMIN_TOKEN in backend/.env")
        return 1

    child_env = os.environ.copy()
    child_env["ENABLE_PACKET_CAPTURE"] = "false"
    child_env["ENABLE_SIMULATION"] = "true"
    child_env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=str(BACKEND_DIR),
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        healthy = False
        for _ in range(60):
            time.sleep(0.5)
            try:
                status, body = http_get(f"http://127.0.0.1:{PORT}/health")
                if status == 200 and json.loads(body.decode("utf-8")).get("status") == "healthy":
                    healthy = True
                    break
            except Exception:
                continue
        if not healthy:
            print("SMOKE_FAIL|backend_not_healthy")
            return 1

        root_status, _ = http_get(f"http://127.0.0.1:{PORT}/")
        stats_status, stats_body = http_get(f"http://127.0.0.1:{PORT}/api/stats", token=api_token)
        alerts_status, alerts_body = http_get(
            f"http://127.0.0.1:{PORT}/api/alerts?limit=5&offset=0", token=api_token
        )
        metrics_status, metrics_body = http_get(f"http://127.0.0.1:{PORT}/metrics", token=api_token)
        sim_status, sim_body = http_post_json(
            f"http://127.0.0.1:{PORT}/api/simulate-attack",
            {
                "attack_type": "SQL Injection",
                "source_ip": "198.51.100.10",
                "target_ip": "10.0.0.5",
                "payload": "GET /search?q=' OR '1'='1",
            },
            token=admin_token,
        )
        asyncio.run(ws_ping(api_token))

        health_status, health_body = http_get(f"http://127.0.0.1:{PORT}/health")
        health = json.loads(health_body.decode("utf-8"))
        stats = json.loads(stats_body.decode("utf-8"))
        alerts = json.loads(alerts_body.decode("utf-8"))
        sim = json.loads(sim_body.decode("utf-8"))

        if root_status != 200:
            raise RuntimeError("root_status_not_200")
        if stats_status != 200 or "packets_analyzed" not in stats:
            raise RuntimeError("stats_invalid")
        if alerts_status != 200 or "alerts" not in alerts:
            raise RuntimeError("alerts_invalid")
        if metrics_status != 200 or b"ids_packets_processed_total" not in metrics_body:
            raise RuntimeError("metrics_invalid")
        if sim_status != 200 or sim.get("status") != "success":
            raise RuntimeError("simulate_invalid")
        if health_status != 200:
            raise RuntimeError("health_invalid")

        print(
            "SMOKE_OK|detectors="
            + ",".join(health.get("detectors", []))
            + f"|root={root_status}|stats={stats_status}|alerts={alerts_status}|metrics={metrics_status}|simulate={sim_status}|ws=ok"
        )
        return 0
    except urllib.error.HTTPError as exc:
        print(f"SMOKE_FAIL|http_error|status={exc.code}|url={exc.url}")
        return 1
    except Exception as exc:
        print(f"SMOKE_FAIL|{type(exc).__name__}|{exc}")
        return 1
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        # Surface the tail of server logs for debugging context.
        if proc.stdout:
            tail = "".join(proc.stdout.readlines()[-30:])
            if tail.strip():
                print("SERVER_LOG_TAIL_BEGIN")
                print(tail.rstrip())
                print("SERVER_LOG_TAIL_END")


if __name__ == "__main__":
    raise SystemExit(main())
