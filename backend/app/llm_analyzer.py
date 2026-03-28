"""
LLM-powered alert analysis via local Ollama API.

Provides async, non-blocking alert triage (TP/FP classification), payload
analysis, and incident summarization using a locally-hosted LLM (Mistral 7B).

Architecture:
    Detection pipeline -> alert generated -> LLM analyzes async -> result
    pushed back via WebSocket.  Detection is NEVER blocked by LLM latency.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ prompts

_TRIAGE_SYSTEM = (
    "You are a senior cybersecurity analyst at a SOC (Security Operations Center). "
    "Your job is to analyze IDS alerts and classify them as true positives or false positives. "
    "Be concise and precise. Respond ONLY with valid JSON."
)

_TRIAGE_TEMPLATE = """Analyze this IDS alert and classify it.

Alert Details:
- Attack Type: {attack_types}
- Source IP: {source_ip}
- Destination IP: {dest_ip}
- Protocol: {protocol}
- Confidence Score: {confidence}
- Payload Snippet: {payload}
- Detection Method: {detection_method}
- Description: {description}

Respond with this JSON structure only:
{{
  "verdict": "true_positive" or "false_positive" or "uncertain",
  "confidence": 0.0 to 1.0,
  "reasoning": "brief explanation (max 2 sentences)",
  "severity": "critical" or "high" or "medium" or "low",
  "recommended_action": "block" or "monitor" or "ignore"
}}"""

_PAYLOAD_SYSTEM = (
    "You are a cybersecurity expert specializing in payload analysis and attack pattern recognition. "
    "Analyze network payloads for malicious content. Respond ONLY with valid JSON."
)

_PAYLOAD_TEMPLATE = """Analyze this network payload for malicious content:

Payload: {payload}
Protocol: {protocol}
Source Port: {src_port}
Destination Port: {dst_port}

Respond with this JSON structure only:
{{
  "is_malicious": true or false,
  "attack_type": "type of attack or null",
  "confidence": 0.0 to 1.0,
  "indicators": ["list of suspicious indicators found"],
  "explanation": "brief analysis (max 2 sentences)"
}}"""


# ------------------------------------------------------------------ cache

class _LRUCache:
    """Simple TTL-based LRU cache for deduplicating LLM calls."""

    def __init__(self, max_size: int = 256, ttl: int = 300):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._max_size = max_size
        self._ttl = ttl

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        entry = self._store.get(key)
        if entry is None:
            return None
        if time.time() - entry["ts"] > self._ttl:
            self._store.pop(key, None)
            return None
        return entry["value"]

    def set(self, key: str, value: Dict[str, Any]) -> None:
        if len(self._store) >= self._max_size:
            oldest_key = min(self._store, key=lambda k: self._store[k]["ts"])
            self._store.pop(oldest_key, None)
        self._store[key] = {"value": value, "ts": time.time()}

    def clear(self) -> None:
        self._store.clear()

    @property
    def size(self) -> int:
        return len(self._store)


# ------------------------------------------------------------------ analyzer

class LLMAnalyzer:
    """Async Ollama-based alert analyzer with caching and rate limiting."""

    def __init__(self):
        self._base_url = str(
            getattr(settings, "LLM_BASE_URL", "http://localhost:11434")
        ).rstrip("/")
        self._model = str(getattr(settings, "LLM_MODEL", "mistral"))
        self._timeout = int(getattr(settings, "LLM_TIMEOUT_SECONDS", 30))
        self._max_concurrent = int(getattr(settings, "LLM_MAX_CONCURRENT", 3))
        self._cache = _LRUCache(
            max_size=256,
            ttl=int(getattr(settings, "LLM_CACHE_TTL_SECONDS", 300)),
        )
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        self._client: Optional[httpx.AsyncClient] = None

        # Stats
        self._total_requests = 0
        self._total_errors = 0
        self._total_cache_hits = 0
        self._avg_latency_ms = 0.0
        self._last_error: Optional[str] = None
        self._online = False

    # ----------------------------------------------------------- lifecycle

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout, connect=5.0),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ----------------------------------------------------------- health

    async def check_health(self) -> Dict[str, Any]:
        """Check if Ollama is reachable and model is loaded."""
        try:
            client = await self._ensure_client()
            resp = await client.get("/api/tags", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                model_ready = any(
                    self._model in name for name in models
                )
                self._online = model_ready
                return {
                    "online": True,
                    "model_ready": model_ready,
                    "model": self._model,
                    "available_models": models,
                }
            self._online = False
            return {"online": False, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            self._online = False
            return {"online": False, "error": str(exc)}

    @property
    def is_available(self) -> bool:
        """Quick check without HTTP — uses cached status."""
        return bool(
            getattr(settings, "LLM_ENABLED", False) and self._online
        )

    # ----------------------------------------------------------- core API

    async def analyze_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an alert as TP/FP/uncertain using the LLM.

        Returns:
            {verdict, confidence, reasoning, severity, recommended_action,
             model, latency_ms, cached}
        """
        if not getattr(settings, "LLM_ENABLED", False):
            return self._fallback_verdict(alert, reason="LLM disabled")

        # Cache check
        cache_key = self._alert_cache_key(alert)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._total_cache_hits += 1
            cached["cached"] = True
            return cached

        # Build prompt
        attack_types = alert.get("attack_types") or alert.get("attacks") or []
        prompt = _TRIAGE_TEMPLATE.format(
            attack_types=", ".join(str(a) for a in attack_types),
            source_ip=alert.get("source_ip", "unknown"),
            dest_ip=alert.get("dest_ip", "unknown"),
            protocol=alert.get("protocol", "TCP"),
            confidence=alert.get("confidence", "N/A"),
            payload=str(alert.get("payload_snippet", ""))[:200],
            detection_method=str(
                (alert.get("mitigation") or {}).get("by", "unknown")
            ),
            description=str(alert.get("description", ""))[:200],
        )

        result = await self._query(prompt, _TRIAGE_SYSTEM)
        if result is None:
            return self._fallback_verdict(alert, reason="LLM unreachable")

        result.setdefault("verdict", "uncertain")
        result.setdefault("confidence", 0.5)
        result.setdefault("reasoning", "")
        result.setdefault("severity", "medium")
        result.setdefault("recommended_action", "monitor")
        result["model"] = self._model
        result["cached"] = False

        self._cache.set(cache_key, result)
        return result

    async def analyze_payload(self, payload: str, protocol: str = "TCP",
                              src_port: int = 0, dst_port: int = 0) -> Dict[str, Any]:
        """Deep payload analysis for novel attack pattern detection."""
        if not getattr(settings, "LLM_ENABLED", False):
            return {"is_malicious": False, "error": "LLM disabled"}

        prompt = _PAYLOAD_TEMPLATE.format(
            payload=payload[:500],
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
        )

        result = await self._query(prompt, _PAYLOAD_SYSTEM)
        if result is None:
            return {"is_malicious": False, "error": "LLM unreachable"}

        result.setdefault("is_malicious", False)
        result.setdefault("confidence", 0.5)
        result["model"] = self._model
        return result

    # ----------------------------------------------------------- Ollama call

    async def _query(self, prompt: str, system: str) -> Optional[Dict[str, Any]]:
        """Send a prompt to Ollama and parse the JSON response."""
        async with self._semaphore:
            self._total_requests += 1
            start = time.time()
            try:
                client = await self._ensure_client()
                resp = await client.post(
                    "/api/generate",
                    json={
                        "model": self._model,
                        "prompt": prompt,
                        "system": system,
                        "stream": False,
                        "options": {
                            "temperature": 0.1,
                            "top_p": 0.9,
                            "num_predict": 256,
                        },
                    },
                )
                latency = (time.time() - start) * 1000
                self._avg_latency_ms = (
                    self._avg_latency_ms * 0.9 + latency * 0.1
                )
                self._online = True

                if resp.status_code != 200:
                    self._total_errors += 1
                    self._last_error = f"HTTP {resp.status_code}"
                    logger.warning("Ollama returned %d", resp.status_code)
                    return None

                raw = resp.json().get("response", "")
                return self._parse_json(raw)

            except httpx.TimeoutException:
                self._total_errors += 1
                self._last_error = "Timeout"
                self._online = False
                logger.warning("Ollama request timed out after %ds", self._timeout)
                return None
            except Exception as exc:
                self._total_errors += 1
                self._last_error = str(exc)
                self._online = False
                logger.warning("Ollama request failed: %s", exc)
                return None

    # ----------------------------------------------------------- helpers

    @staticmethod
    def _parse_json(text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from LLM response (handles markdown code fences)."""
        text = text.strip()
        # Handle ```json ... ``` blocks
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                try:
                    return json.loads(part)
                except (json.JSONDecodeError, ValueError):
                    continue
        # Direct JSON parse
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            # Try to find JSON object in text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except (json.JSONDecodeError, ValueError):
                    pass
        logger.debug("Failed to parse LLM response as JSON: %s", text[:200])
        return None

    @staticmethod
    def _alert_cache_key(alert: Dict[str, Any]) -> str:
        """Generate a cache key from alert content."""
        parts = [
            str(alert.get("attack_types") or alert.get("attacks") or []),
            str(alert.get("source_ip", "")),
            str(alert.get("dest_ip", "")),
            str(alert.get("payload_snippet", ""))[:100],
            str(alert.get("confidence", "")),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    @staticmethod
    def _fallback_verdict(alert: Dict[str, Any], reason: str = "") -> Dict[str, Any]:
        """Heuristic fallback when LLM is unavailable."""
        attack_types = set(alert.get("attack_types") or alert.get("attacks") or [])
        signature_types = {
            "SQL Injection", "Cross-Site Scripting", "Command Injection",
            "Path Traversal", "Log4Shell Exploit", "SSH Brute Force",
            "FTP Brute Force Signature", "SMB Exploitation",
            "C2 Beacon Communication", "Credential Dumping",
        }
        if attack_types & signature_types:
            verdict = "true_positive"
            confidence = 0.85
        elif attack_types <= {"Anomaly", "Drift", "XGBoost Detection"}:
            verdict = "uncertain"
            confidence = 0.4
        else:
            verdict = "uncertain"
            confidence = 0.5

        return {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": f"Heuristic fallback ({reason})",
            "severity": "medium",
            "recommended_action": "monitor",
            "model": "heuristic",
            "cached": False,
        }

    # ----------------------------------------------------------- status

    def get_status(self) -> Dict[str, Any]:
        """Return LLM analyzer status for the API."""
        return {
            "enabled": bool(getattr(settings, "LLM_ENABLED", False)),
            "online": self._online,
            "model": self._model,
            "base_url": self._base_url,
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "cache_hits": self._total_cache_hits,
            "cache_size": self._cache.size,
            "avg_latency_ms": round(self._avg_latency_ms, 1),
            "last_error": self._last_error,
            "max_concurrent": self._max_concurrent,
        }


# Global singleton
llm_analyzer = LLMAnalyzer()

logger.info(
    "LLM Analyzer module loaded (model=%s, enabled=%s)",
    llm_analyzer._model,
    getattr(settings, "LLM_ENABLED", False),
)
