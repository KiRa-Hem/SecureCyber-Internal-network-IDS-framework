"""
Feature extraction helpers to align live packet metadata with the KDD-style
feature space used by the ML detectors.

The extractor keeps short-lived connection statistics so count/rate based fields
closely resemble the semantics expected by the RandomForest and DNN models.
"""

from __future__ import annotations

import re
import time
from collections import Counter, deque
from typing import Any, Deque, Dict, List, Mapping, Tuple


class FeatureExtractor:
    """Convert packet dictionaries into 41-field feature vectors."""

    FEATURE_NAMES: Tuple[str, ...] = (
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "hot",
        "num_failed_logins",
        "logged_in",
        "num_compromised",
        "root_shell",
        "su_attempted",
        "num_root",
        "num_file_creations",
        "num_shells",
        "num_access_files",
        "num_outbound_cmds",
        "is_host_login",
        "is_guest_login",
        "count",
        "srv_count",
        "serror_rate",
        "srv_serror_rate",
        "rerror_rate",
        "srv_rerror_rate",
        "same_srv_rate",
        "diff_srv_rate",
        "srv_diff_host_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
    )

    SERVICE_PORT_MAP: Mapping[int, str] = {
        20: "ftp_data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain_u",
        69: "tftp_u",
        80: "http",
        110: "pop_3",
        111: "rpc",
        135: "netbios_dgm",
        137: "netbios_ns",
        138: "netbios_ssn",
        143: "imap4",
        443: "https",
        445: "microsoft_ds",
        993: "imap4",
        995: "pop_3",
        1080: "socks",
    }

    LOGIN_FAILURE_TOKENS = ("denied", "failed", "invalid", "unauthorized", "error")
    LOGIN_SUCCESS_TOKENS = ("200 ok", "success", "authenticated")
    FILE_TOKENS = ("../", "..\\", "/etc/passwd", "c:\\windows")
    COMMAND_TOKENS = ("cmd", "bash", "powershell", "wget", "curl", "nc ", "perl")
    SQL_TOKENS = (
        "select ",
        "insert ",
        "delete ",
        "drop ",
        "union ",
        "' or ",
        "\" or ",
        " or 1=1",
    )

    FLAG_MAP: Mapping[str, str] = {
        "S": "S0",
        "SA": "SF",
        "FA": "SF",
        "R": "RSTO",
        "RA": "RSTOS0",
        "PA": "SF",
        "F": "SH",
    }

    def __init__(self, window_seconds: int = 120):
        self.window_seconds = window_seconds
        self.history: Deque[Dict[str, Any]] = deque()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _normalize_payload(packet: Mapping[str, Any]) -> str:
        payload = packet.get("payload") or packet.get("payload_snippet") or ""
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="ignore")
        return str(payload).lower()

    @staticmethod
    def _protocol(packet: Mapping[str, Any]) -> str:
        proto = (
            packet.get("protocol_name")
            or packet.get("protocol")
            or packet.get("layer3_protocol")
            or "tcp"
        )
        proto = str(proto).lower()
        if proto not in {"tcp", "udp", "icmp"}:
            return "tcp"
        return proto

    def _service(self, packet: Mapping[str, Any]) -> str:
        port = (
            packet.get("dst_port")
            or packet.get("dest_port")
            or packet.get("destination_port")
        )
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        if isinstance(port, int):
            return self.SERVICE_PORT_MAP.get(port, "other")
        return "other"

    @staticmethod
    def _flag(packet: Mapping[str, Any]) -> str:
        flags = packet.get("flags") or packet.get("packet_flags") or ""
        if isinstance(flags, int):
            flags = format(flags, "b")
        norm = "".join(sorted(str(flags).replace(" ", "").upper()))
        if not norm:
            return "OTH"
        for key, value in FeatureExtractor.FLAG_MAP.items():
            if all(ch in norm for ch in key):
                return value
        if "R" in norm:
            return "RSTO"
        if "S" in norm:
            return "S0"
        if "F" in norm:
            return "SH"
        return "OTH"

    @staticmethod
    def _payload_indicators(payload: str) -> Dict[str, int]:
        sql_hits = sum(1 for token in FeatureExtractor.SQL_TOKENS if token in payload)
        cmd_hits = sum(1 for token in FeatureExtractor.COMMAND_TOKENS if token in payload)
        file_hits = sum(1 for token in FeatureExtractor.FILE_TOKENS if token in payload)
        login_fail = any(token in payload for token in FeatureExtractor.LOGIN_FAILURE_TOKENS)
        login_success = any(token in payload for token in FeatureExtractor.LOGIN_SUCCESS_TOKENS)

        suspicious_score = sql_hits + cmd_hits + file_hits
        return {
            "hot": suspicious_score,
            "num_access_files": file_hits,
            "num_outbound_cmds": cmd_hits,
            "num_failed_logins": int(login_fail),
            "logged_in": int(login_success and not login_fail),
            "num_compromised": 1 if suspicious_score >= 2 else 0,
            "num_shells": int("shell" in payload or "/bin/sh" in payload),
            "num_root": int("root" in payload),
            "num_file_creations": file_hits,
            "is_host_login": int("host:" in payload),
            "is_guest_login": int("guest" in payload),
        }

    def _record_connection(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        service: str,
        src_port: int | None,
        dst_port: int | None,
        is_error: bool,
        is_reset: bool,
    ) -> None:
        record = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": service,
            "src_port": src_port,
            "dst_port": dst_port,
            "is_error": is_error,
            "is_reset": is_reset,
        }
        self.history.append(record)
        cutoff = timestamp - self.window_seconds
        while self.history and self.history[0]["timestamp"] < cutoff:
            self.history.popleft()

    # ------------------------------------------------------------- math helpers
    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return float(numerator) / float(denominator) if denominator else 0.0

    # ---------------------------------------------------------------- interface
    def extract(self, packet: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a dict with all 41 features populated."""
        timestamp = float(packet.get("timestamp") or time.time())
        src_ip = str(packet.get("src_ip") or packet.get("source_ip") or "0.0.0.0")
        dst_ip = str(packet.get("dst_ip") or packet.get("dest_ip") or "0.0.0.0")
        src_port = packet.get("src_port") or packet.get("source_port")
        dst_port = packet.get("dst_port") or packet.get("dest_port")
        service = self._service(packet)
        protocol_type = self._protocol(packet)
        flag = self._flag(packet)
        payload = self._normalize_payload(packet)

        src_bytes = int(packet.get("size") or packet.get("src_bytes") or len(payload))
        dst_bytes = int(packet.get("dst_bytes") or max(src_bytes // 2, 1))
        land = int(src_ip == dst_ip)
        wrong_fragment = int(packet.get("wrong_fragment") or 0)
        urgent = int(packet.get("urgent") or 0)
        duration = float(packet.get("duration") or packet.get("flow_duration") or 0.0)

        indicators = self._payload_indicators(payload)
        hot = indicators["hot"]
        num_failed_logins = indicators["num_failed_logins"]
        logged_in = indicators["logged_in"]
        num_compromised = indicators["num_compromised"]
        num_root = indicators["num_root"]
        num_shells = indicators["num_shells"]
        num_file_creations = indicators["num_file_creations"]
        num_access_files = indicators["num_access_files"]
        num_outbound_cmds = indicators["num_outbound_cmds"]
        is_host_login = indicators["is_host_login"]
        is_guest_login = indicators["is_guest_login"]

        # Heuristic markers
        is_error = hot >= 1 or "error" in payload or "alert" in payload
        is_reset = "r" in (packet.get("flags") or "").lower() or "reset" in payload

        self._record_connection(
            timestamp,
            src_ip,
            dst_ip,
            service,
            src_port if isinstance(src_port, int) else None,
            dst_port if isinstance(dst_port, int) else None,
            is_error,
            is_reset,
        )

        recent = list(self.history)
        src_records = [r for r in recent if r["src_ip"] == src_ip]
        dst_records = [r for r in recent if r["dst_ip"] == dst_ip]
        service_records = [r for r in src_records if r["service"] == service]
        dst_service_records = [r for r in dst_records if r["service"] == service]

        count = len(src_records)
        srv_count = len(service_records)
        same_srv_rate = self._ratio(srv_count, count)
        diff_srv_rate = max(0.0, 1.0 - same_srv_rate)
        srv_diff_host_rate = self._ratio(
            len({r["dst_ip"] for r in service_records}), srv_count or 1
        )

        dst_host_count = len(dst_records)
        dst_host_srv_count = len(dst_service_records)
        dst_host_same_srv_rate = self._ratio(dst_host_srv_count, dst_host_count)
        dst_host_diff_srv_rate = max(0.0, 1.0 - dst_host_same_srv_rate)

        same_src_port_records = [
            r for r in dst_records if src_port and r["src_port"] == src_port
        ]
        dst_host_same_src_port_rate = self._ratio(
            len(same_src_port_records), dst_host_count
        )

        unique_src_for_dst_service = len({r["src_ip"] for r in dst_service_records})
        dst_host_srv_diff_host_rate = self._ratio(
            unique_src_for_dst_service, dst_host_srv_count or 1
        )

        serror_rate = self._ratio(
            sum(r["is_error"] for r in src_records), len(src_records)
        )
        srv_serror_rate = self._ratio(
            sum(r["is_error"] for r in service_records), len(service_records)
        )
        rerror_rate = self._ratio(sum(r["is_reset"] for r in src_records), len(src_records))
        srv_rerror_rate = self._ratio(
            sum(r["is_reset"] for r in service_records), len(service_records)
        )

        dst_host_serror_rate = self._ratio(
            sum(r["is_error"] for r in dst_records), len(dst_records)
        )
        dst_host_srv_serror_rate = self._ratio(
            sum(r["is_error"] for r in dst_service_records), len(dst_service_records)
        )
        dst_host_rerror_rate = self._ratio(
            sum(r["is_reset"] for r in dst_records), len(dst_records)
        )
        dst_host_srv_rerror_rate = self._ratio(
            sum(r["is_reset"] for r in dst_service_records), len(dst_service_records)
        )

        features: Dict[str, Any] = {
            "duration": duration,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "land": land,
            "wrong_fragment": wrong_fragment,
            "urgent": urgent,
            "hot": hot,
            "num_failed_logins": num_failed_logins,
            "logged_in": logged_in,
            "num_compromised": num_compromised,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": num_root,
            "num_file_creations": num_file_creations,
            "num_shells": num_shells,
            "num_access_files": num_access_files,
            "num_outbound_cmds": num_outbound_cmds,
            "is_host_login": is_host_login,
            "is_guest_login": is_guest_login,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate,
            "srv_rerror_rate": srv_rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
            "dst_host_serror_rate": dst_host_serror_rate,
            "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
            "dst_host_rerror_rate": dst_host_rerror_rate,
            "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
        }

        # Ensure every expected feature is present (defaults to 0)
        for name in self.FEATURE_NAMES:
            features.setdefault(name, 0)

        return features


# Shared instance for simple imports
feature_extractor = FeatureExtractor()

