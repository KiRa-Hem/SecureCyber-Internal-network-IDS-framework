"""
Feature extraction for live packet metadata.

Supports:
- CIC flow-level features (legacy, 78 features)
- CICIDS 2018 packet-compatible features (17 features)
"""

from __future__ import annotations

import statistics
import time
from collections import Counter
from typing import Any, Dict, Mapping, Tuple

from app.config import settings
from app.model_metadata import load_model_metadata


def _safe_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "std": 0.0, "var": 0.0}
    if len(values) == 1:
        value = float(values[0])
        return {"min": value, "max": value, "mean": value, "std": 0.0, "var": 0.0}
    mean_val = statistics.mean(values)
    std_val = statistics.pstdev(values)
    return {
        "min": float(min(values)),
        "max": float(max(values)),
        "mean": float(mean_val),
        "std": float(std_val),
        "var": float(std_val ** 2),
    }


class CICFlowFeatureExtractor:
    FEATURE_NAMES: Tuple[str, ...] = (
        "dst_port",
        "protocol",
        "flow_duration",
        "tot_fwd_pkts",
        "tot_bwd_pkts",
        "totlen_fwd_pkts",
        "totlen_bwd_pkts",
        "fwd_pkt_len_max",
        "fwd_pkt_len_min",
        "fwd_pkt_len_mean",
        "fwd_pkt_len_std",
        "bwd_pkt_len_max",
        "bwd_pkt_len_min",
        "bwd_pkt_len_mean",
        "bwd_pkt_len_std",
        "flow_byts_s",
        "flow_pkts_s",
        "flow_iat_mean",
        "flow_iat_std",
        "flow_iat_max",
        "flow_iat_min",
        "fwd_iat_tot",
        "fwd_iat_mean",
        "fwd_iat_std",
        "fwd_iat_max",
        "fwd_iat_min",
        "bwd_iat_tot",
        "bwd_iat_mean",
        "bwd_iat_std",
        "bwd_iat_max",
        "bwd_iat_min",
        "fwd_psh_flags",
        "bwd_psh_flags",
        "fwd_urg_flags",
        "bwd_urg_flags",
        "fwd_header_len",
        "bwd_header_len",
        "fwd_pkts_s",
        "bwd_pkts_s",
        "pkt_len_min",
        "pkt_len_max",
        "pkt_len_mean",
        "pkt_len_std",
        "pkt_len_var",
        "fin_flag_cnt",
        "syn_flag_cnt",
        "rst_flag_cnt",
        "psh_flag_cnt",
        "ack_flag_cnt",
        "urg_flag_cnt",
        "cwe_flag_count",
        "ece_flag_cnt",
        "down_up_ratio",
        "pkt_size_avg",
        "fwd_seg_size_avg",
        "bwd_seg_size_avg",
        "fwd_byts_b_avg",
        "fwd_pkts_b_avg",
        "fwd_blk_rate_avg",
        "bwd_byts_b_avg",
        "bwd_pkts_b_avg",
        "bwd_blk_rate_avg",
        "subflow_fwd_pkts",
        "subflow_fwd_byts",
        "subflow_bwd_pkts",
        "subflow_bwd_byts",
        "init_fwd_win_byts",
        "init_bwd_win_byts",
        "fwd_act_data_pkts",
        "fwd_seg_size_min",
        "active_mean",
        "active_std",
        "active_max",
        "active_min",
        "idle_mean",
        "idle_std",
        "idle_max",
        "idle_min",
    )

    PROTOCOL_MAP: Mapping[str, int] = {"tcp": 6, "udp": 17, "icmp": 1}

    def __init__(
        self,
        flow_timeout: int = 120,
        idle_threshold: float = 1.0,
        min_bulk_packets: int = 4,
    ):
        self.flow_timeout = flow_timeout
        self.idle_threshold = idle_threshold
        self.min_bulk_packets = min_bulk_packets
        self.flows: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    @staticmethod
    def _coerce_int(value: Any, default: int = 0) -> int:
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return default

    @classmethod
    def _protocol_number(cls, value: Any) -> int:
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            text = value.strip().lower()
            if text in cls.PROTOCOL_MAP:
                return cls.PROTOCOL_MAP[text]
            if text.isdigit():
                return int(text)
        return 0

    def _flow_key(self, packet: Mapping[str, Any]) -> Tuple[Any, ...]:
        src_ip = packet.get("src_ip") or packet.get("source_ip")
        dst_ip = packet.get("dst_ip") or packet.get("dest_ip")
        src_port = packet.get("src_port") or packet.get("source_port")
        dst_port = (
            packet.get("dst_port")
            or packet.get("dest_port")
            or packet.get("destination_port")
        )
        proto = packet.get("protocol") or packet.get("protocol_name") or "tcp"
        return (
            src_ip,
            dst_ip,
            self._coerce_int(src_port),
            self._coerce_int(dst_port),
            self._protocol_number(proto),
        )

    def _init_flow(self, key: Tuple[Any, ...], now: float) -> Dict[str, Any]:
        return {
            "key": key,
            "start_time": now,
            "last_seen": now,
            "forward": {
                "count": 0,
                "bytes": 0,
                "packet_sizes": [],
                "iat": [],
                "last_seen": None,
                "psh": 0,
                "urg": 0,
                "header_len": 0,
                "init_win": None,
                "act_data_pkts": 0,
            },
            "backward": {
                "count": 0,
                "bytes": 0,
                "packet_sizes": [],
                "iat": [],
                "last_seen": None,
                "psh": 0,
                "urg": 0,
                "header_len": 0,
                "init_win": None,
                "act_data_pkts": 0,
            },
            "packet_sizes": [],
            "flow_iat": [],
            "flags": Counter(),
            "active_start": now,
            "active_durations": [],
            "idle_durations": [],
            "bulk": {
                "fwd": {
                    "state": {
                        "active": False,
                        "start_time": None,
                        "last_time": None,
                        "packet_count": 0,
                        "size": 0,
                    },
                    "stats": {
                        "count": 0,
                        "packet_count": 0,
                        "size": 0,
                        "duration": 0.0,
                    },
                },
                "bwd": {
                    "state": {
                        "active": False,
                        "start_time": None,
                        "last_time": None,
                        "packet_count": 0,
                        "size": 0,
                    },
                    "stats": {
                        "count": 0,
                        "packet_count": 0,
                        "size": 0,
                        "duration": 0.0,
                    },
                },
            },
        }

    def _prune_flows(self, now: float) -> None:
        expired = [
            key
            for key, flow in self.flows.items()
            if now - flow["last_seen"] > self.flow_timeout
        ]
        for key in expired:
            self.flows.pop(key, None)

    def _update_flow(self, flow: Dict[str, Any], direction: str, packet: Mapping[str, Any], now: float):
        size = self._coerce_int(packet.get("size") or packet.get("length") or 0)
        payload_len = self._coerce_int(packet.get("payload_len") or 0)
        header_len = self._coerce_int(packet.get("header_len") or 0)
        flags = str(packet.get("flags") or "").upper()
        window = packet.get("tcp_window")

        if flow["last_seen"] is not None:
            iat = now - flow["last_seen"]
            if iat > 0:
                flow["flow_iat"].append(iat)
            if iat > self.idle_threshold:
                active_duration = flow["last_seen"] - flow["active_start"]
                if active_duration > 0:
                    flow["active_durations"].append(active_duration)
                flow["idle_durations"].append(iat)
                flow["active_start"] = now

        flow["last_seen"] = now
        flow["packet_sizes"].append(size)
        flow["flags"].update(list(flags))

        bucket = flow["forward"] if direction == "fwd" else flow["backward"]
        bucket["count"] += 1
        bucket["bytes"] += size
        bucket["packet_sizes"].append(size)
        bucket["header_len"] += header_len
        if payload_len > 0:
            bucket["act_data_pkts"] += 1

        if bucket["last_seen"] is not None:
            iat = now - bucket["last_seen"]
            if iat > 0:
                bucket["iat"].append(iat)
        bucket["last_seen"] = now

        if "P" in flags:
            bucket["psh"] += 1
        if "U" in flags:
            bucket["urg"] += 1
        if bucket["init_win"] is None and window is not None:
            bucket["init_win"] = self._coerce_int(window, default=0)

        self._update_bulk(flow, direction, payload_len, now)

    def _finalize_bulk(self, state: Dict[str, Any], stats: Dict[str, Any]):
        if not state["active"]:
            return
        if state["packet_count"] >= self.min_bulk_packets:
            stats["count"] += 1
            stats["packet_count"] += state["packet_count"]
            stats["size"] += state["size"]
            if state["start_time"] is not None and state["last_time"] is not None:
                duration = max(state["last_time"] - state["start_time"], 0.0)
                stats["duration"] += duration
        state["active"] = False
        state["start_time"] = None
        state["last_time"] = None
        state["packet_count"] = 0
        state["size"] = 0

    def _update_bulk(self, flow: Dict[str, Any], direction: str, payload_len: int, now: float):
        bulk_state = flow["bulk"][direction]["state"]
        bulk_stats = flow["bulk"][direction]["stats"]
        if payload_len <= 0:
            if bulk_state["active"] and bulk_state["last_time"] is not None:
                if now - bulk_state["last_time"] > self.idle_threshold:
                    self._finalize_bulk(bulk_state, bulk_stats)
            return

        if not bulk_state["active"]:
            bulk_state["active"] = True
            bulk_state["start_time"] = now
            bulk_state["last_time"] = now
            bulk_state["packet_count"] = 1
            bulk_state["size"] = payload_len
            return

        if bulk_state["last_time"] is not None and (now - bulk_state["last_time"]) <= self.idle_threshold:
            bulk_state["packet_count"] += 1
            bulk_state["size"] += payload_len
            bulk_state["last_time"] = now
            return

        self._finalize_bulk(bulk_state, bulk_stats)
        bulk_state["active"] = True
        bulk_state["start_time"] = now
        bulk_state["last_time"] = now
        bulk_state["packet_count"] = 1
        bulk_state["size"] = payload_len

    def _bulk_totals(self, flow: Dict[str, Any], direction: str) -> Dict[str, float]:
        bulk_state = flow["bulk"][direction]["state"]
        bulk_stats = flow["bulk"][direction]["stats"]
        total_count = bulk_stats["count"]
        total_packets = bulk_stats["packet_count"]
        total_size = bulk_stats["size"]
        total_duration = bulk_stats["duration"]

        if bulk_state["active"] and bulk_state["packet_count"] >= self.min_bulk_packets:
            total_count += 1
            total_packets += bulk_state["packet_count"]
            total_size += bulk_state["size"]
            if bulk_state["start_time"] is not None and bulk_state["last_time"] is not None:
                total_duration += max(bulk_state["last_time"] - bulk_state["start_time"], 0.0)

        return {
            "count": total_count,
            "packet_count": total_packets,
            "size": total_size,
            "duration": total_duration,
        }

    def extract(self, packet: Mapping[str, Any]) -> Dict[str, Any]:
        now = float(packet.get("timestamp") or time.time())
        key = self._flow_key(packet)
        rev_key = (key[1], key[0], key[3], key[2], key[4])
        direction = "fwd"
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows.get(rev_key)
            if flow is not None:
                direction = "bwd"
        if flow is None:
            flow = self._init_flow(key, now)
            self.flows[key] = flow
            direction = "fwd"

        self._update_flow(flow, direction, packet, now)
        self._prune_flows(now)

        duration = max(now - flow["start_time"], 1e-6)
        duration_seconds = duration
        flow_duration = int(duration_seconds * 1_000_000)

        fwd = flow["forward"]
        bwd = flow["backward"]

        fwd_stats = _safe_stats(fwd["packet_sizes"])
        bwd_stats = _safe_stats(bwd["packet_sizes"])
        pkt_stats = _safe_stats(flow["packet_sizes"])
        flow_iat_stats = _safe_stats(flow["flow_iat"])
        fwd_iat_stats = _safe_stats(fwd["iat"])
        bwd_iat_stats = _safe_stats(bwd["iat"])
        active_stats = _safe_stats(flow["active_durations"])
        idle_stats = _safe_stats(flow["idle_durations"])

        total_pkts = fwd["count"] + bwd["count"]
        total_bytes = fwd["bytes"] + bwd["bytes"]
        fwd_bulk = self._bulk_totals(flow, "fwd")
        bwd_bulk = self._bulk_totals(flow, "bwd")
        fwd_bulk_count = fwd_bulk["count"]
        bwd_bulk_count = bwd_bulk["count"]

        proto_value = self._protocol_number(packet.get("protocol") or packet.get("protocol_name"))

        features = {
            "dst_port": self._coerce_int(key[3]),
            "protocol": proto_value,
            "flow_duration": flow_duration,
            "tot_fwd_pkts": fwd["count"],
            "tot_bwd_pkts": bwd["count"],
            "totlen_fwd_pkts": fwd["bytes"],
            "totlen_bwd_pkts": bwd["bytes"],
            "fwd_pkt_len_max": fwd_stats["max"],
            "fwd_pkt_len_min": fwd_stats["min"],
            "fwd_pkt_len_mean": fwd_stats["mean"],
            "fwd_pkt_len_std": fwd_stats["std"],
            "bwd_pkt_len_max": bwd_stats["max"],
            "bwd_pkt_len_min": bwd_stats["min"],
            "bwd_pkt_len_mean": bwd_stats["mean"],
            "bwd_pkt_len_std": bwd_stats["std"],
            "flow_byts_s": total_bytes / duration_seconds,
            "flow_pkts_s": total_pkts / duration_seconds,
            "flow_iat_mean": flow_iat_stats["mean"],
            "flow_iat_std": flow_iat_stats["std"],
            "flow_iat_max": flow_iat_stats["max"],
            "flow_iat_min": flow_iat_stats["min"],
            "fwd_iat_tot": sum(fwd["iat"]),
            "fwd_iat_mean": fwd_iat_stats["mean"],
            "fwd_iat_std": fwd_iat_stats["std"],
            "fwd_iat_max": fwd_iat_stats["max"],
            "fwd_iat_min": fwd_iat_stats["min"],
            "bwd_iat_tot": sum(bwd["iat"]),
            "bwd_iat_mean": bwd_iat_stats["mean"],
            "bwd_iat_std": bwd_iat_stats["std"],
            "bwd_iat_max": bwd_iat_stats["max"],
            "bwd_iat_min": bwd_iat_stats["min"],
            "fwd_psh_flags": fwd["psh"],
            "bwd_psh_flags": bwd["psh"],
            "fwd_urg_flags": fwd["urg"],
            "bwd_urg_flags": bwd["urg"],
            "fwd_header_len": fwd["header_len"],
            "bwd_header_len": bwd["header_len"],
            "fwd_pkts_s": fwd["count"] / duration_seconds,
            "bwd_pkts_s": bwd["count"] / duration_seconds,
            "pkt_len_min": pkt_stats["min"],
            "pkt_len_max": pkt_stats["max"],
            "pkt_len_mean": pkt_stats["mean"],
            "pkt_len_std": pkt_stats["std"],
            "pkt_len_var": pkt_stats["var"],
            "fin_flag_cnt": flow["flags"].get("F", 0),
            "syn_flag_cnt": flow["flags"].get("S", 0),
            "rst_flag_cnt": flow["flags"].get("R", 0),
            "psh_flag_cnt": flow["flags"].get("P", 0),
            "ack_flag_cnt": flow["flags"].get("A", 0),
            "urg_flag_cnt": flow["flags"].get("U", 0),
            "cwe_flag_count": flow["flags"].get("C", 0),
            "ece_flag_cnt": flow["flags"].get("E", 0),
            "down_up_ratio": bwd["count"] / fwd["count"] if fwd["count"] else 0.0,
            "pkt_size_avg": pkt_stats["mean"],
            "fwd_seg_size_avg": fwd_stats["mean"],
            "bwd_seg_size_avg": bwd_stats["mean"],
            "fwd_byts_b_avg": (fwd_bulk["size"] / fwd_bulk_count) if fwd_bulk_count else 0.0,
            "fwd_pkts_b_avg": (fwd_bulk["packet_count"] / fwd_bulk_count) if fwd_bulk_count else 0.0,
            "fwd_blk_rate_avg": (fwd_bulk["size"] / fwd_bulk["duration"]) if fwd_bulk["duration"] > 0 else 0.0,
            "bwd_byts_b_avg": (bwd_bulk["size"] / bwd_bulk_count) if bwd_bulk_count else 0.0,
            "bwd_pkts_b_avg": (bwd_bulk["packet_count"] / bwd_bulk_count) if bwd_bulk_count else 0.0,
            "bwd_blk_rate_avg": (bwd_bulk["size"] / bwd_bulk["duration"]) if bwd_bulk["duration"] > 0 else 0.0,
            "subflow_fwd_pkts": fwd["count"],
            "subflow_fwd_byts": fwd["bytes"],
            "subflow_bwd_pkts": bwd["count"],
            "subflow_bwd_byts": bwd["bytes"],
            "init_fwd_win_byts": fwd["init_win"] or 0,
            "init_bwd_win_byts": bwd["init_win"] or 0,
            "fwd_act_data_pkts": fwd["act_data_pkts"],
            "fwd_seg_size_min": fwd_stats["min"],
            "active_mean": active_stats["mean"],
            "active_std": active_stats["std"],
            "active_max": active_stats["max"],
            "active_min": active_stats["min"],
            "idle_mean": idle_stats["mean"],
            "idle_std": idle_stats["std"],
            "idle_max": idle_stats["max"],
            "idle_min": idle_stats["min"],
        }

        for name in self.FEATURE_NAMES:
            features.setdefault(name, 0)

        return features


PACKET_FEATURE_NAMES: Tuple[str, ...] = (
    "Dst Port",
    "Protocol",
    "TotLen Fwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Mean",
    "Flow Byts/s",
    "PSH Flag Cnt",
    "URG Flag Cnt",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "ACK Flag Cnt",
    "Fwd Header Len",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Std",
    "Down/Up Ratio",
    "Fwd Pkts/s",
)


class PacketFeatureExtractor:
    """Packet-level, 17-feature extractor aligned to CICIDS 2018 columns."""

    FEATURE_NAMES: Tuple[str, ...] = PACKET_FEATURE_NAMES
    PROTOCOL_MAP: Mapping[str, int] = {"tcp": 6, "udp": 17, "icmp": 1}

    def __init__(self, window_seconds: float = 1.0):
        self.window_seconds = max(window_seconds, 0.1)
        self.flows: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    @staticmethod
    def _coerce_int(value: Any, default: int = 0) -> int:
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return default

    @classmethod
    def _protocol_number(cls, value: Any) -> int:
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            text = value.strip().lower()
            if text in cls.PROTOCOL_MAP:
                return cls.PROTOCOL_MAP[text]
            if text.isdigit():
                return int(text)
        return 0

    def _flow_key(self, packet: Mapping[str, Any]) -> Tuple[Any, ...]:
        src_ip = packet.get("src_ip") or packet.get("source_ip")
        dst_ip = packet.get("dst_ip") or packet.get("dest_ip")
        src_port = packet.get("src_port") or packet.get("source_port")
        dst_port = packet.get("dst_port") or packet.get("dest_port")
        proto = packet.get("protocol") or packet.get("protocol_name") or "tcp"
        return (
            src_ip,
            dst_ip,
            self._coerce_int(src_port),
            self._coerce_int(dst_port),
            self._protocol_number(proto),
        )

    def _ensure_flow(self, key: Tuple[Any, ...], now: float) -> Dict[str, Any]:
        if key not in self.flows:
            self.flows[key] = {
                "last_seen": now,
                "fwd": [],
                "bwd": [],
            }
        return self.flows[key]

    def _prune(self, flow: Dict[str, Any], now: float) -> None:
        cutoff = now - self.window_seconds
        for direction in ("fwd", "bwd"):
            flow[direction] = [entry for entry in flow[direction] if entry["ts"] >= cutoff]

    def _flag_count(self, entries: list[dict[str, Any]], flag: str) -> int:
        return sum(1 for entry in entries if flag in entry.get("flags", ""))

    @staticmethod
    def _stats(values: list[float]) -> dict[str, float]:
        if not values:
            return {"min": 0.0, "max": 0.0, "mean": 0.0, "std": 0.0}
        if len(values) == 1:
            value = float(values[0])
            return {"min": value, "max": value, "mean": value, "std": 0.0}
        mean_val = float(statistics.mean(values))
        std_val = float(statistics.pstdev(values))
        return {
            "min": float(min(values)),
            "max": float(max(values)),
            "mean": mean_val,
            "std": std_val,
        }

    def _rate(self, count: int, timestamps: list[float]) -> float:
        if count <= 1:
            return 0.0
        duration = max(max(timestamps) - min(timestamps), 1e-6)
        return float(count / duration)

    def extract(self, packet: Mapping[str, Any]) -> Dict[str, Any]:
        now = float(packet.get("timestamp") or time.time())
        key = self._flow_key(packet)
        rev_key = (key[1], key[0], key[3], key[2], key[4])

        direction = "fwd"
        flow = self.flows.get(key)
        if flow is None and rev_key in self.flows:
            flow = self.flows[rev_key]
            direction = "bwd"
        if flow is None:
            flow = self._ensure_flow(key, now)

        size = self._coerce_int(packet.get("size") or packet.get("length") or 0)
        header_len = self._coerce_int(packet.get("header_len") or 0)
        flags = str(packet.get("flags") or "")

        flow[direction].append({"ts": now, "size": size, "header_len": header_len, "flags": flags})
        flow["last_seen"] = now
        self._prune(flow, now)

        fwd_entries = flow["fwd"]
        bwd_entries = flow["bwd"]
        all_entries = fwd_entries + bwd_entries

        fwd_sizes = [entry["size"] for entry in fwd_entries]
        bwd_sizes = [entry["size"] for entry in bwd_entries]
        all_sizes = [entry["size"] for entry in all_entries]

        fwd_times = [entry["ts"] for entry in fwd_entries]
        all_times = [entry["ts"] for entry in all_entries]

        fwd_stats = self._stats(fwd_sizes)
        total_bytes = sum(all_sizes)
        flow_duration = max(max(all_times) - min(all_times), 1e-6) if len(all_times) > 1 else 1e-6

        features = {
            "Dst Port": self._coerce_int(packet.get("dst_port") or packet.get("dest_port") or 0),
            "Protocol": self._protocol_number(packet.get("protocol") or packet.get("protocol_name")),
            "TotLen Fwd Pkts": float(sum(fwd_sizes)),
            "Fwd Pkt Len Max": fwd_stats["max"],
            "Fwd Pkt Len Mean": fwd_stats["mean"],
            "Flow Byts/s": float(total_bytes / flow_duration),
            "PSH Flag Cnt": float(self._flag_count(all_entries, "P")),
            "URG Flag Cnt": float(self._flag_count(all_entries, "U")),
            "FIN Flag Cnt": float(self._flag_count(all_entries, "F")),
            "SYN Flag Cnt": float(self._flag_count(all_entries, "S")),
            "RST Flag Cnt": float(self._flag_count(all_entries, "R")),
            "ACK Flag Cnt": float(self._flag_count(all_entries, "A")),
            "Fwd Header Len": float(sum(entry["header_len"] for entry in fwd_entries)),
            "Fwd Pkt Len Min": fwd_stats["min"],
            "Fwd Pkt Len Std": fwd_stats["std"],
            "Down/Up Ratio": float(len(bwd_entries) / len(fwd_entries)) if fwd_entries else 0.0,
            "Fwd Pkts/s": self._rate(len(fwd_entries), fwd_times),
        }

        for name in self.FEATURE_NAMES:
            features.setdefault(name, 0.0)

        return features


def _should_use_packet_schema(feature_columns: list[str]) -> bool:
    if not feature_columns:
        return False
    return all(name in feature_columns for name in PACKET_FEATURE_NAMES)


def get_feature_extractor() -> CICFlowFeatureExtractor:
    schema = (settings.feature_schema or "auto").lower()
    if schema in {"packet", "packet17", "cicids2018", "cicids2018_packet"}:
        return PacketFeatureExtractor(
            window_seconds=settings.packet_feature_window_seconds,
        )

    if schema == "auto":
        metadata = load_model_metadata()
        columns = list(metadata.get("feature_columns") or [])
        if _should_use_packet_schema(columns):
            return PacketFeatureExtractor(
                window_seconds=settings.packet_feature_window_seconds,
            )

    return CICFlowFeatureExtractor(
        flow_timeout=settings.cic_flow_timeout_seconds,
        idle_threshold=settings.cic_idle_threshold_seconds,
    )


feature_extractor = get_feature_extractor()
