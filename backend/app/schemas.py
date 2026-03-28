"""
Pydantic response models for API documentation and Swagger UI.

Provides structured response schemas with examples and descriptions
for all SecureCyber IDS API endpoints.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


# ------------------------------------------------------------------ Core

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(example="healthy")
    version: str = Field(example="2.0.0")
    uptime_seconds: float = Field(example=3600.0)

    class Config:
        json_schema_extra = {"example": {"status": "healthy", "version": "2.0.0", "uptime_seconds": 3600.0}}


class StatsResponse(BaseModel):
    """Dashboard statistics."""
    packets_analyzed: int = Field(example=15420)
    threats_detected: int = Field(example=42)
    active_hosts: int = Field(example=18)
    attack_rate: int = Field(example=3)
    simulation_enabled: bool = Field(example=True)
    top_attackers: List[Dict[str, Any]] = Field(default_factory=list)
    model_health: str = Field(example="green")
    rl_status: str = Field(example="none")
    active_incidents: int = Field(example=2)


# ------------------------------------------------------------------ Alerts

class AlertItem(BaseModel):
    """Single alert record."""
    id: str = Field(example="alert-1709467200")
    timestamp: int = Field(example=1709467200)
    source_ip: str = Field(example="203.0.113.45")
    dest_ip: str = Field(example="10.0.1.10")
    attack_types: List[str] = Field(example=["SQL Injection"])
    confidence: float = Field(example=92.0)
    severity: Optional[str] = Field(example="high")
    mitigation: Optional[Dict[str, str]] = Field(example={"action": "blocked", "by": "risk-fusion"})
    mitre_techniques: Optional[List[str]] = Field(default=None, example=["T1190"])


class AlertsResponse(BaseModel):
    """Paginated alerts list."""
    alerts: List[AlertItem] = Field(default_factory=list)
    total: int = Field(example=42)


# ------------------------------------------------------------------ RL Optimizer

class RLStatusResponse(BaseModel):
    """RL optimizer operational status."""
    enabled: bool = Field(example=True)
    current_threshold: float = Field(example=0.9800)
    total_evaluations: int = Field(example=3)
    total_adjustments: int = Field(example=1)
    last_action: Optional[str] = Field(example="lower_threshold")
    current_state: Optional[str] = Field(example="medium_fp")
    epsilon: Optional[float] = Field(example=0.85)
    q_table_size: Optional[int] = Field(example=4)


# ------------------------------------------------------------------ Incidents

class PlaybookStep(BaseModel):
    """Single playbook step."""
    action: str = Field(example="Block source IP at firewall")
    automated: bool = Field(example=True)


class IncidentItem(BaseModel):
    """Single incident record."""
    id: str = Field(example="INC-00001")
    attack_type: str = Field(example="SQL Injection")
    severity: str = Field(example="critical")
    narrative: str = Field(example="Critical SQL Injection attack detected from 203.0.113.45")
    playbook_steps: List[PlaybookStep] = Field(default_factory=list)
    created_at: Optional[str] = Field(example="2026-03-03T15:30:00")


class IncidentStats(BaseModel):
    """Incident statistics."""
    active_incidents: int = Field(example=5)
    by_severity: Dict[str, int] = Field(example={"critical": 1, "high": 2, "medium": 2})


class IncidentsResponse(BaseModel):
    """Incidents with statistics."""
    incidents: List[IncidentItem] = Field(default_factory=list)
    stats: IncidentStats = Field(default_factory=IncidentStats)


class PlaybookInfo(BaseModel):
    """Playbook summary."""
    name: str = Field(example="SQL Injection Response")
    attack_type: str = Field(example="SQL Injection")
    severity: str = Field(example="critical")
    steps: List[PlaybookStep] = Field(default_factory=list)


class PlaybooksResponse(BaseModel):
    """All available playbooks."""
    playbooks: List[PlaybookInfo] = Field(default_factory=list)


# ------------------------------------------------------------------ Signatures

class SignatureItem(BaseModel):
    """Signature summary."""
    id: str = Field(example="sqli-basic")
    name: str = Field(example="SQL Injection")
    description: str = Field(example="Detects SQL keywords in HTTP payloads")
    severity: str = Field(example="high")
    tags: List[str] = Field(example=["web", "injection"])
    protocol: Optional[str] = Field(example="tcp")
    match_count: int = Field(example=12)


class SignatureStats(BaseModel):
    """Signature engine statistics."""
    total_signatures: int = Field(example=32)
    severity_breakdown: Dict[str, int] = Field(example={"critical": 10, "high": 8, "medium": 8, "low": 6})
    total_matches: int = Field(example=150)
    top_signatures: List[Dict[str, Any]] = Field(default_factory=list)


class SignaturesResponse(BaseModel):
    """Signatures list with stats."""
    signatures: List[SignatureItem] = Field(default_factory=list)
    stats: SignatureStats = Field(default_factory=SignatureStats)


class SignatureActionResponse(BaseModel):
    """Result of add/remove signature."""
    status: str = Field(example="ok")
    message: str = Field(example="Added signature 'custom-sig'")


# ------------------------------------------------------------------ Kill Chains

class KillChainStage(BaseModel):
    """Kill chain stage data."""
    attack_types: List[str] = Field(example=["Port Scanning"])
    alert_count: int = Field(example=3)


class KillChainItem(BaseModel):
    """Active kill chain tracking for one source IP."""
    source_ip: str = Field(example="203.0.113.45")
    completeness: float = Field(example=0.57)
    stages: Dict[str, KillChainStage] = Field(default_factory=dict)
    total_alerts: int = Field(example=8)


class KillChainsResponse(BaseModel):
    """Kill chain detection data."""
    active_chains: List[KillChainItem] = Field(default_factory=list)
    recent_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    stages: List[Dict[str, Any]] = Field(default_factory=list)


# ------------------------------------------------------------------ Model

class ModelStatusResponse(BaseModel):
    """Model health and update status."""
    health: str = Field(example="green")
    model_version: str = Field(example="1.0.0")
    drift_events_1h: int = Field(example=0)
    retrain_queued: bool = Field(example=False)
    shadow_active: bool = Field(example=False)
    shadow_progress: str = Field(example="0/100")


# ------------------------------------------------------------------ MITRE

class MitreCoverageResponse(BaseModel):
    """MITRE ATT&CK coverage data."""
    techniques: List[Dict[str, Any]] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    coverage_pct: Optional[float] = Field(example=45.2)
    hits: Dict[str, int] = Field(default_factory=dict)


# ------------------------------------------------------------------ Analytics

class AnalyticsResponse(BaseModel):
    """Aggregated analytics data."""
    attack_type_distribution: Dict[str, int] = Field(default_factory=dict)
    hourly_attack_counts: Dict[str, int] = Field(default_factory=dict)
    top_source_ips: Dict[str, int] = Field(default_factory=dict)
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    mitre_technique_hits: Dict[str, int] = Field(default_factory=dict)
    mitre_coverage: Optional[Dict[str, Any]] = None
    model_status: Optional[Dict[str, Any]] = None
    rl_status: Optional[Dict[str, Any]] = None


# Tag groups for Swagger UI organization
API_TAGS = [
    {"name": "Core", "description": "Health, stats, and dashboard endpoints"},
    {"name": "Alerts", "description": "Alert management and queries"},
    {"name": "Mitigation", "description": "IP blocking and node isolation"},
    {"name": "Detection", "description": "Signature management and analytics"},
    {"name": "Intelligence", "description": "MITRE ATT&CK, kill chains, and correlation"},
    {"name": "AI/ML", "description": "RL optimizer, model status, and autonomous updates"},
    {"name": "Incidents", "description": "Incident response and playbooks"},
    {"name": "Simulation", "description": "Attack simulation for testing"},
]
