import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from app.config import settings

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MODELS_ROOT = ROOT_DIR / "models"
REGISTRY_FILENAME = "registry.json"
ACTIVE_FILENAME = "active_model.json"


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def _resolve_models_root() -> Path:
    override = os.getenv("MODEL_REGISTRY_ROOT")
    if override:
        return Path(override).expanduser().resolve()

    model_path = Path(settings.model_path)
    if model_path.is_dir():
        if (model_path / REGISTRY_FILENAME).exists():
            return model_path
        if (model_path.parent / REGISTRY_FILENAME).exists():
            return model_path.parent

    return DEFAULT_MODELS_ROOT


def load_registry() -> Dict[str, Any]:
    root = _resolve_models_root()
    registry_path = root / REGISTRY_FILENAME
    if registry_path.exists():
        registry = _read_json(registry_path)
    else:
        registry = {}

    profiles = registry.get("profiles")
    if not isinstance(profiles, dict):
        profiles = {}

    for name in ("cic",):
        candidate = root / name
        if name not in profiles and candidate.exists():
            profiles[name] = {
                "path": str(candidate),
                "feature_schema": name,
                "description": f"{name.upper()} model profile",
            }

    registry["profiles"] = profiles
    if "active" not in registry and profiles:
        registry["active"] = next(iter(profiles.keys()))
    return registry


def get_active_profile() -> Optional[str]:
    root = _resolve_models_root()
    active_path = root / ACTIVE_FILENAME
    if active_path.exists():
        data = _read_json(active_path)
        if isinstance(data, dict) and data.get("active"):
            return str(data["active"])
        if isinstance(data, str) and data:
            return data

    env_profile = os.getenv("MODEL_PROFILE")
    if env_profile:
        return env_profile

    registry = load_registry()
    if registry.get("active"):
        return str(registry["active"])

    profiles = registry.get("profiles") or {}
    if profiles:
        return next(iter(profiles.keys()))
    return None


def resolve_model_dir() -> Path:
    root = _resolve_models_root()
    registry = load_registry()
    active = get_active_profile()
    profiles = registry.get("profiles") or {}
    profile = profiles.get(active) if active else None

    if isinstance(profile, dict) and profile.get("path"):
        candidate = Path(profile["path"])
        if not candidate.is_absolute():
            candidate = (root / candidate).resolve()
        return candidate

    return Path(settings.model_path)


def resolve_feature_schema() -> str:
    registry = load_registry()
    active = get_active_profile()
    profiles = registry.get("profiles") or {}
    profile = profiles.get(active) if active else None
    if isinstance(profile, dict):
        schema = profile.get("feature_schema")
        if schema:
            return str(schema).lower()
    return "auto"
