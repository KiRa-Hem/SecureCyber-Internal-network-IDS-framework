import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from app.config import settings
from app.db import db

logger = logging.getLogger(__name__)


def _resolve_audit_path() -> Optional[Path]:
    if not settings.AUDIT_LOG_ENABLED:
        return None
    path = Path(settings.AUDIT_LOG_FILE)
    if not path.is_absolute():
        base_dir = Path(__file__).resolve().parents[1]
        path = (base_dir / path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def audit_event(event_type: str, actor: str, details: Dict[str, Any], ip: Optional[str] = None) -> None:
    """Write a structured audit log entry (JSONL)."""
    path = _resolve_audit_path()
    if path is None and not settings.AUDIT_LOG_TO_DB:
        return

    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "actor": actor,
        "ip": ip,
        "details": details,
    }

    if settings.AUDIT_LOG_TO_DB:
        try:
            db.store_audit(payload)
        except Exception as exc:
            logger.warning("Failed to store audit in DB: %s", exc)

    try:
        if path is not None:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + os.linesep)
    except Exception as exc:
        logger.warning("Failed to write audit log: %s", exc)
