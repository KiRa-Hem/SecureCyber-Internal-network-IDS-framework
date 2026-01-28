import json
from pathlib import Path
from typing import Any, Dict, Optional

from app.model_registry import resolve_model_dir


def load_model_metadata(model_dir: Optional[Path] = None) -> Dict[str, Any]:
    base_dir = Path(model_dir) if model_dir else resolve_model_dir()
    for filename in ("model_metadata.json", "model_metrics.json"):
        path = base_dir / filename
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    return json.load(handle)
            except Exception:
                return {}
    return {}
