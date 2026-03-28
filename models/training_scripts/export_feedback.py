#!/usr/bin/env python3
"""
Export analyst feedback labels from MongoDB for retraining.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from pymongo import MongoClient


def parse_args():
    parser = argparse.ArgumentParser(description="Export alert feedback from MongoDB.")
    parser.add_argument("--mongo-uri", type=str, default="mongodb://localhost:27017/ids")
    parser.add_argument("--output", type=Path, default=Path("models/training_scripts/data/feedback_labels.json"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = MongoClient(args.mongo_uri, serverSelectionTimeoutMS=3000)
    db = client.get_default_database()
    feedback_rows = list(db["alert_feedback"].find({}, {"_id": 0}))
    samples = []
    for entry in feedback_rows:
        alert_id = entry.get("alert_id")
        if not alert_id:
            continue
        alert = db["alerts"].find_one({"id": alert_id}, {"_id": 0})
        if not alert:
            continue
        features = alert.get("feature_snapshot") or {}
        if not features:
            continue
        label = entry.get("label") or "unknown"
        weight = entry.get("weight") or 5.0
        samples.append(
            {
                "alert_id": alert_id,
                "label": label,
                "weight": float(weight),
                "features": features,
            }
        )

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "count": len(samples),
        "samples": samples,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote feedback labels to {args.output}")


if __name__ == "__main__":
    main()
