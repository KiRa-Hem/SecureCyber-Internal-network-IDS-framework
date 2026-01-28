#!/usr/bin/env python3
"""
Trigger retraining when drift alerts are observed.

This script:
1) Checks MongoDB for recent drift alerts.
2) If found (or --force), runs preprocessing + training steps.
3) Updates model card via existing training scripts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from pymongo import MongoClient


def parse_args():
    parser = argparse.ArgumentParser(description="Retrain model when drift is detected.")
    parser.add_argument("--mongo-uri", type=str, required=False, default="mongodb://localhost:27017/ids")
    parser.add_argument("--lookback-hours", type=int, default=24)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("models/training_scripts/data/cicids2018_pipeline"))
    parser.add_argument("--model-dir", type=Path, default=Path("models/cicids2018_packet"))
    return parser.parse_args()


def has_recent_drift(mongo_uri: str, lookback_hours: int) -> bool:
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
    db = client.get_default_database()
    cutoff = datetime.utcnow() - timedelta(hours=lookback_hours)
    ts_cutoff = int(cutoff.timestamp())
    count = db["alerts"].count_documents({
        "attack_types": {"$in": ["Drift"]},
        "timestamp": {"$gte": ts_cutoff},
    })
    client.close()
    return count > 0


def run_step(args_list: list[str]) -> None:
    result = subprocess.run(args_list, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> None:
    args = parse_args()
    if not args.force:
        try:
            if not has_recent_drift(args.mongo_uri, args.lookback_hours):
                print("No recent drift alerts. Skipping retraining.")
                return
        except Exception as exc:
            print(f"Drift check failed: {exc}. Use --force to retrain anyway.")
            return

    pipeline = [
        ["python", "models/training_scripts/preprocess_cic.py", "load"],
        ["python", "models/training_scripts/preprocess_cic.py", "select"],
        ["python", "models/training_scripts/preprocess_cic.py", "finalize"],
        ["python", "models/training_scripts/preprocess_cic.py", "balance"],
        ["python", "models/training_scripts/preprocess_cic.py", "split"],
        ["python", "models/training_scripts/preprocess_cic.py", "scale"],
        ["python", "models/training_scripts/preprocess_cic.py", "train"],
        ["python", "models/training_scripts/preprocess_cic.py", "train-anomaly"],
        ["python", "models/training_scripts/preprocess_cic.py", "evaluate"],
    ]

    for cmd in pipeline:
        run_step(cmd)

    print("Retraining complete. Model card and metrics updated.")


if __name__ == "__main__":
    main()
