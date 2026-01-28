#!/usr/bin/env python3
"""
Run cross-dataset evaluation on multiple dataset directories.

Example:
  python models/training_scripts/run_generalization_suite.py ^
    --model-dir models/cicids2018_packet ^
    --datasets "models/training_scripts/data/raw/CICIDS 2018" "models/training_scripts/data/raw/cicids"
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import List

import subprocess


def parse_args():
    parser = argparse.ArgumentParser(description="Generalization suite runner.")
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--datasets", nargs="+", required=True)
    parser.add_argument("--output", type=Path, default=Path("models/generalization_suite.json"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    model_dir = args.model_dir.expanduser()
    reports = []

    for dataset in args.datasets:
        dataset_path = Path(dataset).expanduser()
        output_path = model_dir / f"{dataset_path.name}_cross_eval.json"
        cmd = [
            "python",
            "models/training_scripts/evaluate_cross_dataset.py",
            "--input-dir",
            str(dataset_path),
            "--model-dir",
            str(model_dir),
            "--output",
            str(output_path),
            "--max-auc-rows",
            "2000000",
            "--max-rows",
            "0",
        ]
        result = subprocess.run(cmd, check=False)
        reports.append({
            "dataset": str(dataset_path),
            "output": str(output_path),
            "status": result.returncode,
        })

    suite = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "model_dir": str(model_dir),
        "reports": reports,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(suite, indent=2), encoding="utf-8")
    print(f"Wrote generalization suite report to {args.output}")


if __name__ == "__main__":
    main()
