#!/usr/bin/env python3
"""
Evaluate a trained XGBoost model on a separate CICIDS dataset directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score

try:
    import xgboost as xgb
except Exception:
    xgb = None

from preprocess_cic import normalize_column_name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cross-dataset evaluation for CICIDS.")
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing CICIDS CSV files (e.g., CICIDS 2018).",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("models") / "cic",
        help="Directory with attack_classifier_xgb.json and model_metadata.json.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON path (default: <model-dir>/cic_cross_eval.json).",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=200_000,
        help="CSV chunk size for streaming evaluation (default: 200000).",
    )
    parser.add_argument(
        "--max-auc-rows",
        type=int,
        default=2_000_000,
        help="Max rows stored for AUC/PR-AUC (0 to disable).",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Stop after processing this many total rows (0 = no limit).",
    )
    parser.add_argument(
        "--days",
        nargs="*",
        default=None,
        help="Optional list of CSV filenames to evaluate (e.g. 02-14-2018.csv).",
    )
    return parser.parse_args()


def iter_csv_files(input_dir: Path) -> List[Path]:
    return sorted(Path(input_dir).rglob("*.csv"))


def load_metadata(model_dir: Path) -> Dict[str, object]:
    for name in ("model_metadata.json", "model_metrics.json"):
        path = model_dir / name
        if path.exists():
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
    raise FileNotFoundError(f"Model metadata not found in {model_dir}")


def coerce_features(df: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    working = df.copy()
    for col in feature_columns:
        if col not in working.columns:
            working[col] = 0
    working = working[feature_columns]
    working = working.apply(pd.to_numeric, errors="coerce")
    working.replace([np.inf, -np.inf], np.nan, inplace=True)
    return working


def compute_counts(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, int]:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def metrics_from_counts(counts: Dict[str, int]) -> Dict[str, float]:
    tp = counts["tp"]
    tn = counts["tn"]
    fp = counts["fp"]
    fn = counts["fn"]
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }


def main() -> None:
    args = parse_args()
    if xgb is None:
        raise SystemExit("ERROR: xgboost is not installed.")

    model_dir = args.model_dir.expanduser()
    metadata = load_metadata(model_dir)
    feature_columns = list(metadata.get("feature_columns") or [])
    if not feature_columns:
        raise SystemExit("ERROR: feature_columns missing from model metadata.")
    feature_columns = [normalize_column_name(col) for col in feature_columns]

    model_path = model_dir / "attack_classifier_xgb.json"
    if not model_path.exists():
        raise SystemExit(f"ERROR: Model not found at {model_path}")

    model = xgb.XGBClassifier()
    model.load_model(str(model_path))

    input_dir = args.input_dir.expanduser()
    csv_files = iter_csv_files(input_dir)
    if args.days:
        requested = set(args.days)
        csv_files = [p for p in csv_files if p.name in requested]
    if not csv_files:
        raise SystemExit(f"ERROR: No CSV files found under {input_dir}")

    overall_counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    total_rows = 0
    dropped_rows = 0

    auc_rows = 0
    auc_enabled = args.max_auc_rows > 0
    auc_partial = False
    auc_labels: List[np.ndarray] = []
    auc_scores: List[np.ndarray] = []

    per_file = {}

    for csv_path in csv_files:
        file_counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        file_rows = 0
        file_dropped = 0

        for chunk in pd.read_csv(csv_path, chunksize=args.chunksize, low_memory=False):
            chunk.columns = [normalize_column_name(col) for col in chunk.columns]
            if "label" not in chunk.columns:
                continue

            labels = chunk["label"].astype(str).str.strip().str.lower()
            y_true = (labels != "benign").astype(int).to_numpy()

            features = coerce_features(chunk, feature_columns)
            valid_mask = features.notna().all(axis=1)
            if not valid_mask.all():
                drop_count = int((~valid_mask).sum())
                file_dropped += drop_count
                dropped_rows += drop_count
            features = features[valid_mask].fillna(0.0)
            y_true = y_true[valid_mask.to_numpy()]

            if features.empty:
                continue

            X = features.to_numpy(dtype=np.float32)
            probas = model.predict_proba(X)[:, 1]
            preds = (probas >= 0.5).astype(int)

            counts = compute_counts(y_true, preds)
            for key in file_counts:
                file_counts[key] += counts[key]
                overall_counts[key] += counts[key]

            rows = len(y_true)
            total_rows += rows
            file_rows += rows

            if args.max_rows and total_rows >= args.max_rows:
                break

            if auc_enabled and not auc_partial:
                if auc_rows + rows <= args.max_auc_rows:
                    auc_labels.append(y_true.astype(np.int8))
                    auc_scores.append(probas.astype(np.float32))
                    auc_rows += rows
                else:
                    auc_partial = True
                    auc_enabled = False

        per_file[str(csv_path)] = {
            "rows": file_rows,
            "dropped_rows": file_dropped,
            "counts": file_counts,
            "metrics": metrics_from_counts(file_counts),
        }

        if args.max_rows and total_rows >= args.max_rows:
            break

    overall_metrics = metrics_from_counts(overall_counts)
    roc_auc = None
    pr_auc = None
    if auc_rows > 0 and not auc_partial:
        labels = np.concatenate(auc_labels)
        scores = np.concatenate(auc_scores)
        if np.unique(labels).size > 1:
            roc_auc = float(roc_auc_score(labels, scores))
            pr_auc = float(average_precision_score(labels, scores))

    output_payload = {
        "model_dir": str(model_dir),
        "input_dir": str(input_dir),
        "files": [str(path) for path in csv_files],
        "feature_columns": feature_columns,
        "total_rows": total_rows,
        "dropped_rows": dropped_rows,
        "overall": {
            "counts": overall_counts,
            "metrics": overall_metrics,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "auc_rows": auc_rows,
            "auc_partial": auc_partial,
        },
        "per_file": per_file,
    }

    output_path = args.output or (model_dir / "cic_cross_eval.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(output_payload, handle, indent=2, ensure_ascii=True)

    print(f"Wrote cross-dataset metrics to {output_path}")


if __name__ == "__main__":
    main()
