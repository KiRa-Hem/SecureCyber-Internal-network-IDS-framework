#!/usr/bin/env python3
"""
Evaluate a trained XGBoost model on specific CICIDS 2018 day CSVs (holdout).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

try:
    import xgboost as xgb
except Exception:
    xgb = None

from preprocess_cic import (
    CONFIG,
    discover_dataset_dir,
    finalize_preprocessing,
    load_days,
    select_features,
    simplify_labels,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate XGBoost on holdout CICIDS 2018 days.")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Directory containing CICIDS 2018 CSVs.",
    )
    parser.add_argument(
        "--days",
        nargs="+",
        required=True,
        help="CSV filenames to use for holdout evaluation.",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        required=True,
        help="Directory containing attack_classifier_xgb.json and model_metadata.json.",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=200_000,
        help="CSV chunk size for loading (default: 200000).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON path (default: <model-dir>/holdout_eval.json).",
    )
    return parser.parse_args()


def load_metadata(model_dir: Path) -> Dict[str, object]:
    for name in ("model_metadata.json", "model_metrics.json"):
        path = model_dir / name
        if path.exists():
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
    raise FileNotFoundError(f"Model metadata not found in {model_dir}")


def align_features(X: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    working = X.copy()
    for col in feature_columns:
        if col not in working.columns:
            working[col] = 0
    working = working[feature_columns]
    working = working.apply(pd.to_numeric, errors="coerce")
    working.replace([np.inf, -np.inf], np.nan, inplace=True)
    working = working.fillna(0.0)
    return working


def main() -> None:
    args = parse_args()
    if xgb is None:
        raise SystemExit("ERROR: xgboost is not installed.")

    data_dir = discover_dataset_dir(args.data_dir)
    model_dir = args.model_dir.expanduser().resolve()
    metadata = load_metadata(model_dir)
    feature_columns = list(metadata.get("feature_columns") or [])
    if not feature_columns:
        raise SystemExit("ERROR: feature_columns missing from model metadata.")

    model_path = model_dir / "attack_classifier_xgb.json"
    if not model_path.exists():
        raise SystemExit(f"ERROR: Model not found at {model_path}")

    print(f"Using model: {model_path}")
    print(f"Holdout days: {', '.join(args.days)}")

    split_method = CONFIG.get("split_method", "by_day")
    df = load_days(
        data_dir,
        args.days,
        args.chunksize,
        fill_na_value=0.0,
        drop_na=False,
        split_method=split_method,
    )
    df, _selected = select_features(df)
    if CONFIG.get("use_simplified", True):
        df = simplify_labels(df)

    df = finalize_preprocessing(df)
    X = df.drop("Label", axis=1)
    y = df["Label"]

    normal_label = "Normal" if CONFIG.get("use_simplified") else "Benign"
    y_true = (y != normal_label).astype(int).to_numpy()

    X_aligned = align_features(X, feature_columns)

    model = xgb.XGBClassifier()
    model.load_model(str(model_path))
    probas = model.predict_proba(X_aligned.to_numpy(dtype=np.float32))[:, 1]
    preds = (probas >= 0.5).astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y_true, preds)),
        "precision": float(precision_score(y_true, preds, zero_division=0)),
        "recall": float(recall_score(y_true, preds, zero_division=0)),
        "f1": float(f1_score(y_true, preds, zero_division=0)),
        "roc_auc": None,
        "pr_auc": None,
    }

    if np.unique(y_true).size > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, probas))
        metrics["pr_auc"] = float(average_precision_score(y_true, probas))

    cm = confusion_matrix(y_true, preds).tolist()

    output_payload = {
        "model_dir": str(model_dir),
        "data_dir": str(data_dir),
        "days": args.days,
        "rows": int(len(y_true)),
        "metrics": metrics,
        "confusion_matrix": cm,
        "feature_columns": feature_columns,
    }

    output_path = args.output or (model_dir / "holdout_eval.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(output_payload, handle, indent=2, ensure_ascii=True)

    print("Holdout evaluation metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
    print(f"Wrote holdout metrics to {output_path}")


if __name__ == "__main__":
    main()
