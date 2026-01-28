#!/usr/bin/env python3
"""
Evaluate a trained XGBoost model against preprocessed CICIDS data.
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

try:
    import xgboost as xgb
except Exception:
    xgb = None

METADATA_FILENAME = "dataset_metadata.json"


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate XGBoost IDS model.")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    return parser.parse_args()


def load_metadata(data_dir: Path) -> Optional[Dict[str, object]]:
    metadata_path = data_dir / METADATA_FILENAME
    if not metadata_path.exists():
        return None
    with open(metadata_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def prepare_matrix(df: pd.DataFrame, feature_columns) -> np.ndarray:
    X = df.copy()
    for col in feature_columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.fillna(0.0)
    return X[feature_columns].values


def tune_threshold(y_true: np.ndarray, probas: np.ndarray, target_fpr: float) -> Dict[str, Optional[float]]:
    if np.unique(y_true).size < 2:
        return {
            "best_f1": None,
            "best_f1_threshold": None,
            "recall_at_fpr_target": None,
            "threshold_at_fpr_target": None,
        }

    precisions, recalls, pr_thresholds = precision_recall_curve(y_true, probas)
    f1_scores = (2 * precisions * recalls) / (precisions + recalls + 1e-12)
    best_idx = int(np.nanargmax(f1_scores))
    best_f1 = float(f1_scores[best_idx])
    best_threshold = None
    if best_idx < len(pr_thresholds):
        best_threshold = float(pr_thresholds[best_idx])

    fpr, tpr, roc_thresholds = roc_curve(y_true, probas)
    mask = fpr <= target_fpr
    if np.any(mask):
        idx = np.argmax(tpr[mask])
        recall_at_target = float(tpr[mask][idx])
        threshold_at_target = float(roc_thresholds[mask][idx])
    else:
        recall_at_target = None
        threshold_at_target = None

    return {
        "best_f1": best_f1,
        "best_f1_threshold": best_threshold,
        "recall_at_fpr_target": recall_at_target,
        "threshold_at_fpr_target": threshold_at_target,
    }


def main():
    args = parse_args()
    if xgb is None:
        raise SystemExit("ERROR: xgboost is not installed.")

    data_dir = args.data_dir.expanduser()
    model_dir = args.model_dir.expanduser()

    X_train = pd.read_pickle(data_dir / "X_train.pkl")
    X_test = pd.read_pickle(data_dir / "X_test.pkl")
    y_binary_test = np.load(data_dir / "y_binary_test.npy")

    metadata = load_metadata(data_dir)
    feature_columns = (
        metadata.get("feature_columns") if metadata else list(X_train.columns)
    )
    feature_columns = list(feature_columns)
    excluded_features = set(metadata.get("excluded_features", []) if metadata else [])
    if excluded_features:
        print(f"Excluded {len(excluded_features)} features during evaluation: {', '.join(sorted(excluded_features))}")
        X_train = X_train.drop(columns=[c for c in excluded_features if c in X_train.columns])
        X_test = X_test.drop(columns=[c for c in excluded_features if c in X_test.columns])

    X_matrix = prepare_matrix(X_test, feature_columns)

    model_path = model_dir / "attack_classifier_xgb.json"
    model = xgb.XGBClassifier()
    model.load_model(str(model_path))

    probas = model.predict_proba(X_matrix)[:, 1]
    preds = (probas >= 0.5).astype(int)

    metrics_payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "dataset_dir": str(data_dir),
        "model_dir": str(model_dir),
        "dataset": metadata.get("dataset") if metadata else "cic",
        "feature_columns": feature_columns,
        "sample_counts": {
            "train": int(len(X_train)),
            "test": int(len(X_test)),
        },
        "xgboost": {
            "accuracy": accuracy_score(y_binary_test, preds),
            "f1": f1_score(y_binary_test, preds, zero_division=0),
            "roc_auc": None if np.unique(y_binary_test).size < 2 else roc_auc_score(y_binary_test, probas),
            "pr_auc": None if np.unique(y_binary_test).size < 2 else average_precision_score(y_binary_test, probas),
            "classification_report": classification_report(
                y_binary_test, preds, output_dict=True, zero_division=0
            ),
        },
        "thresholds": {
            "target_fpr": args.target_fpr,
            "xgboost": tune_threshold(y_binary_test, probas, args.target_fpr),
        },
    }

    output_path = args.output or model_dir / "model_metrics.json"
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(metrics_payload, handle, indent=2, ensure_ascii=True)

    print(f"Wrote metrics to {output_path}")


if __name__ == "__main__":
    main()
