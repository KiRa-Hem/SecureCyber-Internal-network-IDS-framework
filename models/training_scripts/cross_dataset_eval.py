#!/usr/bin/env python3
"""
Train on one preprocessed dataset and evaluate on another (cross-dataset generalization).

Usage:
  python models/training_scripts/cross_dataset_eval.py \
    --train-dir "models/training_scripts/data/cic" \
    --test-dir "models/training_scripts/data/cicids2018_pipeline/split" \
    --model-dir "models/cross_eval"
"""

from __future__ import annotations

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
    roc_auc_score,
)

try:
    import xgboost as xgb
except Exception:
    xgb = None


def parse_args():
    parser = argparse.ArgumentParser(description="Cross-dataset evaluation runner.")
    parser.add_argument("--train-dir", type=Path, required=True)
    parser.add_argument("--test-dir", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--target-fpr", type=float, default=0.01)
    return parser.parse_args()


def _load_split(dir_path: Path):
    X_train = pd.read_pickle(dir_path / "X_train.pkl")
    X_test = pd.read_pickle(dir_path / "X_test.pkl")
    y_train = pd.read_pickle(dir_path / "y_train.pkl") if (dir_path / "y_train.pkl").exists() else None
    y_test = pd.read_pickle(dir_path / "y_test.pkl") if (dir_path / "y_test.pkl").exists() else None
    return X_train, X_test, y_train, y_test


def _prepare_matrix(df: pd.DataFrame, feature_columns) -> np.ndarray:
    X = df.copy()
    for col in feature_columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.fillna(0.0)
    return X[feature_columns].values


def main():
    args = parse_args()
    if xgb is None:
        raise SystemExit("xgboost is required for cross-dataset evaluation.")

    train_dir = args.train_dir.expanduser()
    test_dir = args.test_dir.expanduser()
    model_dir = args.model_dir.expanduser()
    model_dir.mkdir(parents=True, exist_ok=True)

    X_train, _, y_train, _ = _load_split(train_dir)
    _, X_test, _, y_test = _load_split(test_dir)

    feature_columns = list(X_train.columns)
    X_train_matrix = _prepare_matrix(X_train, feature_columns)
    X_test_matrix = _prepare_matrix(X_test, feature_columns)

    y_train_bin = np.asarray(y_train)
    y_test_bin = np.asarray(y_test)

    model = xgb.XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=400,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        n_jobs=-1,
    )
    model.fit(X_train_matrix, y_train_bin)
    model.save_model(str(model_dir / "attack_classifier_xgb.json"))

    probas = model.predict_proba(X_test_matrix)[:, 1]
    preds = (probas >= 0.5).astype(int)

    metrics_payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "train_dir": str(train_dir),
        "test_dir": str(test_dir),
        "feature_columns": feature_columns,
        "xgboost": {
            "accuracy": accuracy_score(y_test_bin, preds),
            "f1": f1_score(y_test_bin, preds, zero_division=0),
            "roc_auc": None if np.unique(y_test_bin).size < 2 else roc_auc_score(y_test_bin, probas),
            "pr_auc": None if np.unique(y_test_bin).size < 2 else average_precision_score(y_test_bin, probas),
            "classification_report": classification_report(y_test_bin, preds, output_dict=True, zero_division=0),
        },
    }

    with open(model_dir / "cross_dataset_report.json", "w", encoding="utf-8") as handle:
        json.dump(metrics_payload, handle, indent=2, ensure_ascii=True)

    print("Cross-dataset evaluation complete.")
    print(f"Report: {model_dir / 'cross_dataset_report.json'}")


if __name__ == "__main__":
    main()
