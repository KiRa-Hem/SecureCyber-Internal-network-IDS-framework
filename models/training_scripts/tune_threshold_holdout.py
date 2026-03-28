#!/usr/bin/env python3
"""
Tune the decision threshold to maximize F1 on holdout CICIDS 2018 days.
Optionally writes the threshold into model_metadata.json.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
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
    parser = argparse.ArgumentParser(description="Tune XGBoost threshold on holdout days.")
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("models") / "cicids2018_packet",
        help="Directory containing attack_classifier_xgb.json and model_metadata.json.",
    )
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
        help="Holdout CSV filenames to evaluate.",
    )
    parser.add_argument(
        "--train-dir",
        type=Path,
        default=None,
        help="Optional training output dir to load scaler (scaled.pkl).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON path (default: <model-dir>/holdout_threshold.json).",
    )
    parser.add_argument(
        "--write-metadata",
        action="store_true",
        help="Write best threshold into model_metadata.json.",
    )
    return parser.parse_args()


def load_metadata(model_dir: Path) -> Dict[str, object]:
    for name in ("model_metadata.json", "model_metrics.json"):
        path = model_dir / name
        if path.exists():
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
    return {}


def load_scaler(train_dir: Optional[Path]) -> Optional[object]:
    if not train_dir:
        return None
    scaled_path = train_dir / "scaled.pkl"
    if scaled_path.exists():
        payload = pd.read_pickle(scaled_path)
        return payload.get("scaler")
    return None


def to_binary_labels(values: np.ndarray) -> np.ndarray:
    normal_label = "Normal" if CONFIG.get("use_simplified") else "Benign"
    values = np.asarray(values)
    if values.dtype.kind in "biuf":
        unique = set(np.unique(values).tolist())
        if unique.issubset({0, 1}):
            return values.astype(int)
    as_text = np.array([str(v).strip() for v in values])
    return (as_text != normal_label).astype(int)


def align_features(X: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    working = X.copy()
    for col in feature_columns:
        if col not in working.columns:
            working[col] = 0
    working = working[feature_columns]
    working = working.apply(pd.to_numeric, errors="coerce")
    working.replace([np.inf, -np.inf], np.nan, inplace=True)
    return working.fillna(0.0)


def compute_metrics(y_true: np.ndarray, probas: np.ndarray, threshold: float) -> Dict[str, float]:
    preds = (probas >= threshold).astype(int)
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
    return metrics


def best_threshold_f1(y_true: np.ndarray, probas: np.ndarray) -> Tuple[float, float]:
    precisions, recalls, thresholds = precision_recall_curve(y_true, probas)
    if len(thresholds) == 0:
        return 0.5, 0.0
    f1_scores = (2 * precisions * recalls) / (precisions + recalls + 1e-12)
    best_idx = int(np.nanargmax(f1_scores))
    best_thresh = float(thresholds[min(best_idx, len(thresholds) - 1)])
    best_f1 = float(f1_scores[best_idx])
    return best_thresh, best_f1


def update_model_metadata(model_dir: Path, threshold: float) -> None:
    path = model_dir / "model_metadata.json"
    if path.exists():
        metadata = json.loads(path.read_text(encoding="utf-8"))
    else:
        metadata = {}
    thresholds = metadata.get("thresholds") or {}
    xgb_thresholds = thresholds.get("xgboost") or {}
    xgb_thresholds["best_f1_threshold"] = threshold
    thresholds["xgboost"] = xgb_thresholds
    metadata["thresholds"] = thresholds
    path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="utf-8")


def main() -> None:
    args = parse_args()
    if xgb is None:
        raise SystemExit("ERROR: xgboost is not installed.")

    model_dir = args.model_dir.expanduser().resolve()
    model_path = model_dir / "attack_classifier_xgb.json"
    if not model_path.exists():
        raise SystemExit(f"ERROR: Model not found at {model_path}")

    metadata = load_metadata(model_dir)
    feature_columns = list(metadata.get("feature_columns") or [])
    if not feature_columns:
        raise SystemExit("ERROR: feature_columns missing from model metadata.")

    scaler = load_scaler(args.train_dir.expanduser().resolve() if args.train_dir else None)

    data_dir = discover_dataset_dir(args.data_dir)
    df = load_days(
        data_dir,
        args.days,
        chunksize=200_000,
        fill_na_value=0.0,
        drop_na=False,
        split_method=CONFIG.get("split_method", "by_day"),
    )
    df, _ = select_features(df)
    if CONFIG.get("use_simplified", True):
        df = simplify_labels(df)
    df = finalize_preprocessing(df)
    X = df.drop("Label", axis=1)
    y = df["Label"]
    y_true = to_binary_labels(y.values)

    X_aligned = align_features(X, feature_columns)
    X_values = X_aligned.to_numpy(dtype=np.float32)
    if scaler is not None:
        try:
            X_values = scaler.transform(X_values)
        except Exception:
            pass

    model = xgb.XGBClassifier()
    model.load_model(str(model_path))
    probas = model.predict_proba(X_values)[:, 1]

    best_thresh, best_f1 = best_threshold_f1(y_true, probas)
    metrics_at_best = compute_metrics(y_true, probas, best_thresh)
    metrics_at_05 = compute_metrics(y_true, probas, 0.5)

    payload = {
        "model_dir": str(model_dir),
        "data_dir": str(data_dir),
        "days": args.days,
        "rows": int(len(y_true)),
        "best_threshold": best_thresh,
        "best_f1": best_f1,
        "metrics_at_best": metrics_at_best,
        "metrics_at_0.5": metrics_at_05,
    }

    output_path = args.output or (model_dir / "holdout_threshold.json")
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"Best threshold: {best_thresh:.6f} (F1={best_f1:.6f})")
    print(f"Saved threshold report to {output_path}")

    if args.write_metadata:
        update_model_metadata(model_dir, best_thresh)
        print("Updated model_metadata.json with best_f1_threshold.")


if __name__ == "__main__":
    main()
