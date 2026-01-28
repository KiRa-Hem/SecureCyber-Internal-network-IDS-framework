#!/usr/bin/env python3
"""
Random search tuner for XGBoost using preprocessed training data and holdout days.
Saves a leaderboard JSON and optionally the best model.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
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
    parser = argparse.ArgumentParser(description="Tune XGBoost with holdout-day evaluation.")
    parser.add_argument(
        "--train-dir",
        type=Path,
        default=Path("models") / "training_scripts" / "data" / "cicids2018_train7",
        help="Directory with split/scaled training artifacts.",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("models") / "cicids2018_packet",
        help="Directory to save the best model/leaderboard.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Directory containing CICIDS 2018 CSVs.",
    )
    parser.add_argument(
        "--holdout-days",
        nargs="+",
        required=True,
        help="CSV filenames to use for holdout evaluation.",
    )
    parser.add_argument("--trials", type=int, default=20, help="Number of random trials.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--metric",
        choices=["f1", "pr_auc", "roc_auc", "recall", "precision", "accuracy"],
        default="f1",
        help="Metric to optimize on holdout.",
    )
    parser.add_argument(
        "--save-best",
        action="store_true",
        help="Save the best model as attack_classifier_xgb_tuned.json.",
    )
    return parser.parse_args()


def load_scaled_payload(train_dir: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, object, List[str]]:
    split_dir = train_dir / "split"
    feature_path = split_dir / "feature_columns.json"
    feature_columns = []
    if feature_path.exists():
        feature_columns = json.loads(feature_path.read_text(encoding="utf-8"))

    scaled_path = train_dir / "scaled.pkl"
    if scaled_path.exists():
        payload = pd.read_pickle(scaled_path)
        X_train = np.asarray(payload["X_train"])
        X_val = np.asarray(payload["X_test"])
        y_train = payload["y_train"]
        y_val = payload["y_test"]
        scaler = payload.get("scaler")
        return X_train, X_val, np.asarray(y_train), np.asarray(y_val), scaler, feature_columns

    X_train = pd.read_pickle(split_dir / "X_train.pkl").to_numpy()
    X_val = pd.read_pickle(split_dir / "X_test.pkl").to_numpy()
    y_train = pd.read_pickle(split_dir / "y_train.pkl")
    y_val = pd.read_pickle(split_dir / "y_test.pkl")
    return X_train, X_val, np.asarray(y_train), np.asarray(y_val), None, feature_columns


def to_binary_labels(values: np.ndarray) -> np.ndarray:
    normal_label = "Normal" if CONFIG.get("use_simplified") else "Benign"
    values = np.asarray(values)
    if values.dtype.kind in "biuf":
        unique = set(np.unique(values).tolist())
        if unique.issubset({0, 1}):
            return values.astype(int)
    as_text = np.array([str(v).strip() for v in values])
    return (as_text != normal_label).astype(int)


def load_holdout(
    data_dir: Path,
    days: List[str],
    feature_columns: List[str],
    scaler: object,
) -> Tuple[np.ndarray, np.ndarray]:
    df = load_days(data_dir, days, chunksize=200_000, fill_na_value=0.0, drop_na=False)
    df, _ = select_features(df)
    if CONFIG.get("use_simplified", True):
        df = simplify_labels(df)
    df = finalize_preprocessing(df)
    X = df.drop("Label", axis=1)
    y = df["Label"]
    y_true = to_binary_labels(y.values)

    for col in feature_columns:
        if col not in X.columns:
            X[col] = 0
    X = X[feature_columns].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)

    X_values = X.to_numpy(dtype=np.float32)
    if scaler is not None:
        try:
            X_values = scaler.transform(X_values)
        except Exception:
            pass
    return X_values, y_true


def sample_params(rng: np.random.Generator) -> Dict[str, object]:
    return {
        "n_estimators": int(rng.choice([300, 500, 800, 1200])),
        "max_depth": int(rng.choice([4, 6, 8, 10])),
        "learning_rate": float(rng.choice([0.03, 0.05, 0.1, 0.2])),
        "subsample": float(rng.choice([0.7, 0.8, 0.9, 1.0])),
        "colsample_bytree": float(rng.choice([0.7, 0.8, 0.9, 1.0])),
        "min_child_weight": float(rng.choice([1, 5, 10])),
        "gamma": float(rng.choice([0.0, 0.1, 0.5])),
        "reg_alpha": float(rng.choice([0.0, 0.01, 0.1])),
        "reg_lambda": float(rng.choice([1.0, 2.0, 5.0])),
    }


def compute_metrics(y_true: np.ndarray, probas: np.ndarray) -> Dict[str, float]:
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
    return metrics


def main() -> None:
    args = parse_args()
    if xgb is None:
        raise SystemExit("ERROR: xgboost is not installed.")

    train_dir = args.train_dir.expanduser().resolve()
    model_dir = args.model_dir.expanduser().resolve()
    model_dir.mkdir(parents=True, exist_ok=True)

    X_train, X_val, y_train, y_val, scaler, feature_columns = load_scaled_payload(train_dir)
    y_train_bin = to_binary_labels(y_train)
    y_val_bin = to_binary_labels(y_val)

    data_dir = discover_dataset_dir(args.data_dir)
    X_holdout, y_holdout = load_holdout(data_dir, args.holdout_days, feature_columns, scaler)

    rng = np.random.default_rng(args.seed)
    leaderboard = []
    best_score = -1.0
    best_params = None
    best_model = None

    for idx in range(1, args.trials + 1):
        params = sample_params(rng)
        start = time.time()

        model = xgb.XGBClassifier(
            objective="binary:logistic",
            eval_metric="aucpr",
            tree_method="hist",
            n_jobs=-1,
            random_state=args.seed,
            **params,
        )

        model.fit(
            X_train,
            y_train_bin,
            eval_set=[(X_val, y_val_bin)],
            verbose=False,
            early_stopping_rounds=30,
        )

        probas = model.predict_proba(X_holdout)[:, 1]
        metrics = compute_metrics(y_holdout, probas)
        elapsed = time.time() - start

        score = metrics.get(args.metric) or 0.0
        leaderboard.append(
            {
                "trial": idx,
                "score_metric": args.metric,
                "score": float(score),
                "metrics": metrics,
                "params": params,
                "seconds": round(elapsed, 2),
            }
        )

        print(f"[{idx}/{args.trials}] {args.metric}={score:.4f} params={params}")

        if score > best_score:
            best_score = score
            best_params = params
            best_model = model

    leaderboard = sorted(leaderboard, key=lambda item: item["score"], reverse=True)
    output_path = model_dir / "tuning_leaderboard.json"
    output_path.write_text(json.dumps(leaderboard, indent=2), encoding="utf-8")
    print(f"Saved leaderboard to {output_path}")

    if args.save_best and best_model is not None:
        best_path = model_dir / "attack_classifier_xgb_tuned.json"
        best_model.save_model(str(best_path))
        print(f"Saved best model to {best_path}")
        if best_params:
            (model_dir / "tuning_best_params.json").write_text(
                json.dumps(best_params, indent=2), encoding="utf-8"
            )


if __name__ == "__main__":
    main()
