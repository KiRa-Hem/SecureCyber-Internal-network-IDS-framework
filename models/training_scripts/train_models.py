#!/usr/bin/env python3
"""
Train an XGBoost model on preprocessed CICIDS data.
"""

import argparse
import json
import pickle
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

try:
    import xgboost as xgb
except Exception:
    xgb = None

import matplotlib.pyplot as plt
import seaborn as sns
try:
    from preprocess_cic import EXCLUDED_FEATURES as DEFAULT_EXCLUDED_FEATURES
except Exception:
    DEFAULT_EXCLUDED_FEATURES = set()

BASE_DIR = Path(__file__).parent
ROOT_DIR = BASE_DIR.parents[1]
DEFAULT_DATA_DIR = BASE_DIR / "data" / "cic"
DEFAULT_MODEL_DIR = ROOT_DIR / "models" / "cic"
METADATA_FILENAME = "dataset_metadata.json"


def parse_args():
    parser = argparse.ArgumentParser(description="Train XGBoost on CICIDS data.")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Directory containing preprocessed CIC artifacts (default: models/training_scripts/data/cic).",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=DEFAULT_MODEL_DIR,
        help="Directory where model artifacts will be saved (default: models/cic).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Optional cap on the number of training samples.",
    )
    parser.add_argument(
        "--validation-size",
        type=float,
        default=0.2,
        help="Fraction of training data reserved for threshold tuning (default: 0.2).",
    )
    parser.add_argument(
        "--target-fpr",
        type=float,
        default=0.01,
        help="Target false-positive rate for recall tuning (default: 0.01).",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=400)
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument("--subsample", type=float, default=0.8)
    parser.add_argument("--colsample-bytree", type=float, default=0.8)
    parser.add_argument("--min-child-weight", type=float, default=1.0)
    parser.add_argument("--early-stopping-rounds", type=int, default=30)
    return parser.parse_args()


def load_metadata(data_dir: Path) -> Optional[Dict[str, object]]:
    metadata_path = data_dir / METADATA_FILENAME
    if not metadata_path.exists():
        return None
    with open(metadata_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_data(data_dir: Path, max_samples: Optional[int] = None):
    data_dir = data_dir.expanduser()
    if not data_dir.exists():
        raise FileNotFoundError(f"Preprocessed data directory not found: {data_dir}")

    X_train = pd.read_pickle(data_dir / "X_train.pkl")
    X_test = pd.read_pickle(data_dir / "X_test.pkl")
    y_binary_train = np.load(data_dir / "y_binary_train.npy")
    y_binary_test = np.load(data_dir / "y_binary_test.npy")
    y_category_train = np.load(data_dir / "y_category_train.npy")
    y_category_test = np.load(data_dir / "y_category_test.npy")

    if max_samples:
        X_train = X_train.head(max_samples)
        y_binary_train = y_binary_train[:max_samples]
        y_category_train = y_category_train[:max_samples]
        X_test = X_test.head(max_samples)
        y_binary_test = y_binary_test[:max_samples]
        y_category_test = y_category_test[:max_samples]

    return (
        X_train,
        X_test,
        y_binary_train,
        y_binary_test,
        y_category_train,
        y_category_test,
    )


def prepare_matrix(df: pd.DataFrame, feature_columns) -> np.ndarray:
    X = df.copy()
    for col in feature_columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.fillna(0.0)
    return X[feature_columns].values


def compute_baseline_stats(df: pd.DataFrame, feature_columns) -> Dict[str, Dict[str, float]]:
    baseline = {}
    for col in feature_columns:
        series = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
        baseline[col] = {
            "mean": float(series.mean()),
            "std": float(series.std(ddof=0) or 1.0),
            "min": float(series.min()),
            "max": float(series.max()),
        }
    return baseline


def write_model_card(model_dir: Path, metrics_payload: Dict[str, object], metadata: Dict[str, object]) -> None:
    card = [
        "# SecureCyber IDS Model Card",
        "",
        f"- Generated: {metrics_payload.get('generated_at')}",
        f"- Dataset: {metrics_payload.get('dataset')}",
        f"- Split: {metrics_payload.get('split_method')}",
        f"- Samples: train={metrics_payload.get('sample_counts', {}).get('train')} test={metrics_payload.get('sample_counts', {}).get('test')}",
        "",
        "## Performance (Binary Attack Detection)",
        f"- Accuracy: {metrics_payload.get('xgboost', {}).get('accuracy')}",
        f"- F1: {metrics_payload.get('xgboost', {}).get('f1')}",
        f"- ROC-AUC: {metrics_payload.get('xgboost', {}).get('roc_auc')}",
        f"- PR-AUC: {metrics_payload.get('xgboost', {}).get('pr_auc')}",
        "",
        "## Thresholds",
        f"- Target FPR: {metrics_payload.get('thresholds', {}).get('target_fpr')}",
        f"- Best F1 Threshold: {metrics_payload.get('thresholds', {}).get('xgboost', {}).get('best_f1_threshold')}",
        f"- Recall@FPR: {metrics_payload.get('thresholds', {}).get('xgboost', {}).get('recall_at_fpr_target')}",
        "",
        "## Intended Use",
        "- Internal network IDS with packet-level feature extraction",
        "",
        "## Limitations",
        "- Requires periodic re-evaluation on unseen datasets.",
        "- Performance can drift with changing traffic distributions.",
        "",
        "## Monitoring",
        "- Drift monitoring enabled at runtime using baseline feature stats.",
    ]
    (model_dir / "model_card.md").write_text("\n".join(card), encoding="utf-8")


def split_validation(
    X: np.ndarray,
    y: np.ndarray,
    validation_size: float,
    split_method: str,
) -> Tuple[np.ndarray, Optional[np.ndarray], np.ndarray, Optional[np.ndarray]]:
    if validation_size <= 0 or validation_size >= 1:
        return X, None, y, None
    if split_method == "time":
        split_index = int(len(X) * (1 - validation_size))
        return (
            X[:split_index],
            X[split_index:],
            y[:split_index],
            y[split_index:],
        )
    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y,
        test_size=validation_size,
        random_state=42,
        stratify=y,
    )
    return X_train, X_val, y_train, y_val


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


def save_confusion_matrix(cm: np.ndarray, output_path: Path) -> None:
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("XGBoost Confusion Matrix")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path)
    plt.close()


def main():
    args = parse_args()
    if xgb is None:
        print("ERROR: xgboost is not installed. Install it in your environment before training.")
        sys.exit(1)

    (
        X_train_df,
        X_test_df,
        y_binary_train,
        y_binary_test,
        _y_category_train,
        _y_category_test,
    ) = load_data(args.data_dir, args.max_samples)

    metadata = load_metadata(args.data_dir)
    feature_columns = (
        metadata.get("feature_columns") if metadata else list(X_train_df.columns)
    )
    feature_columns = list(feature_columns)
    split_method = str(metadata.get("split_method")) if metadata else "random"
    excluded_features = set(metadata.get("excluded_features", []) if metadata else [])
    if not excluded_features and DEFAULT_EXCLUDED_FEATURES:
        excluded_features = set(DEFAULT_EXCLUDED_FEATURES)
    if excluded_features:
        before = len(feature_columns)
        feature_columns = [col for col in feature_columns if col not in excluded_features]
        removed = before - len(feature_columns)
        print(f"Excluded {removed} features: {', '.join(sorted(excluded_features))}")
        X_train_df = X_train_df.drop(columns=[c for c in excluded_features if c in X_train_df.columns])
        X_test_df = X_test_df.drop(columns=[c for c in excluded_features if c in X_test_df.columns])

    X_train = prepare_matrix(X_train_df, feature_columns)
    X_test = prepare_matrix(X_test_df, feature_columns)

    X_fit, X_val, y_fit, y_val = split_validation(
        X_train, y_binary_train, args.validation_size, split_method
    )

    pos_count = int(np.sum(y_fit))
    neg_count = int(len(y_fit) - pos_count)
    scale_pos_weight = float(neg_count / max(pos_count, 1))

    model = xgb.XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        min_child_weight=args.min_child_weight,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=args.seed,
        scale_pos_weight=scale_pos_weight,
    )

    eval_set = [(X_val, y_val)] if X_val is not None else None
    model.fit(
        X_fit,
        y_fit,
        eval_set=eval_set,
        verbose=False,
        early_stopping_rounds=args.early_stopping_rounds if eval_set else None,
    )

    probas = model.predict_proba(X_test)[:, 1]
    preds = (probas >= 0.5).astype(int)

    accuracy = accuracy_score(y_binary_test, preds)
    f1 = f1_score(y_binary_test, preds, zero_division=0)
    if np.unique(y_binary_test).size < 2:
        roc_auc = None
        pr_auc = None
    else:
        roc_auc = roc_auc_score(y_binary_test, probas)
        pr_auc = average_precision_score(y_binary_test, probas)
    report = classification_report(y_binary_test, preds, output_dict=True, zero_division=0)

    cm = confusion_matrix(y_binary_test, preds)
    model_dir = args.model_dir.expanduser()
    if not model_dir.is_absolute():
        model_dir = (Path.cwd() / model_dir).resolve()
    model_dir.mkdir(parents=True, exist_ok=True)

    save_confusion_matrix(cm, model_dir / "xgb_confusion_matrix.png")

    thresholds = tune_threshold(
        y_val if y_val is not None else y_binary_test,
        model.predict_proba(X_val)[:, 1] if X_val is not None else probas,
        args.target_fpr,
    )

    print(f"Saving model to {model_dir} ...")
    model.save_model(str(model_dir / "attack_classifier_xgb.json"))

    # Copy label encoders for reference if present
    for name in ("le_binary.pkl", "le_category.pkl"):
        source = args.data_dir / name
        if source.exists():
            with open(source, "rb") as handle:
                payload = pickle.load(handle)
            with open(model_dir / name, "wb") as handle:
                pickle.dump(payload, handle)

    metrics_payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "dataset_dir": str(args.data_dir),
        "dataset": metadata.get("dataset") if metadata else "cic",
        "feature_columns": feature_columns,
        "excluded_features": sorted(excluded_features),
        "split_method": split_method,
        "sample_counts": {
            "train": int(len(X_train_df)),
            "test": int(len(X_test_df)),
        },
        "xgboost": {
            "accuracy": accuracy,
            "f1": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "classification_report": report,
        },
        "thresholds": {
            "target_fpr": args.target_fpr,
            "xgboost": thresholds,
        },
    }
    with open(model_dir / "model_metrics.json", "w", encoding="utf-8") as handle:
        json.dump(metrics_payload, handle, indent=2, ensure_ascii=True)

    baseline_stats = compute_baseline_stats(X_train_df, feature_columns)

    model_metadata_payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "dataset": metadata.get("dataset") if metadata else "cic",
        "feature_columns": feature_columns,
        "categorical_features": metadata.get("categorical_features", []) if metadata else [],
        "split_method": split_method,
        "excluded_features": sorted(excluded_features),
        "thresholds": {
            "target_fpr": args.target_fpr,
            "xgboost": thresholds,
        },
        "baseline_stats": baseline_stats,
    }
    with open(model_dir / "model_metadata.json", "w", encoding="utf-8") as handle:
        json.dump(model_metadata_payload, handle, indent=2, ensure_ascii=True)

    write_model_card(model_dir, metrics_payload, model_metadata_payload)

    print("Training complete!")


if __name__ == "__main__":
    main()
