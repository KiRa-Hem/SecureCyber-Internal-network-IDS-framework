#!/usr/bin/env python3
"""
Stepwise pipeline for CICIDS 2018.

Stages (run one by one):
  discover     : find dataset directory and list CSV files
  load         : load selected days, basic cleaning, save combined dataset
  select       : select 17 packet-compatible features, save filtered dataset
  finalize     : numeric conversion, fill NaNs, optional constant-drop, save final dataset
  balance      : handle class imbalance, save balanced dataset
  split        : train/test split (stratified), save split datasets
  scale        : scale features using selected scaler, save scaled datasets
  train        : train model (xgboost) on prepared data
  train-anomaly: train Isolation Forest anomaly model
  evaluate     : evaluate trained model on test set
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import pickle
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).parent
ROOT_DIR = BASE_DIR.parents[1]
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
DEFAULT_2018_DIR = RAW_DIR / "CICIDS 2018"
DEFAULT_OUTPUT_DIR = DATA_DIR / "cicids2018_pipeline"
DEFAULT_MODEL_DIR = ROOT_DIR / "models" / "cicids2018_packet"

DEFAULT_DAYS = [
    "02-15-2018.csv",
    "02-16-2018.csv",
    "02-20-2018.csv",
    "02-21-2018.csv",
    "02-22-2018.csv",
    "02-23-2018.csv",
]

CONFIG = {
    "use_simplified": True,
    "balance_method": "hybrid",  # hybrid, undersample, oversample, smote, none
    "min_samples_per_class": 10000,
    "max_samples_per_class": 100000,
    "test_size": 0.2,
    "scaler_type": "robust",  # standard, minmax, robust, none
    "random_state": 42,
    "days_to_load": DEFAULT_DAYS,
    "split_method": "by_day",  # random, by_day, by_source_ip
    "model_type": "xgboost",
    "target_type": "binary",  # binary or multiclass
    "drop_constant_features": False,
    "anomaly_contamination": 0.01,
    "anomaly_n_estimators": 200,
    "model_params": {
        "n_estimators": 400,
        "max_depth": 6,
        "learning_rate": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 1.0,
        "tree_method": "hist",
    },
}

SIMPLIFIED_MAPPING = {
    "Benign": "Normal",
    "FTP-BruteForce": "BruteForce",
    "SSH-Bruteforce": "BruteForce",
    "DoS-GoldenEye": "DoS",
    "DoS-Slowloris": "DoS",
    "DoS-SlowHTTPTest": "DoS",
    "DoS-Hulk": "DoS",
    "Heartbleed": "Exploit",
    "Web-BruteForce": "Web",
    "Web-XSS": "Web",
    "Infiltration": "Infiltration",
    "Botnet": "Botnet",
    "DDoS-LOIC-HTTP": "DDoS",
    "DDoS-HOIC": "DDoS",
}

FEATURE_MAPPING = {
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "TotLen Fwd Pkts": "total_length",
    "Fwd Pkt Len Max": "payload_size",
    "Fwd Pkt Len Mean": "mean_length",
    "Flow Byts/s": "packet_rate",
    "PSH Flag Cnt": "tcp_psh_flag",
    "URG Flag Cnt": "tcp_urg_flag",
    "FIN Flag Cnt": "tcp_fin_flag",
    "SYN Flag Cnt": "tcp_syn_flag",
    "RST Flag Cnt": "tcp_rst_flag",
    "ACK Flag Cnt": "tcp_ack_flag",
    "Fwd Header Len": "header_length",
    "Fwd Pkt Len Min": "min_length",
    "Fwd Pkt Len Std": "length_std",
    "Down/Up Ratio": "down_up_ratio",
    "Fwd Pkts/s": "packet_rate_fwd",
}

BACKUP_FEATURES = [
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Bwd Pkts",
    "Bwd Pkt Len Mean",
    "Flow Duration",
    "Flow IAT Mean",
    "Fwd IAT Mean",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "Fwd Seg Size Avg",
    "Init Fwd Win Byts",
]


def normalize_column_name(name: str) -> str:
    """Normalize CICIDS column names to match training features."""
    cleaned = str(name).strip().lower()
    for ch in (" ", "/", "-", "%", "(", ")", "[", "]", ":", ".", "#"):
        cleaned = cleaned.replace(ch, "_")
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned.strip("_")


@dataclass
class Paths:
    output_dir: Path
    model_dir: Path

    @property
    def stage1_path(self) -> Path:
        return self.output_dir / "stage1_combined.pkl"

    @property
    def stage2_path(self) -> Path:
        return self.output_dir / "stage2_selected.pkl"

    @property
    def stage3_path(self) -> Path:
        return self.output_dir / "stage3_preprocessed.pkl"

    @property
    def stage4_path(self) -> Path:
        return self.output_dir / "stage4_balanced.pkl"

    @property
    def split_dir(self) -> Path:
        return self.output_dir / "split"

    @property
    def scale_path(self) -> Path:
        return self.output_dir / "scaled.pkl"

    @property
    def model_path(self) -> Path:
        return self.model_dir / "attack_classifier_xgb.json"

    @property
    def encoder_binary_path(self) -> Path:
        return self.model_dir / "le_binary.pkl"

    @property
    def encoder_category_path(self) -> Path:
        return self.model_dir / "le_category.pkl"

    @property
    def metrics_path(self) -> Path:
        return self.model_dir / "model_metrics.json"

    @property
    def model_metadata_path(self) -> Path:
        return self.model_dir / "model_metadata.json"

    @property
    def metadata_path(self) -> Path:
        return self.output_dir / "preprocess_metadata.json"


# ----------------------------- dataset discovery

def discover_dataset_dir(explicit_dir: Optional[Path]) -> Path:
    if explicit_dir is not None:
        return explicit_dir

    kaggle_input = os.environ.get("KAGGLE_INPUT")
    if kaggle_input:
        kaggle_root = Path(kaggle_input)
        if kaggle_root.exists():
            dataset_dirs = list(kaggle_root.glob("*ids*")) + list(kaggle_root.glob("*intrusion*"))
            if dataset_dirs:
                return dataset_dirs[0]
            return kaggle_root

    if DEFAULT_2018_DIR.exists():
        return DEFAULT_2018_DIR

    return RAW_DIR


def list_csv_files(data_dir: Path) -> List[Path]:
    return sorted([p for p in data_dir.glob("*.csv")])


# ----------------------------- IO helpers

def save_frame(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_pickle(path)


def load_frame(path: Path) -> pd.DataFrame:
    return pd.read_pickle(path)


def save_pickle(payload: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        pickle.dump(payload, handle)


def load_pickle(path: Path) -> object:
    with open(path, "rb") as handle:
        return pickle.load(handle)


def load_json(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def write_json(payload: Dict[str, object], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def update_model_metadata(paths: Paths, updates: Dict[str, object]) -> None:
    existing = load_json(paths.model_metadata_path)
    thresholds = dict(existing.get("thresholds") or {})
    new_thresholds = updates.pop("thresholds", None)
    if isinstance(new_thresholds, dict):
        for key, value in new_thresholds.items():
            if isinstance(value, dict) and isinstance(thresholds.get(key), dict):
                merged = dict(thresholds.get(key) or {})
                merged.update(value)
                thresholds[key] = merged
            else:
                thresholds[key] = value

    existing.update(updates)
    existing["generated_at"] = datetime.utcnow().isoformat() + "Z"
    if thresholds:
        existing["thresholds"] = thresholds

    write_json(existing, paths.model_metadata_path)


def compute_baseline_stats(X_train, feature_columns: List[str]) -> Dict[str, Dict[str, float]]:
    df = X_train
    if not isinstance(df, pd.DataFrame):
        df = pd.DataFrame(df, columns=feature_columns)
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


def write_model_card(paths: Paths, metrics_payload: Dict[str, object]) -> None:
    card = [
        "# SecureCyber IDS Model Card (CICIDS 2018 Packet)",
        "",
        f"- Generated: {datetime.utcnow().isoformat()}Z",
        f"- Dataset: {metrics_payload.get('dataset', 'cicids2018')}",
        f"- Split: {metrics_payload.get('split_method', CONFIG.get('split_method'))}",
        "",
        "## Intended Use",
        "- Internal network IDS with packet-level feature extraction.",
        "",
        "## Metrics",
        f"- Target FPR: {metrics_payload.get('thresholds', {}).get('target_fpr')}",
        f"- Best F1 Threshold: {metrics_payload.get('thresholds', {}).get('xgboost', {}).get('best_f1_threshold')}",
        "",
        "## Limitations",
        "- Requires periodic re-evaluation on unseen datasets.",
        "- Susceptible to drift when traffic patterns change.",
    ]
    paths.model_dir.mkdir(parents=True, exist_ok=True)
    (paths.model_dir / "model_card.md").write_text("\n".join(card), encoding="utf-8")


def load_feature_columns(paths: Paths) -> List[str]:
    feature_path = paths.split_dir / "feature_columns.json"
    if feature_path.exists():
        try:
            return list(json.loads(feature_path.read_text(encoding="utf-8")))
        except Exception:
            return []
    return []


def _json_safe(value: object) -> object:
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (np.integer, np.floating)):
        return value.item()
    if isinstance(value, dict):
        return {key: _json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


# ----------------------------- stage 1: load

def load_and_preprocess_day(
    csv_path: Path,
    split_method: str,
    chunksize: int = 50000,
    fill_na_value: Optional[float] = 0.0,
    drop_na: bool = False,
) -> pd.DataFrame:
    print(f"\nLoading {csv_path.name}...")

    drop_cols = ["Flow ID", "Src Port", "Dst IP", "Timestamp"]
    if split_method != "by_source_ip":
        drop_cols.append("Src IP")
    chunks: List[pd.DataFrame] = []

    for chunk in pd.read_csv(csv_path, chunksize=chunksize, low_memory=False):
        chunk = chunk.drop(columns=[c for c in drop_cols if c in chunk.columns], errors="ignore")
        if split_method == "by_source_ip" and "Src IP" in chunk.columns:
            chunk.rename(columns={"Src IP": "_src_ip"}, inplace=True)
        chunk["_day"] = csv_path.name

        if "Dst Port" in chunk.columns:
            chunk = chunk[chunk["Dst Port"] != "Dst Port"]

        chunk = chunk.replace(["Infinity", "infinity"], np.inf)
        chunk = chunk.replace([np.inf, -np.inf], np.nan)

        for col in chunk.columns:
            if col != "Label":
                chunk[col] = pd.to_numeric(chunk[col], errors="coerce", downcast="float")

        if drop_na:
            chunk = chunk.dropna()
        elif fill_na_value is not None:
            numeric_cols = [c for c in chunk.columns if c != "Label"]
            chunk[numeric_cols] = chunk[numeric_cols].fillna(fill_na_value)

        chunks.append(chunk)

    df = pd.concat(chunks, ignore_index=True)
    del chunks
    gc.collect()

    print(f"  Loaded {len(df):,} samples")
    print(f"  Memory: {df.memory_usage(deep=True).sum() / 1024**2:.1f} MB")
    if "Label" in df.columns:
        print(f"  Attack distribution: {df['Label'].value_counts().to_dict()}")

    return df


def load_days(
    data_dir: Path,
    days: List[str],
    chunksize: int,
    fill_na_value: Optional[float],
    drop_na: bool,
    split_method: str,
) -> pd.DataFrame:
    def _generator() -> Iterable[pd.DataFrame]:
        for day in days:
            day_path = data_dir / day
            if day_path.exists():
                yield load_and_preprocess_day(
                    day_path,
                    split_method=split_method,
                    chunksize=chunksize,
                    fill_na_value=fill_na_value,
                    drop_na=drop_na,
                )
            else:
                print(f"WARNING: {day} not found, skipping...")

    print("\n" + "=" * 50)
    print("Combining data from selected days...")
    df = pd.concat(_generator(), ignore_index=True)
    gc.collect()

    for col in df.columns:
        if col != "Label":
            df[col] = pd.to_numeric(df[col], errors="coerce", downcast="float")

    print(f"Total samples: {len(df):,}")
    print(f"Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.1f} MB")
    if "Label" in df.columns:
        print("Label distribution:")
        print(df["Label"].value_counts())

    return df


# ----------------------------- stage 2: feature selection

def select_features(df: pd.DataFrame, target_count: int = 17) -> Tuple[pd.DataFrame, List[str]]:
    print("\n" + "=" * 50)
    print("FEATURE SELECTION: Mapping to packet-level features")
    print("=" * 50)
    print("Selecting features that match packet-level capture equivalents.\n")

    selected: List[str] = []

    for cic_feat, mapped in FEATURE_MAPPING.items():
        if cic_feat in df.columns:
            selected.append(cic_feat)
            print(f"  OK {cic_feat:25s} -> {mapped}")

    if len(selected) < target_count:
        print(f"\nNeed {target_count - len(selected)} more features...")
        for feat in BACKUP_FEATURES:
            if feat in df.columns and feat not in selected:
                selected.append(feat)
                print(f"  + {feat:25s} (backup)")
            if len(selected) >= target_count:
                break

    selected = selected[:target_count]
    print("\n" + "=" * 50)
    print(f"Final selection: {len(selected)} features")
    print("=" * 50)
    for idx, feat in enumerate(selected, 1):
        print(f"  {idx:2d}. {feat}")

    filtered = df[selected + ["Label"]].copy()
    return filtered, selected


def simplify_labels(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["Label"] = df["Label"].replace(SIMPLIFIED_MAPPING)
    return df


# ----------------------------- stage 3: finalize

def finalize_preprocessing(df: pd.DataFrame) -> pd.DataFrame:
    print("\nConverting features to numeric...")
    X = df.drop("Label", axis=1)
    y = df["Label"]

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce", downcast="float")

    X.fillna(0, inplace=True)

    if CONFIG.get("drop_constant_features", False):
        print("\nRemoving constant features...")
        variances = X.var()
        constant_features = variances[variances < 1e-8].index.tolist()
        if constant_features:
            X = X.drop(columns=constant_features)
            print(f"  Dropped {len(constant_features)} constant features")
        gc.collect()

    final_df = X.copy()
    final_df["Label"] = y.values

    print(f"Final feature matrix: {X.shape}")
    print(f"Memory usage: {final_df.memory_usage(deep=True).sum() / 1024**2:.1f} MB")
    return final_df


# ----------------------------- stage 4: class imbalance

def balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    try:
        from imblearn.over_sampling import RandomOverSampler, SMOTE
        from imblearn.under_sampling import RandomUnderSampler
    except Exception as exc:  # pragma: no cover
        raise SystemExit("imbalanced-learn is required for balancing. Install it and retry.") from exc

    X = df.drop("Label", axis=1)
    y = df["Label"]

    balance_method = CONFIG.get("balance_method", "hybrid")
    print(f"Applying {balance_method} balancing...")

    if balance_method == "hybrid":
        min_samples = CONFIG.get("min_samples_per_class", 10000)
        max_samples = CONFIG.get("max_samples_per_class", 100000)

        print(f"  Target range: {min_samples:,} - {max_samples:,} samples per class")
        class_counts = y.value_counts()
        print("\nOriginal distribution:")
        for cls, count in class_counts.items():
            print(f"  {cls}: {count:,}")

        sampling_strategy = {}
        for cls, count in class_counts.items():
            if count < min_samples:
                sampling_strategy[cls] = min_samples
            elif count > max_samples:
                sampling_strategy[cls] = max_samples
            else:
                sampling_strategy[cls] = count

        print("\nTarget distribution:")
        for cls, target in sampling_strategy.items():
            original = class_counts[cls]
            change = "? oversample" if target > original else "? undersample" if target < original else "? unchanged"
            print(f"  {cls}: {original:,} ? {target:,} {change}")

        minority_classes = [cls for cls, count in class_counts.items() if count < min_samples]
        if minority_classes:
            print(f"\nOversampling {len(minority_classes)} minority classes...")
            oversample_strategy = {cls: sampling_strategy[cls] for cls in minority_classes}
            oversampler = RandomOverSampler(sampling_strategy=oversample_strategy, random_state=CONFIG["random_state"])
            X_resampled, y_resampled = oversampler.fit_resample(X, y)
        else:
            X_resampled, y_resampled = X, y

        majority_classes = [cls for cls, count in class_counts.items() if count > max_samples]
        if majority_classes:
            print(f"Undersampling {len(majority_classes)} majority classes...")
            undersample_strategy = {cls: sampling_strategy[cls] for cls in majority_classes}
            undersampler = RandomUnderSampler(sampling_strategy=undersample_strategy, random_state=CONFIG["random_state"])
            X_balanced, y_balanced = undersampler.fit_resample(X_resampled, y_resampled)
        else:
            X_balanced, y_balanced = X_resampled, y_resampled

    elif balance_method == "undersample":
        min_samples = CONFIG.get("min_samples_per_class", 10000)
        class_counts = y.value_counts()
        target_size = max(class_counts.min(), min_samples)
        print(f"  Target samples per class: {target_size:,}")
        sampler = RandomUnderSampler(
            sampling_strategy={cls: min(count, target_size) for cls, count in class_counts.items()},
            random_state=CONFIG["random_state"],
        )
        X_balanced, y_balanced = sampler.fit_resample(X, y)

    elif balance_method == "oversample":
        sampler = RandomOverSampler(random_state=CONFIG["random_state"])
        X_balanced, y_balanced = sampler.fit_resample(X, y)

    elif balance_method == "smote":
        sampler = SMOTE(random_state=CONFIG["random_state"], k_neighbors=5)
        X_balanced, y_balanced = sampler.fit_resample(X, y)

    else:
        X_balanced, y_balanced = X, y
        print("No balancing applied.")

    if isinstance(X_balanced, np.ndarray):
        X_balanced = pd.DataFrame(X_balanced, columns=X.columns)
    if isinstance(y_balanced, np.ndarray):
        y_balanced = pd.Series(y_balanced)

    for col in X_balanced.columns:
        X_balanced[col] = X_balanced[col].astype("float32")

    print(f"\nBefore: {len(X):,} samples")
    print(f"After: {len(X_balanced):,} samples")
    print("Final balanced distribution:")
    print(pd.Series(y_balanced).value_counts())

    gc.collect()

    balanced_df = X_balanced.copy()
    balanced_df["Label"] = y_balanced.values
    return balanced_df


# ----------------------------- stage 5: split

def split_data(df: pd.DataFrame, test_size: float) -> Dict[str, object]:
    from sklearn.model_selection import train_test_split

    split_method = CONFIG.get("split_method", "random")
    split_cols = ["_day", "_src_ip"]
    X = df.drop("Label", axis=1)
    y = df["Label"]

    if split_method == "by_day" and "_day" in X.columns:
        days = sorted(X["_day"].unique())
        holdout_count = max(1, int(len(days) * test_size))
        test_days = set(days[-holdout_count:])
        train_mask = ~X["_day"].isin(test_days)
        X_train, X_test = X[train_mask], X[~train_mask]
        y_train, y_test = y[train_mask], y[~train_mask]
    elif split_method == "by_source_ip" and "_src_ip" in X.columns:
        ips = sorted(X["_src_ip"].unique())
        holdout_count = max(1, int(len(ips) * test_size))
        test_ips = set(ips[-holdout_count:])
        train_mask = ~X["_src_ip"].isin(test_ips)
        X_train, X_test = X[train_mask], X[~train_mask]
        y_train, y_test = y[train_mask], y[~train_mask]
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=CONFIG["random_state"],
            stratify=y,
        )

    for col in split_cols:
        if col in X_train.columns:
            X_train = X_train.drop(columns=[col])
        if col in X_test.columns:
            X_test = X_test.drop(columns=[col])

    print(f"Train: {len(X_train):,} samples")
    print(f"Test: {len(X_test):,} samples")

    return {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "feature_columns": list(X.columns),
    }


# ----------------------------- stage 6: scaling

def scale_data(split_payload: Dict[str, object]) -> Dict[str, object]:
    from sklearn.preprocessing import MinMaxScaler, RobustScaler, StandardScaler

    scaler_type = CONFIG.get("scaler_type", "none")
    if scaler_type == "none":
        print("No scaling applied.")
        return split_payload

    X_train = split_payload["X_train"]
    X_test = split_payload["X_test"]

    if scaler_type == "standard":
        scaler = StandardScaler()
    elif scaler_type == "minmax":
        scaler = MinMaxScaler()
    else:
        scaler = RobustScaler()

    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    payload = dict(split_payload)
    payload["X_train"] = X_train_scaled
    payload["X_test"] = X_test_scaled
    payload["scaler"] = scaler

    print(f"Scaling applied: {scaler_type}")
    return payload


# ----------------------------- stage 7: training

def train_model(
    split_payload: Dict[str, object],
    paths: Paths,
    feature_columns: Optional[List[str]] = None,
) -> Dict[str, object]:
    try:
        import xgboost as xgb
    except Exception as exc:  # pragma: no cover
        raise SystemExit("xgboost is required for training.") from exc

    from sklearn.preprocessing import LabelEncoder

    X_train = split_payload["X_train"]
    y_train = split_payload["y_train"]

    target_type = CONFIG.get("target_type", "multiclass")
    normal_label = "Normal" if CONFIG.get("use_simplified") else "Benign"

    encoder = LabelEncoder()

    if target_type == "binary":
        y_train_enc = (y_train != normal_label).astype(int)
        num_class = 2
        objective = "binary:logistic"
        eval_metric = "aucpr"
        encoder.fit([0, 1])
    else:
        y_train_enc = encoder.fit_transform(y_train)
        num_class = len(encoder.classes_)
        objective = "multi:softprob"
        eval_metric = "mlogloss"

    params = CONFIG.get("model_params", {})

    model = xgb.XGBClassifier(
        objective=objective,
        eval_metric=eval_metric,
        n_estimators=params.get("n_estimators", 400),
        max_depth=params.get("max_depth", 6),
        learning_rate=params.get("learning_rate", 0.1),
        subsample=params.get("subsample", 0.8),
        colsample_bytree=params.get("colsample_bytree", 0.8),
        min_child_weight=params.get("min_child_weight", 1.0),
        tree_method=params.get("tree_method", "hist"),
    )

    if target_type == "multiclass":
        model.set_params(num_class=num_class)

    model.fit(X_train, y_train_enc)

    paths.model_dir.mkdir(parents=True, exist_ok=True)
    model.save_model(str(paths.model_path))
    if target_type == "binary":
        save_pickle(encoder, paths.encoder_binary_path)
    else:
        save_pickle(encoder, paths.encoder_category_path)

    classes = getattr(encoder, "classes_", [])
    if hasattr(classes, "tolist"):
        classes = classes.tolist()

    print(f"Model saved to {paths.model_path}")
    return {
        "model_path": str(paths.model_path),
        "encoder_binary_path": str(paths.encoder_binary_path)
        if target_type == "binary"
        else None,
        "encoder_category_path": str(paths.encoder_category_path)
        if target_type != "binary"
        else None,
        "classes": classes,
        "target_type": target_type,
        "feature_columns": feature_columns or list(getattr(X_train, "columns", [])),
    }


# ----------------------------- stage 8: evaluation

def evaluate_model(split_payload: Dict[str, object], paths: Paths, training_meta: Dict[str, object]) -> None:
    from sklearn.metrics import classification_report, confusion_matrix
    try:
        import xgboost as xgb
    except Exception as exc:  # pragma: no cover
        raise SystemExit("xgboost is required for evaluation.") from exc

    model = xgb.XGBClassifier()
    model.load_model(str(paths.model_path))

    X_test = split_payload["X_test"]
    y_test = split_payload["y_test"]

    target_type = training_meta.get("target_type", CONFIG.get("target_type", "multiclass"))
    normal_label = "Normal" if CONFIG.get("use_simplified") else "Benign"

    if target_type == "binary":
        y_true = (y_test != normal_label).astype(int)
        y_pred = (model.predict(X_test) > 0.5).astype(int)
    else:
        encoder = load_pickle(paths.encoder_category_path)
        y_true = encoder.transform(y_test)
        y_pred = model.predict(X_test).astype(int)

    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()

    payload = {
        "report": report,
        "confusion_matrix": cm,
        "target_type": target_type,
        "feature_columns": training_meta.get("feature_columns") or load_feature_columns(paths),
    }

    paths.model_dir.mkdir(parents=True, exist_ok=True)
    paths.metrics_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Evaluation saved to {paths.metrics_path}")


# ----------------------------- metadata

def write_metadata(paths: Paths, data_dir: Path, selected_features: List[str]) -> None:
    payload = {
        "data_dir": str(data_dir),
        "selected_features": selected_features,
        "use_simplified": CONFIG["use_simplified"],
        "days_to_load": CONFIG["days_to_load"],
        "balance_method": CONFIG["balance_method"],
        "scaler_type": CONFIG["scaler_type"],
        "target_type": CONFIG["target_type"],
        "model_type": CONFIG["model_type"],
        "split_method": CONFIG.get("split_method", "random"),
    }
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    paths.metadata_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ----------------------------- stages

def stage_discover(data_dir: Optional[Path]) -> None:
    resolved = discover_dataset_dir(data_dir)
    print(f"Dataset directory: {resolved}")
    csv_files = list_csv_files(resolved)
    print(f"Found {len(csv_files)} CSV files:")
    for f in csv_files:
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"  - {f.name:20s} ({size_mb:>6.1f} MB)")


def stage_load(args, paths: Paths) -> None:
    data_dir = discover_dataset_dir(args.data_dir)
    days = args.days if args.days else CONFIG["days_to_load"]
    print("Configuration:")
    print(f"  Days to load: {len(days)}")
    print(f"  Fill NaN value: {args.fill_na}")
    print(f"  Drop NaN rows: {args.drop_na}")

    df = load_days(
        data_dir,
        days,
        args.chunksize,
        args.fill_na,
        args.drop_na,
        CONFIG.get("split_method", "random"),
    )
    save_frame(df, paths.stage1_path)
    write_metadata(paths, data_dir, [])
    print(f"Saved combined dataset to: {paths.stage1_path}")


def stage_select(paths: Paths) -> None:
    df = load_frame(paths.stage1_path)
    filtered, selected = select_features(df)
    save_frame(filtered, paths.stage2_path)
    write_metadata(paths, discover_dataset_dir(None), selected)
    print(f"Saved selected feature dataset to: {paths.stage2_path}")


def stage_finalize(paths: Paths) -> None:
    df = load_frame(paths.stage2_path)
    if CONFIG["use_simplified"]:
        print("Applying simplified label mapping...")
        df = simplify_labels(df)
        print(f"Classes: {df['Label'].nunique()} unique values")

    final_df = finalize_preprocessing(df)
    save_frame(final_df, paths.stage3_path)
    print(f"Saved final preprocessed dataset to: {paths.stage3_path}")


def stage_balance(paths: Paths) -> None:
    df = load_frame(paths.stage3_path)
    balanced = balance_classes(df)
    save_frame(balanced, paths.stage4_path)
    print(f"Saved balanced dataset to: {paths.stage4_path}")


def stage_split(paths: Paths) -> None:
    df = load_frame(paths.stage4_path if paths.stage4_path.exists() else paths.stage3_path)
    split_payload = split_data(df, CONFIG["test_size"])
    paths.split_dir.mkdir(parents=True, exist_ok=True)
    save_frame(split_payload["X_train"], paths.split_dir / "X_train.pkl")
    save_frame(split_payload["X_test"], paths.split_dir / "X_test.pkl")
    save_pickle(split_payload["y_train"], paths.split_dir / "y_train.pkl")
    save_pickle(split_payload["y_test"], paths.split_dir / "y_test.pkl")
    (paths.split_dir / "feature_columns.json").write_text(
        json.dumps(split_payload["feature_columns"], indent=2), encoding="utf-8"
    )
    print(f"Saved split datasets to: {paths.split_dir}")


def stage_scale(paths: Paths) -> None:
    X_train = load_frame(paths.split_dir / "X_train.pkl")
    X_test = load_frame(paths.split_dir / "X_test.pkl")
    y_train = load_pickle(paths.split_dir / "y_train.pkl")
    y_test = load_pickle(paths.split_dir / "y_test.pkl")

    split_payload = {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
    }

    scaled_payload = scale_data(split_payload)
    save_pickle(scaled_payload, paths.scale_path)
    print(f"Saved scaled dataset to: {paths.scale_path}")


def stage_train(paths: Paths) -> Dict[str, object]:
    if paths.scale_path.exists():
        split_payload = load_pickle(paths.scale_path)
    else:
        split_payload = {
            "X_train": load_frame(paths.split_dir / "X_train.pkl"),
            "X_test": load_frame(paths.split_dir / "X_test.pkl"),
            "y_train": load_pickle(paths.split_dir / "y_train.pkl"),
            "y_test": load_pickle(paths.split_dir / "y_test.pkl"),
        }

    feature_columns = load_feature_columns(paths)
    training_meta = train_model(split_payload, paths, feature_columns=feature_columns)
    baseline_stats = compute_baseline_stats(split_payload["X_train"], feature_columns)
    update_model_metadata(
        paths,
        {
            "dataset": "cicids2018_packet",
            "feature_columns": training_meta.get("feature_columns") or feature_columns,
            "categorical_features": [],
            "split_method": CONFIG.get("split_method", "random"),
            "target_type": training_meta.get("target_type"),
            "model_type": CONFIG.get("model_type"),
            "use_simplified": CONFIG.get("use_simplified"),
            "baseline_stats": baseline_stats,
        },
    )
    return training_meta


def stage_train_anomaly(paths: Paths) -> None:
    try:
        from sklearn.ensemble import IsolationForest
        from joblib import dump as joblib_dump
    except Exception as exc:  # pragma: no cover
        raise SystemExit("scikit-learn and joblib are required for anomaly training.") from exc

    if paths.scale_path.exists():
        split_payload = load_pickle(paths.scale_path)
    else:
        split_payload = {
            "X_train": load_frame(paths.split_dir / "X_train.pkl"),
            "X_test": load_frame(paths.split_dir / "X_test.pkl"),
            "y_train": load_pickle(paths.split_dir / "y_train.pkl"),
            "y_test": load_pickle(paths.split_dir / "y_test.pkl"),
        }

    X_train = split_payload["X_train"]
    y_train = split_payload["y_train"]
    feature_columns = load_feature_columns(paths)

    normal_label = "Normal" if CONFIG.get("use_simplified") else "Benign"
    mask = None
    try:
        if isinstance(y_train, pd.Series):
            mask = y_train == normal_label
        else:
            y_array = np.asarray(y_train)
            mask = y_array == normal_label
    except Exception:
        mask = None

    if mask is not None and np.any(mask):
        if isinstance(X_train, pd.DataFrame):
            X_fit = X_train.loc[mask]
        else:
            X_fit = np.asarray(X_train)[mask]
        print(f"Training Isolation Forest on normal samples: {len(X_fit):,}")
    else:
        X_fit = X_train
        print("Training Isolation Forest on full training set.")

    if isinstance(X_fit, pd.DataFrame):
        X_fit = X_fit.values
    X_fit = np.asarray(X_fit, dtype=np.float32)

    contamination = float(CONFIG.get("anomaly_contamination", 0.01))
    n_estimators = int(CONFIG.get("anomaly_n_estimators", 200))

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=CONFIG.get("random_state", 42),
    )
    model.fit(X_fit)
    scores = model.decision_function(X_fit)
    try:
        threshold = float(np.quantile(scores, contamination))
    except Exception:
        threshold = float(np.min(scores)) if len(scores) else 0.0

    paths.model_dir.mkdir(parents=True, exist_ok=True)
    joblib_dump(model, paths.model_dir / "anomaly_isoforest.joblib")
    print(f"Anomaly model saved to {paths.model_dir / 'anomaly_isoforest.joblib'}")

    update_model_metadata(
        paths,
        {
            "dataset": "cicids2018_packet",
            "feature_columns": feature_columns or list(getattr(X_train, "columns", [])),
            "categorical_features": [],
            "split_method": "random",
            "thresholds": {
                "isolation_forest": {
                    "score_threshold": threshold,
                    "contamination": contamination,
                }
            },
        },
    )


def stage_evaluate(paths: Paths, training_meta: Dict[str, object]) -> None:
    if paths.scale_path.exists():
        split_payload = load_pickle(paths.scale_path)
    else:
        split_payload = {
            "X_train": load_frame(paths.split_dir / "X_train.pkl"),
            "X_test": load_frame(paths.split_dir / "X_test.pkl"),
            "y_train": load_pickle(paths.split_dir / "y_train.pkl"),
            "y_test": load_pickle(paths.split_dir / "y_test.pkl"),
        }

    evaluate_model(split_payload, paths, training_meta)
    metrics_payload = load_json(paths.metrics_path)
    if metrics_payload:
        write_model_card(paths, metrics_payload)


# ----------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CICIDS 2018 stepwise pipeline")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for intermediate outputs",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=DEFAULT_MODEL_DIR,
        help="Directory for model artifacts (default: models/cicids2018_packet)",
    )

    subparsers = parser.add_subparsers(dest="stage", required=True)

    discover = subparsers.add_parser("discover", help="Discover dataset directory and list CSVs")
    discover.add_argument("--data-dir", type=Path, default=None)

    load = subparsers.add_parser("load", help="Load selected CSVs and save combined dataset")
    load.add_argument("--data-dir", type=Path, default=None)
    load.add_argument("--chunksize", type=int, default=50000)
    load.add_argument("--days", nargs="*", default=None)
    load.add_argument("--fill-na", type=float, default=0.0)
    load.add_argument("--drop-na", action="store_true")

    subparsers.add_parser("select", help="Select 17 packet-compatible features")
    subparsers.add_parser("finalize", help="Finalize preprocessing")
    subparsers.add_parser("balance", help="Balance classes (oversample/undersample)")
    subparsers.add_parser("split", help="Train/test split")
    subparsers.add_parser("scale", help="Scale features")
    subparsers.add_parser("train", help="Train model")
    subparsers.add_parser("train-anomaly", help="Train Isolation Forest anomaly model")
    subparsers.add_parser("evaluate", help="Evaluate model")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    paths = Paths(output_dir=args.output_dir, model_dir=args.model_dir)

    training_meta: Dict[str, object] = {}

    if args.stage == "discover":
        stage_discover(getattr(args, "data_dir", None))
    elif args.stage == "load":
        stage_load(args, paths)
    elif args.stage == "select":
        stage_select(paths)
    elif args.stage == "finalize":
        stage_finalize(paths)
    elif args.stage == "balance":
        stage_balance(paths)
    elif args.stage == "split":
        stage_split(paths)
    elif args.stage == "scale":
        stage_scale(paths)
    elif args.stage == "train":
        training_meta = stage_train(paths)
        (paths.model_dir / "train_metadata.json").write_text(
            json.dumps(_json_safe(training_meta), indent=2), encoding="utf-8"
        )
    elif args.stage == "train-anomaly":
        stage_train_anomaly(paths)
    elif args.stage == "evaluate":
        train_meta_path = paths.model_dir / "train_metadata.json"
        if train_meta_path.exists():
            training_meta = json.loads(train_meta_path.read_text(encoding="utf-8"))
        stage_evaluate(paths, training_meta)


if __name__ == "__main__":
    main()
