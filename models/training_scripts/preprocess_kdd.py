#!/usr/bin/env python3
"""
Preprocess KDD Cup 99 and CICIDS datasets for training IDS/IPS models.
"""

import argparse
import pickle
import re
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

try:
    from scipy import sparse
except ImportError:  # pragma: no cover - scipy should be present with sklearn, but guard anyway.
    sparse = None

# Repository paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"

# Default dataset locations (can be overridden via CLI)
DEFAULT_DATASET_PATHS = {
    "kdd_10": DATA_DIR / "kddcup.data_10_percent",
    "kdd_full": RAW_DIR / "kdd99" / "kddcup.data",
    "cic": RAW_DIR / "cicids" / "cic.csv",
}
SUPPORTED_DATASETS = tuple(DEFAULT_DATASET_PATHS.keys())

# Attack category helpers
KDD_ATTACK_CATEGORIES = {
    'normal': 'normal',
    'back': 'dos',
    'land': 'dos',
    'neptune': 'dos',
    'pod': 'dos',
    'smurf': 'dos',
    'teardrop': 'dos',
    'mailbomb': 'dos',
    'processtable': 'dos',
    'udpstorm': 'dos',
    'apache2': 'dos',
    'worm': 'dos',
    'ipsweep': 'probe',
    'nmap': 'probe',
    'portsweep': 'probe',
    'satan': 'probe',
    'mscan': 'probe',
    'saint': 'probe',
    'ftp_write': 'r2l',
    'guess_passwd': 'r2l',
    'imap': 'r2l',
    'multihop': 'r2l',
    'phf': 'r2l',
    'spy': 'r2l',
    'warezclient': 'r2l',
    'warezmaster': 'r2l',
    'sendmail': 'r2l',
    'named': 'r2l',
    'snmpgetattack': 'r2l',
    'snmpguess': 'r2l',
    'xlock': 'r2l',
    'xsnoop': 'r2l',
    'buffer_overflow': 'u2r',
    'loadmodule': 'u2r',
    'perl': 'u2r',
    'rootkit': 'u2r',
    'httptunnel': 'u2r',
    'ps': 'u2r',
    'sqlattack': 'u2r',
    'xterm': 'u2r'
}

CIC_CATEGORY_RULES = [
    ("dos", ("ddos", "dos", "slowloris", "slowhttptest", "goldeneye", "hulk", "heartbleed")),
    ("bruteforce", ("bruteforce", "patator")),
    ("web", ("web", "xss", "sql", "shell")),
    ("botnet", ("bot",)),
    ("infiltration", ("infiltration",)),
    ("probe", ("scan", "portscan")),
    ("malware", ("trojan", "worm")),
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Preprocess IDS datasets (KDD Cup 99 or CICIDS)."
    )
    parser.add_argument(
        "--dataset",
        choices=SUPPORTED_DATASETS,
        default="kdd_10",
        help="Which dataset schema to expect (default: kdd_10)."
    )
    parser.add_argument(
        "--input-file",
        type=Path,
        help="Optional explicit path to the raw dataset file."
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of data to reserve for testing (default: 0.2)."
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Optional cap on the number of rows to load (useful for smoke tests)."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DATA_DIR,
        help="Directory where processed artifacts should be written (default: models/training_scripts/data)."
    )
    return parser.parse_args()


def normalize_column_name(name: str) -> str:
    """Normalize CICIDS column names to snake_case."""
    normalized = re.sub(r'[^0-9a-zA-Z]+', '_', name.strip().lower())
    normalized = normalized.strip('_')
    if not normalized:
        return "unnamed_column"
    if normalized[0].isdigit():
        normalized = f"col_{normalized}"
    return normalized


def ensure_dense(matrix):
    """Convert scipy sparse matrices to dense numpy arrays when needed."""
    if sparse is not None and sparse.issparse(matrix):
        return matrix.toarray()
    return matrix


def save_artifacts(
    output_dir: Path,
    X_train,
    X_test,
    y_binary_train,
    y_binary_test,
    y_category_train,
    y_category_test,
    preprocessor,
    le_binary,
    le_category,
):
    """Persist numpy arrays and encoders."""
    output_dir.mkdir(exist_ok=True)
    X_train = ensure_dense(X_train)
    X_test = ensure_dense(X_test)
    print(f"Saving preprocessed artifacts to {output_dir} ...")
    np.save(output_dir / "X_train.npy", X_train)
    np.save(output_dir / "X_test.npy", X_test)
    np.save(output_dir / "y_binary_train.npy", y_binary_train)
    np.save(output_dir / "y_binary_test.npy", y_binary_test)
    np.save(output_dir / "y_category_train.npy", y_category_train)
    np.save(output_dir / "y_category_test.npy", y_category_test)

    with open(output_dir / "preprocessor.pkl", "wb") as f:
        pickle.dump(preprocessor, f)
    with open(output_dir / "le_binary.pkl", "wb") as f:
        pickle.dump(le_binary, f)
    with open(output_dir / "le_category.pkl", "wb") as f:
        pickle.dump(le_category, f)


def track_dataset_cleaning(df: pd.DataFrame, numeric_cols):
    """Log how much data was dropped when cleaning NaNs."""
    nan_counts = df[numeric_cols].isna().sum()
    if nan_counts.any():
        print("NaN counts in numeric columns after conversion:")
        for col, count in nan_counts.items():
            if count > 0:
                print(f"  {col}: {count} NaN values")


def load_kdd_data(file_path: Path, nrows: Optional[int] = None) -> pd.DataFrame:
    """Load the raw KDD Cup 99 dataset, cleaning numeric columns as needed."""
    print(f"Loading KDD data from {file_path} ...")
    column_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
        'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
        'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
    ]
    numeric_cols = [col for col in column_names if col not in {'protocol_type', 'service', 'flag', 'label'}]
    data = pd.read_csv(
        file_path,
        names=column_names,
        header=None,
        low_memory=False,
        nrows=nrows
    )
    print(f"Loaded {len(data)} rows")

    for col in numeric_cols:
        data[col] = pd.to_numeric(data[col], errors='coerce')

    track_dataset_cleaning(data, numeric_cols)
    before = len(data)
    data = data.dropna(subset=numeric_cols)
    print(f"Dropped {before - len(data)} rows with invalid numeric values")

    data['label'] = data['label'].astype(str).str.strip().str.rstrip('.')
    return data


def categorize_cic_label(label: str) -> str:
    label_clean = str(label).strip().lower()
    if not label_clean or label_clean == 'nan':
        return 'unknown'
    if label_clean == 'benign':
        return 'normal'
    for category, keywords in CIC_CATEGORY_RULES:
        if any(keyword in label_clean for keyword in keywords):
            return category
    return 'unknown'


def load_cic_data(file_path: Path, nrows: Optional[int] = None) -> pd.DataFrame:
    """Load the CICIDS dataset and normalize column names."""
    print(f"Loading CICIDS data from {file_path} ...")
    df = pd.read_csv(file_path, nrows=nrows, low_memory=False)
    print(f"Loaded {len(df)} rows")
    df.columns = [normalize_column_name(col) for col in df.columns]

    if 'label' not in df.columns:
        raise ValueError("CICIDS dataset must include a 'Label' column.")

    # Timestamp is textual and not currently used as a feature.
    if 'timestamp' in df.columns:
        df = df.drop(columns=['timestamp'])

    numeric_cols = [col for col in df.columns if col != 'label']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    track_dataset_cleaning(df, numeric_cols)
    before = len(df)
    df = df.dropna(subset=numeric_cols)
    print(f"Dropped {before - len(df)} rows with invalid numeric values")
    return df


def preprocess_kdd_data(df: pd.DataFrame, output_dir: Path, test_size: float):
    """Preprocess KDD data (categorical + numeric features)."""
    print("Preprocessing KDD dataset ...")
    df = df.copy()
    df['binary_label'] = (df['label'] != 'normal').astype(int)
    df['attack_category'] = df['label'].map(KDD_ATTACK_CATEGORIES).fillna('unknown')

    categorical_features = ['protocol_type', 'service', 'flag']
    numerical_features = [
        'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
        'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]

    for feature in numerical_features:
        df[feature] = pd.to_numeric(df[feature], errors='coerce')

    print(f"Records before numerical cleanup: {len(df)}")
    df = df.dropna(subset=numerical_features)
    print(f"Records after numerical cleanup: {len(df)}")

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_features),
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
        ]
    )

    X = df.drop(columns=['label', 'binary_label', 'attack_category'])
    y_binary = df['binary_label']
    y_category = df['attack_category']

    stratify_target = y_category if y_category.nunique() > 1 else None
    X_train, X_test, y_binary_train, y_binary_test, y_category_train, y_category_test = train_test_split(
        X, y_binary, y_category, test_size=test_size, random_state=42, stratify=stratify_target
    )

    preprocessor.fit(X_train)
    X_train_processed = preprocessor.transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    le_binary = LabelEncoder()
    le_category = LabelEncoder()
    y_binary_train_encoded = le_binary.fit_transform(y_binary_train)
    y_binary_test_encoded = le_binary.transform(y_binary_test)
    y_category_train_encoded = le_category.fit_transform(y_category_train)
    y_category_test_encoded = le_category.transform(y_category_test)

    save_artifacts(
        output_dir,
        X_train_processed,
        X_test_processed,
        y_binary_train_encoded,
        y_binary_test_encoded,
        y_category_train_encoded,
        y_category_test_encoded,
        preprocessor,
        le_binary,
        le_category,
    )


def preprocess_cic_data(df: pd.DataFrame, output_dir: Path, test_size: float):
    """Preprocess CICIDS data (all numeric features)."""
    print("Preprocessing CICIDS dataset ...")
    df = df.copy()
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df['binary_label'] = (df['label'] != 'benign').astype(int)
    df['attack_category'] = df['label'].apply(categorize_cic_label)

    feature_columns = [col for col in df.columns if col not in {'label', 'binary_label', 'attack_category'}]
    if not feature_columns:
        raise ValueError("No feature columns available after cleaning CICIDS dataset.")

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), feature_columns),
        ]
    )

    X = df[feature_columns]
    y_binary = df['binary_label']
    y_category = df['attack_category']

    stratify_target = y_category if y_category.nunique() > 1 else None
    X_train, X_test, y_binary_train, y_binary_test, y_category_train, y_category_test = train_test_split(
        X, y_binary, y_category, test_size=test_size, random_state=42, stratify=stratify_target
    )

    preprocessor.fit(X_train)
    X_train_processed = preprocessor.transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    le_binary = LabelEncoder()
    le_category = LabelEncoder()
    y_binary_train_encoded = le_binary.fit_transform(y_binary_train)
    y_binary_test_encoded = le_binary.transform(y_binary_test)
    y_category_train_encoded = le_category.fit_transform(y_category_train)
    y_category_test_encoded = le_category.transform(y_category_test)

    save_artifacts(
        output_dir,
        X_train_processed,
        X_test_processed,
        y_binary_train_encoded,
        y_binary_test_encoded,
        y_category_train_encoded,
        y_category_test_encoded,
        preprocessor,
        le_binary,
        le_category,
    )


def resolve_dataset_path(dataset: str, override_path: Optional[Path]) -> Path:
    if override_path:
        candidate = override_path.expanduser()
        return candidate if candidate.is_absolute() else candidate.resolve()
    return DEFAULT_DATASET_PATHS[dataset]


def resolve_output_dir(path: Path) -> Path:
    candidate = path.expanduser()
    return candidate if candidate.is_absolute() else (Path.cwd() / candidate).resolve()


def main():
    args = parse_args()
    dataset_path = resolve_dataset_path(args.dataset, args.input_file)
    if not dataset_path.exists():
        print(f"ERROR: Dataset file not found: {dataset_path}")
        sys.exit(1)

    output_dir = resolve_output_dir(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.dataset in {"kdd_10", "kdd_full"}:
        data = load_kdd_data(dataset_path, nrows=args.max_rows)
        preprocess_kdd_data(data, output_dir, args.test_size)
    else:
        data = load_cic_data(dataset_path, nrows=args.max_rows)
        preprocess_cic_data(data, output_dir, args.test_size)

    print("Preprocessing complete!")


if __name__ == "__main__":
    main()
