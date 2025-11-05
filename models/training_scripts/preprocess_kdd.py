#!/usr/bin/env python3
"""
Preprocess KDD Cup 99 dataset for training IDS/IPS models
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
import pickle

def load_data(file_path):
    """Load KDD Cup 99 dataset"""
    print(f"Loading data from {file_path}...")
    
    # Define column names
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
    
    # Define which columns should be numeric
    numeric_cols = [
        'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
        'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]
    
    # Load data with explicit handling for mixed types
    try:
        # First, load without dtype specification to see what we have
        data = pd.read_csv(file_path, names=column_names, header=None, low_memory=False)
        print(f"Loaded {len(data)} records")
        
        # Check for non-numeric values in numeric columns
        print("Checking for non-numeric values in numeric columns...")
        for col in numeric_cols:
            if col in data.columns:
                # Try to convert to numeric, set errors='coerce' to convert non-numeric to NaN
                data[col] = pd.to_numeric(data[col], errors='coerce')
        
        # Count how many NaN values we have in each numeric column
        nan_counts = data[numeric_cols].isna().sum()
        print("NaN counts in numeric columns after conversion:")
        for col, count in nan_counts.items():
            if count > 0:
                print(f"  {col}: {count} NaN values")
        
        # Drop rows with NaN values in numeric columns
        initial_count = len(data)
        data = data.dropna(subset=numeric_cols)
        final_count = len(data)
        
        print(f"Dropped {initial_count - final_count} rows with NaN values in numeric columns")
        print(f"Remaining records: {final_count}")
        
        return data
    except Exception as e:
        print(f"Error loading data: {e}")
        return None

def preprocess_data(data):
    """Preprocess KDD Cup 99 dataset"""
    print("Preprocessing data...")
    
    # Create a copy of the data
    df = data.copy()
    
    # Map labels to binary classification (normal vs attack)
    df['binary_label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Map labels to attack categories
    attack_categories = {
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
        'worm': 'r2l',
        
        'buffer_overflow': 'u2r',
        'loadmodule': 'u2r',
        'perl': 'u2r',
        'rootkit': 'u2r',
        'httptunnel': 'u2r',
        'ps': 'u2r',
        'sqlattack': 'u2r',
        'xterm': 'u2r'
    }
    
    df['attack_category'] = df['label'].map(attack_categories)
    
    # Handle any unmapped labels (set to 'unknown')
    df['attack_category'] = df['attack_category'].fillna('unknown')
    
    # Define categorical and numerical features
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
    
    # Ensure all numerical features are numeric
    for feature in numerical_features:
        if feature in df.columns:
            df[feature] = pd.to_numeric(df[feature], errors='coerce')
    
    # Drop rows with NaN values in numerical features
    print(f"Before cleaning numerical features: {len(df)} records")
    df = df.dropna(subset=numerical_features)
    print(f"After cleaning numerical features: {len(df)} records")
    
    # Create preprocessing pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_features),
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
        ]
    )
    
    # Fit and transform the data
    print("Fitting preprocessing pipeline...")
    X = df.drop(['label', 'binary_label', 'attack_category'], axis=1)
    y_binary = df['binary_label']
    y_category = df['attack_category']
    
    # Split data
    X_train, X_test, y_binary_train, y_binary_test, y_category_train, y_category_test = train_test_split(
        X, y_binary, y_category, test_size=0.2, random_state=42
    )
    
    # Fit preprocessor
    preprocessor.fit(X_train)
    
    # Transform data
    X_train_processed = preprocessor.transform(X_train)
    X_test_processed = preprocessor.transform(X_test)
    
    # Encode labels
    le_binary = LabelEncoder()
    le_category = LabelEncoder()
    
    y_binary_train_encoded = le_binary.fit_transform(y_binary_train)
    y_binary_test_encoded = le_binary.transform(y_binary_test)
    
    y_category_train_encoded = le_category.fit_transform(y_category_train)
    y_category_test_encoded = le_category.transform(y_category_test)
    
    # Save preprocessed data
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)
    
    print("Saving preprocessed data...")
    np.save(data_dir / "X_train.npy", X_train_processed)
    np.save(data_dir / "X_test.npy", X_test_processed)
    np.save(data_dir / "y_binary_train.npy", y_binary_train_encoded)
    np.save(data_dir / "y_binary_test.npy", y_binary_test_encoded)
    np.save(data_dir / "y_category_train.npy", y_category_train_encoded)
    np.save(data_dir / "y_category_test.npy", y_category_test_encoded)
    
    # Save preprocessors and encoders
    with open(data_dir / "preprocessor.pkl", 'wb') as f:
        pickle.dump(preprocessor, f)
    
    with open(data_dir / "le_binary.pkl", 'wb') as f:
        pickle.dump(le_binary, f)
    
    with open(data_dir / "le_category.pkl", 'wb') as f:
        pickle.dump(le_category, f)
    
    print("Preprocessing complete!")
    return X_train_processed, X_test_processed, y_binary_train_encoded, y_binary_test_encoded, y_category_train_encoded, y_category_test_encoded

def main():
    # Get paths
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)
    
    kdd_path = data_dir / "kddcup.data_10_percent"
    
    # Load data
    data = load_data(kdd_path)
    if data is None:
        sys.exit(1)
    
    # Preprocess data
    preprocess_data(data)

if __name__ == "__main__":
    main()