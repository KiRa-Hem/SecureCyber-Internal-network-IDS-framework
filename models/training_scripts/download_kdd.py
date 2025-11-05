#!/usr/bin/env python3
"""
Download KDD Cup 99 dataset for training IDS/IPS models
"""

import os
import sys
import urllib.request
import tarfile
import shutil
from pathlib import Path

def download_file(url, file_path):
    """Download a file from URL"""
    print(f"Downloading {url}...")
    try:
        with urllib.request.urlopen(url) as response, open(file_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        print(f"Downloaded to {file_path}")
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def extract_tarfile(tar_path, extract_path):
    """Extract a tar.gz file"""
    print(f"Extracting {tar_path} to {extract_path}...")
    try:
        with tarfile.open(tar_path) as tar:
            tar.extractall(path=extract_path)
        print(f"Extracted to {extract_path}")
        return True
    except Exception as e:
        print(f"Error extracting {tar_path}: {e}")
        return False

def main():
    # Create data directory if it doesn't exist
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)
    
    # KDD Cup 99 dataset URLs
    kdd_url = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
    kdd_test_url = "http://kdd.ics.uci.edu/databases/kddcup99/corrected.gz"
    
    # Download paths
    kdd_gz_path = data_dir / "kddcup.data_10_percent.gz"
    kdd_path = data_dir / "kddcup.data_10_percent"
    
    kdd_test_gz_path = data_dir / "corrected.gz"
    kdd_test_path = data_dir / "corrected"
    
    # Download training data
    if not kdd_path.exists():
        if not kdd_gz_path.exists():
            if not download_file(kdd_url, kdd_gz_path):
                sys.exit(1)
        
        # Extract the file
        import gzip
        print(f"Extracting {kdd_gz_path}...")
        try:
            with gzip.open(kdd_gz_path, 'rb') as f_in:
                with open(kdd_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            print(f"Extracted to {kdd_path}")
        except Exception as e:
            print(f"Error extracting {kdd_gz_path}: {e}")
            sys.exit(1)
    else:
        print(f"Training data already exists at {kdd_path}")
    
    # Download test data
    if not kdd_test_path.exists():
        if not kdd_test_gz_path.exists():
            if not download_file(kdd_test_url, kdd_test_gz_path):
                sys.exit(1)
        
        # Extract the file
        import gzip
        print(f"Extracting {kdd_test_gz_path}...")
        try:
            with gzip.open(kdd_test_gz_path, 'rb') as f_in:
                with open(kdd_test_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            print(f"Extracted to {kdd_test_path}")
        except Exception as e:
            print(f"Error extracting {kdd_test_gz_path}: {e}")
            sys.exit(1)
    else:
        print(f"Test data already exists at {kdd_test_path}")
    
    print("KDD Cup 99 dataset download complete!")

if __name__ == "__main__":
    main()