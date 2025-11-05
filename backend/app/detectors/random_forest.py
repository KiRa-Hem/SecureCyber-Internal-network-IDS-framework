import os
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import logging

from app.config import settings

logger = logging.getLogger(__name__)

class RandomForestDetector:
    def __init__(self, model_path: str = None):
        self.model_path = model_path or os.path.join("models", "attack_classifier_rf.pkl")
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
            'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
            'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        self.categorical_features = ['protocol_type', 'service', 'flag']
        
        self._load_model()
    
    def _load_model(self):
        """Load the trained model."""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                logger.info(f"RandomForest model loaded from {self.model_path}")
            else:
                logger.warning(f"Model file not found at {self.model_path}")
                self.model = None
        except Exception as e:
            logger.error(f"Error loading RandomForest model: {e}")
            self.model = None
    
    def train(self, X: pd.DataFrame, y: pd.Series):
        """Train the RandomForest model."""
        logger.info("Training RandomForest model...")
        
        # Preprocess data
        X_processed = self._preprocess_features(X, fit=True)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_processed, y, test_size=0.2, random_state=42
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        logger.info(f"Training accuracy: {train_score:.4f}")
        logger.info(f"Test accuracy: {test_score:.4f}")
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        logger.info(f"Model saved to {self.model_path}")
        
        # Save preprocessing objects
        joblib.dump(self.scaler, self.model_path.replace('.pkl', '_scaler.pkl'))
        joblib.dump(self.label_encoders, self.model_path.replace('.pkl', '_encoders.pkl'))
    
    def _preprocess_features(self, X: pd.DataFrame, fit: bool = False) -> np.ndarray:
        """Preprocess features for model input."""
        X_processed = X.copy()
        
        # Handle categorical features
        for feature in self.categorical_features:
            if feature in X_processed.columns:
                if fit:
                    if feature not in self.label_encoders:
                        self.label_encoders[feature] = LabelEncoder()
                    X_processed[feature] = self.label_encoders[feature].fit_transform(X_processed[feature])
                else:
                    if feature in self.label_encoders:
                        X_processed[feature] = self.label_encoders[feature].transform(X_processed[feature])
                    else:
                        # Handle unknown categories
                        X_processed[feature] = 0
        
        # Scale numerical features
        numerical_features = [f for f in self.feature_names if f not in self.categorical_features]
        if fit:
            X_processed[numerical_features] = self.scaler.fit_transform(X_processed[numerical_features])
        else:
            X_processed[numerical_features] = self.scaler.transform(X_processed[numerical_features])
        
        # Ensure all features are present
        for feature in self.feature_names:
            if feature not in X_processed.columns:
                X_processed[feature] = 0
        
        # Reorder columns to match training order
        X_processed = X_processed[self.feature_names]
        
        return X_processed.values
    
    def predict(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Predict if a packet is malicious."""
        if not self.model:
            logger.warning("RandomForest model not loaded")
            return None
        
        try:
            # Convert packet info to DataFrame
            df = pd.DataFrame([packet_info])
            
            # Add missing features with default values
            for feature in self.feature_names:
                if feature not in df.columns:
                    df[feature] = 0
            
            # Preprocess
            X = self._preprocess_features(df, fit=False)
            
            # Predict
            probabilities = self.model.predict_proba(X)[0]
            prediction = self.model.predict(X)[0]
            
            # Get feature importance
            feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
            
            return {
                'prediction': int(prediction),
                'probabilities': {
                    'normal': float(probabilities[0]),
                    'attack': float(probabilities[1])
                },
                'confidence': float(max(probabilities)),
                'feature_importance': feature_importance
            }
            
        except Exception as e:
            logger.error(f"Error predicting with RandomForest: {e}")
            return None
    
    def create_sample_model(self):
        """Create a small sample model for demo purposes."""
        logger.info("Creating sample RandomForest model for demo...")
        
        # Generate synthetic data
        np.random.seed(42)
        n_samples = 1000
        n_features = len(self.feature_names)
        
        # Create synthetic features
        X = pd.DataFrame(np.random.rand(n_samples, n_features), columns=self.feature_names)
        
        # Create synthetic labels (20% attacks)
        y = np.random.choice([0, 1], size=n_samples, p=[0.8, 0.2])
        
        # Add some patterns to make it more realistic
        # Attacks tend to have higher values for certain features
        attack_indices = np.where(y == 1)[0]
        X.loc[attack_indices, 'src_bytes'] = np.random.exponential(1000, size=len(attack_indices))
        X.loc[attack_indices, 'dst_bytes'] = np.random.exponential(5000, size=len(attack_indices))
        X.loc[attack_indices, 'count'] = np.random.randint(10, 100, size=len(attack_indices))
        
        # Train model
        self.train(X, y)
        
        logger.info("Sample RandomForest model created successfully")