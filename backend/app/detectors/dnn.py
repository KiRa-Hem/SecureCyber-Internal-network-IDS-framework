import logging
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from app.config import settings

MODELS_DIR = Path(settings.model_path)

logger = logging.getLogger(__name__)

class DNN(nn.Module):
    """Deep Neural Network for attack detection."""
    
    def __init__(self, input_size: int, hidden_sizes: List[int], output_size: int):
        super(DNN, self).__init__()
        
        layers = []
        prev_size = input_size
        
        for hidden_size in hidden_sizes:
            layers.extend([
                nn.Linear(prev_size, hidden_size),
                nn.BatchNorm1d(hidden_size),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_size = hidden_size
        
        layers.append(nn.Linear(prev_size, output_size))
        
        self.model = nn.Sequential(*layers)
    
    def forward(self, x):
        return self.model(x)

class DNNDetector:
    def __init__(self, model_path: str = None):
        default_path = MODELS_DIR / "attack_classifier_dnn.pth"
        self.model_path = Path(model_path) if model_path else default_path
        self.model = None
        self.scaler: StandardScaler | None = None
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
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
        self.training_columns = list(self.feature_names)
        self.input_size = len(self.feature_names)
        self.category_encoder = None
        self.num_classes = 2
        
        self._load_label_encoder()
        self._load_model()
    def _load_label_encoder(self):
        encoder_path = MODELS_DIR / "le_category.pkl"
        if not encoder_path.exists():
            logger.warning("Category label encoder not found at %s; defaulting to binary output", encoder_path)
            return
        try:
            self.category_encoder = joblib.load(encoder_path)
            if hasattr(self.category_encoder, "classes_"):
                self.num_classes = len(self.category_encoder.classes_)
                logger.info("Loaded category label encoder (%d classes)", self.num_classes)
        except Exception as exc:
            logger.warning("Failed to load category encoder (%s); defaulting to binary output", exc)
            self.category_encoder = None

    
    def _load_model(self):
        """Load the trained model."""
        try:
            if self.model_path.exists():
                self.model = DNN(self.input_size, [128, 64, 32], self.num_classes)
                self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
                self.model.eval()
                logger.info(f"DNN model loaded from {self.model_path}")
                
                # Load preprocessing objects
                scaler_path = self.model_path.with_name(self.model_path.stem + "_scaler.pkl")
                if os.path.exists(scaler_path):
                    import joblib
                    self.scaler = joblib.load(scaler_path)
                else:
                    self.scaler = None
                    logger.warning("DNN scaler not found; using raw values")
                
                encoders_path = self.model_path.with_name(self.model_path.stem + "_encoders.pkl")
                if os.path.exists(encoders_path):
                    import joblib
                    self.label_encoders = joblib.load(encoders_path)
                else:
                    self.label_encoders = {}
            else:
                logger.warning(f"Model file not found at {self.model_path}")
                self.model = None
        except Exception as e:
            logger.error(f"Error loading DNN model: {e}")
            self.model = None
    
    def train(self, X: pd.DataFrame, y: pd.Series, epochs: int = 50, batch_size: int = 64):
        """Train the DNN model."""
        logger.info("Training DNN model...")
        
        # Preprocess data
        X_processed = self._preprocess_features(X, fit=True)
        X_tensor = torch.FloatTensor(X_processed).to(self.device)
        y_tensor = torch.LongTensor(y.values).to(self.device)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_tensor, y_tensor, test_size=0.2, random_state=42
        )
        
        # Create model
        self.model = DNN(len(self.feature_names), [128, 64, 32], 2).to(self.device)
        
        # Training setup
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        
        # Training loop
        self.model.train()
        for epoch in range(epochs):
            # Mini-batch training
            for i in range(0, len(X_train), batch_size):
                batch_X = X_train[i:i+batch_size]
                batch_y = y_train[i:i+batch_size]
                
                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
            
            # Evaluate
            if (epoch + 1) % 10 == 0:
                self.model.eval()
                with torch.no_grad():
                    train_outputs = self.model(X_train)
                    train_preds = torch.argmax(train_outputs, dim=1)
                    train_acc = (train_preds == y_train).float().mean()
                    
                    test_outputs = self.model(X_test)
                    test_preds = torch.argmax(test_outputs, dim=1)
                    test_acc = (test_preds == y_test).float().mean()
                    
                    logger.info(f"Epoch {epoch+1}/{epochs} - Train Acc: {train_acc:.4f}, Test Acc: {test_acc:.4f}")
                self.model.train()
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        torch.save(self.model.state_dict(), self.model_path)
        logger.info(f"Model saved to {self.model_path}")
        
        # Save preprocessing objects
        import joblib
        joblib.dump(self.scaler, self.model_path.replace('.pth', '_scaler.pkl'))
        joblib.dump(self.label_encoders, self.model_path.replace('.pth', '_encoders.pkl'))
    
    def _preprocess_features(self, X: pd.DataFrame, fit: bool = False) -> np.ndarray:
        """Preprocess features for model input."""
        X_processed = X.copy()

        # Ensure numeric fields are numeric
        numerical_features = [f for f in self.feature_names if f not in self.categorical_features]
        if numerical_features:
            try:
                X_processed[numerical_features] = (
                    X_processed[numerical_features]
                    .apply(pd.to_numeric, errors="coerce")
                    .fillna(0.0)
                    .astype(float)
                )
            except Exception as exc:
                logger.warning("Failed to coerce numeric DNN features (%s); filling with 0", exc)
                X_processed[numerical_features] = (
                    X_processed[numerical_features].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(float)
                )

        # Handle categorical features
        for feature in self.categorical_features:
            if feature in X_processed.columns:
                if fit:
                    if feature not in self.label_encoders:
                        self.label_encoders[feature] = LabelEncoder()
                    X_processed[feature] = self.label_encoders[feature].fit_transform(X_processed[feature].astype(str))
                else:
                    if feature in self.label_encoders:
                        mapping = {cls: idx for idx, cls in enumerate(self.label_encoders[feature].classes_)}
                        X_processed[feature] = (
                            X_processed[feature].astype(str).map(mapping).fillna(0).astype(int)
                        )
                    else:
                        X_processed[feature] = 0

        # Scale numerical features
        numerical_features = [f for f in self.feature_names if f not in self.categorical_features]
        if self.scaler:
            if fit:
                X_processed[numerical_features] = self.scaler.fit_transform(X_processed[numerical_features])
            else:
                try:
                    X_processed[numerical_features] = self.scaler.transform(X_processed[numerical_features])
                except Exception as exc:
                    logger.warning(f"DNN scaler transform failed ({exc}); using raw values")
                    self.scaler = None
        if not self.scaler:
            X_processed[numerical_features] = X_processed[numerical_features].fillna(0)
        
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
            logger.warning("DNN model not loaded")
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
            
            # Convert to tensor
            X_tensor = torch.FloatTensor(X).to(self.device)
            
            # Predict
            self.model.eval()
            with torch.no_grad():
                outputs = self.model(X_tensor)
                probabilities = torch.softmax(outputs, dim=1)[0]
                prediction = torch.argmax(outputs, dim=1).item()
            
            return {
                'prediction': prediction,
                'probabilities': {
                    'normal': float(probabilities[0]),
                    'attack': float(probabilities[1])
                },
                'confidence': float(max(probabilities))
            }
            
        except Exception as e:
            logger.error(f"Error predicting with DNN: {e}")
            return None
    
    def create_sample_model(self):
        """Create a small sample model for demo purposes."""
        logger.info("Creating sample DNN model for demo...")
        
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
        self.train(X, y, epochs=20)
        
        logger.info("Sample DNN model created successfully")
