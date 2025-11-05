import numpy as np
from typing import Dict, Any, List
import joblib
import os

class MLDetector:
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.model = None
        self.preprocessor = None
        self.le = None
        self.load_model()
    
    def load_model(self):
        """Load the trained model and preprocessors."""
        try:
            # Try to load Random Forest model
            self.model = joblib.load(os.path.join(self.model_path, "attack_classifier_rf.pkl"))
            
            # Load preprocessors
            import pickle
            with open(os.path.join(self.model_path, "preprocessor.pkl"), 'rb') as f:
                self.preprocessor = pickle.load(f)
            
            with open(os.path.join(self.model_path, "le_binary.pkl"), 'rb') as f:
                self.le = pickle.load(f)
                
            print("ML model loaded successfully")
        except Exception as e:
            print(f"Error loading ML model: {e}")
            self.model = None
    
    def extract_features(self, packet: Dict[str, Any]) -> np.ndarray:
        """Extract features from packet data."""
        features = []
        
        # Protocol type (one-hot encoded)
        protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3, 'other': 0}
        protocol = protocol_map.get(packet.get('protocol', 'other').lower(), 0)
        features.append(protocol)
        
        # Ports
        features.append(packet.get('src_port', 0))
        features.append(packet.get('dst_port', 0))
        
        # Flags
        flags = packet.get('flags', '')
        features.append(len(flags))  # Simple flag representation
        
        # Payload analysis
        payload = packet.get('payload', '')
        features.append(len(payload))  # Payload length
        
        # Check for attack patterns in payload
        attack_patterns = [
            "' OR '1'='1",  # SQL injection
            "<script>",       # XSS
            "; rm -rf",       # Command injection
            "${jndi:ldap://", # Log4j
            "../"            # Path traversal
        ]
        
        for pattern in attack_patterns:
            features.append(1 if pattern.lower() in payload.lower() else 0)
        
        # Fill with zeros if we don't have enough features
        while len(features) < 10:
            features.append(0)
        
        return np.array(features[:10]).reshape(1, -1)
    
    def detect(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Detect if packet is malicious using ML model."""
        if self.model is None:
            return {
                'is_malicious': False,
                'attack_types': [],
                'confidence': 0.0,
                'error': 'Model not loaded'
            }
        
        try:
            # Extract features
            features = self.extract_features(packet)
            
            # Preprocess features
            if self.preprocessor:
                features = self.preprocessor.transform(features)
            
            # Make prediction
            prediction = self.model.predict(features)[0]
            probability = self.model.predict_proba(features)[0]
            
            # Get confidence
            confidence = float(max(probability))
            
            # Determine attack type
            attack_types = []
            if prediction == 1:  # Malicious
                # Simple rule-based attack type detection
                payload = packet.get('payload', '').lower()
                if "' or '1'='1" in payload:
                    attack_types.append('sql_injection')
                elif '<script>' in payload:
                    attack_types.append('xss')
                elif '; rm -rf' in payload:
                    attack_types.append('command_injection')
                elif '${jndi:ldap://' in payload:
                    attack_types.append('log4j')
                elif '../' in payload:
                    attack_types.append('path_traversal')
                else:
                    attack_types.append('unknown')
            
            return {
                'is_malicious': bool(prediction),
                'attack_types': attack_types,
                'confidence': confidence
            }
        except Exception as e:
            return {
                'is_malicious': False,
                'attack_types': [],
                'confidence': 0.0,
                'error': str(e)
            }