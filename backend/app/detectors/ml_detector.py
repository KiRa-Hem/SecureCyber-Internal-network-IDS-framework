import uuid
import pickle
import os
from datetime import datetime
from typing import Dict, Any, Optional

class MLDetector:
    def __init__(self, model_path: str = None):
        self.model_path = model_path or os.path.join("models", "model.pkl")
        self.model = None
        self._load_model()
    
    def _load_model(self):
        """Load the ML model if it exists."""
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)
    
    def detect(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect attacks using ML model.
        Returns alert data if an attack is detected, None otherwise.
        """
        # If no model is available, return None
        if not self.model:
            return None
        
        # Extract features from packet data
        features = self._extract_features(packet_data)
        
        # Make prediction
        try:
            prediction = self.model.predict([features])[0]
            probability = max(self.model.predict_proba([features])[0])
            
            # If attack is detected
            if prediction == 1:  # Assuming 1 is the attack class
                confidence = int(probability * 100)
                
                return {
                    "id": str(uuid.uuid4()),
                    "timestamp": int(datetime.now().timestamp()),
                    "source_ip": packet_data.get("source_ip", ""),
                    "dest_ip": packet_data.get("dest_ip", ""),
                    "attacks": ["Anomalous Traffic"],
                    "attack_types_short": ["Anomaly"],
                    "confidence": confidence,
                    "payload_snippet": "ML-detected anomalous traffic pattern",
                    "path": packet_data.get("path", []),
                    "area_of_effect": packet_data.get("area_of_effect", {"nodes": [], "radius": 0}),
                    "mitigation": {"action": "flagged", "by": "ml-detector"},
                    "packets_analyzed": 1
                }
        except Exception as e:
            # Log error and continue
            print(f"ML prediction error: {e}")
        
        return None
    
    def _extract_features(self, packet_data: Dict[str, Any]) -> list:
        """
        Extract features from packet data for ML model.
        This is a simplified version - in a real implementation, 
        you would extract more meaningful features.
        """
        payload = packet_data.get("payload", "")
        
        # Simple features (in a real implementation, these would be more sophisticated)
        features = [
            len(payload),  # Payload length
            payload.count(";"),  # Number of semicolons
            payload.count("'"),  # Number of single quotes
            payload.count('"'),  # Number of double quotes
            payload.count("<"),  # Number of opening angle brackets
            payload.count(">"),  # Number of closing angle brackets
            payload.count("/"),  # Number of forward slashes
            payload.count("\\"),  # Number of backslashes
            payload.count(" "),  # Number of spaces
            payload.count("="),  # Number of equals signs
        ]
        
        return features