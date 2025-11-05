import os
from dotenv import load_dotenv
load_dotenv()
from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    # Server settings
    HOST: str = '0.0.0.0'
    PORT: int = 8000
    DEBUG: bool = False
    
    # MongoDB settings
    MONGO_USER: str
    MONGO_PASSWORD: str
    MONGO_CLUSTER: str
    MONGO_DB: str = 'Users'
    MONGODB_URI: Optional[str] = None
    
    # Packet Capture
    ENABLE_PACKET_CAPTURE: bool = False
    NETWORK_INTERFACE: str = 'auto'
    CAPTURE_FILTER: str = 'tcp or udp'
    
    # Redis
    ENABLE_REDIS: bool = False
    REDIS_HOST: str = 'localhost'
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    
    # Detection settings
    CONFIDENCE_THRESHOLD: float = 0.7
    MODEL_PATH: str = 'models/'
    RETRAIN_THRESHOLD: int = 100
    
    # Mitigation settings
    ENABLE_REAL_MITIGATION: bool = False
    MITIGATION_CONFIRMATION_TOKEN: Optional[str] = None
    BLOCK_DURATION: int = 300
    
    # Sensor settings
    SENSOR_LOCATIONS: List[str] = ['edge', 'internal']
    
    # Security
    PAYLOAD_SNIPPET_MAX: int = 512
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60
    
    # Logging
    LOG_LEVEL: str = 'INFO'
    LOG_FILE: str = 'logs/ids.log'
    
    # Computed properties
    @property
    def MONGO_URI_COMPUTED(self) -> str:
        if self.MONGODB_URI:
            return self.MONGODB_URI
        return (
            f'mongodb+srv://{self.MONGO_USER}:{self.MONGO_PASSWORD}@{self.MONGO_CLUSTER}/{self.MONGO_DB}'
            '?retryWrites=true&w=majority'
        )
    
    class Config:
        env_file = '.env'
        case_sensitive = True
        protected_namespaces = ('settings_',)

# Global settings instance
settings = Settings()