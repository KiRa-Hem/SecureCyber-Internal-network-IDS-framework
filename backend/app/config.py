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
    CORRELATION_WINDOW_SECONDS: int = 300
    
    # Mitigation settings
    ENABLE_REAL_MITIGATION: bool = False
    MITIGATION_CONFIRMATION_TOKEN: Optional[str] = None
    BLOCK_DURATION: int = 300
    BLOCKLIST_TTL_SECONDS: int = 3600
    
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
    
    @property
    def enable_redis(self) -> bool:
        return self.ENABLE_REDIS
    
    @property
    def enable_packet_capture(self) -> bool:
        return self.ENABLE_PACKET_CAPTURE
    
    @property
    def network_interface(self) -> str:
        return self.NETWORK_INTERFACE
    
    @property
    def capture_filter(self) -> str:
        return self.CAPTURE_FILTER
    
    @property
    def sensor_locations(self) -> List[str]:
        return self.SENSOR_LOCATIONS
    
    @property
    def enable_real_mitigation(self) -> bool:
        return self.ENABLE_REAL_MITIGATION
    
    @property
    def mitigation_confirmation_token(self) -> Optional[str]:
        return self.MITIGATION_CONFIRMATION_TOKEN
    
    @property
    def blocklist_ttl_seconds(self) -> int:
        return self.BLOCKLIST_TTL_SECONDS
    
    @property
    def correlation_window_seconds(self) -> int:
        return self.CORRELATION_WINDOW_SECONDS
    
    class Config:
        env_file = '.env'
        case_sensitive = True
        protected_namespaces = ('settings_',)

# Global settings instance
settings = Settings()
