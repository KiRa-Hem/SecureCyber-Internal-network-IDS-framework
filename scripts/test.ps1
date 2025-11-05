# Navigate to project root
Write-Host "Navigating to project root..." -ForegroundColor Green
cd C:\Users\hemes\OneDrive\Desktop\IDS

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Green
.\venv\Scripts\Activate.ps1

# Navigate to backend directory
Write-Host "Navigating to backend directory..." -ForegroundColor Green
cd backend

# Install pymongo if not already installed
Write-Host "Installing pymongo..." -ForegroundColor Green
pip install pymongo

# Install email-validator for Pydantic email validation
Write-Host "Installing email-validator..." -ForegroundColor Green
pip install email-validator

# Create new config.py with all fields
Write-Host "Creating new config.py with all fields..." -ForegroundColor Green
$configContent = @"
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
    
    # Authentication
    SECRET_KEY: str = 'your-secret-key-change-in-production'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 10080
    
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
"@

Set-Content -Path "app\config.py" -Value $configContent

# Create new db.py with only MongoDB
Write-Host "Creating new db.py with only MongoDB..." -ForegroundColor Green
$dbContent = @"
import os
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from typing import Optional, Dict, List, Any
from datetime import datetime
from contextlib import contextmanager

from app.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB setup
class MongoDB:
    def __init__(self):
        self.client = None
        self.db = None
        self.connect()
    
    def connect(self):
        try:
            self.client = MongoClient(settings.MONGO_URI_COMPUTED)
            self.db = self.client[settings.MONGO_DB]
            # Test connection
            self.client.admin.command('ping')
            logger.info(f'Connected to MongoDB: {settings.MONGO_CLUSTER}')
        except ConnectionFailure as e:
            logger.error(f'Failed to connect to MongoDB: {e}')
            raise
    
    def close(self):
        if self.client:
            self.client.close()
            logger.info('Disconnected from MongoDB')
    
    def get_collection(self, collection_name: str):
        return self.db[collection_name]
    
    def insert_one(self, collection_name: str, document: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.insert_one(document)
    
    def insert_many(self, collection_name: str, documents: List[Dict[str, Any]]):
        collection = self.get_collection(collection_name)
        return collection.insert_many(documents)
    
    def find(self, collection_name: str, query: Dict[str, Any] = None, limit: int = 0):
        collection = self.get_collection(collection_name)
        if query is None:
            query = {}
        cursor = collection.find(query)
        if limit > 0:
            cursor = cursor.limit(limit)
        return list(cursor)
    
    def find_one(self, collection_name: str, query: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.find_one(query)
    
    def update_one(self, collection_name: str, query: Dict[str, Any], update: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.update_one(query, update)
    
    def delete_one(self, collection_name: str, query: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.delete_one(query)
    
    def count_documents(self, collection_name: str, query: Dict[str, Any] = None):
        collection = self.get_collection(collection_name)
        if query is None:
            query = {}
        return collection.count_documents(query)

# Create MongoDB instance
mongodb = MongoDB()

# Context manager for MongoDB operations
@contextmanager
def get_mongodb_collection(collection_name: str):
    try:
        collection = mongodb.get_collection(collection_name)
        yield collection
    except Exception as e:
        logger.error(f'Error accessing MongoDB collection {collection_name}: {e}')
        raise

# Initialize database
def init_db():
    # Create indexes in MongoDB
    try:
        # Users collection indexes
        users_collection = mongodb.get_collection('users')
        users_collection.create_index([('username', 1)], unique=True)
        users_collection.create_index([('email', 1)], unique=True)
        
        # Alerts collection indexes
        alerts_collection = mongodb.get_collection('alerts')
        alerts_collection.create_index([('timestamp', -1)])
        alerts_collection.create_index([('source_ip', 1)])
        alerts_collection.create_index([('attack_types', 1)])
        
        # Packets collection indexes
        packets_collection = mongodb.get_collection('packets')
        packets_collection.create_index([('timestamp', -1)])
        packets_collection.create_index([('source_ip', 1)])
        packets_collection.create_index([('dest_ip', 1)])
        
        logger.info('Database initialized successfully')
    except Exception as e:
        logger.error(f'Error initializing database: {e}')
        raise
"@

Set-Content -Path "app\db.py" -Value $dbContent

# Create auth/models.py
Write-Host "Creating auth/models.py..." -ForegroundColor Green
$modelsContent = @"
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr
from bson import ObjectId
from app.db import mongodb

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class UserInDB(UserResponse):
    hashed_password: str

    @classmethod
    def get_by_username(cls, username: str):
        user_data = mongodb.find_one('users', {'username': username})
        if user_data:
            # Convert ObjectId to string for id
            user_data['id'] = str(user_data['_id'])
            return cls(**user_data)
        return None

    @classmethod
    def get_by_email(cls, email: str):
        user_data = mongodb.find_one('users', {'email': email})
        if user_data:
            # Convert ObjectId to string for id
            user_data['id'] = str(user_data['_id'])
            return cls(**user_data)
        return None

    @classmethod
    def create(cls, user_data: dict):
        # Insert the user into MongoDB
        result = mongodb.insert_one('users', user_data)
        # Get the inserted user
        user_data['_id'] = str(result.inserted_id)
        return cls(**user_data)
"@

Set-Content -Path "app\auth\models.py" -Value $modelsContent

# Create auth/routes.py
Write-Host "Creating auth/routes.py..." -ForegroundColor Green
$routesContent = @"
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime
from app.auth.models import UserCreate, UserResponse, UserInDB
from app.auth.security import get_password_hash, verify_password, create_access_token

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/login')

@router.post('/register', response_model=UserResponse)
async def register(user: UserCreate):
    # Check if user already exists
    if UserInDB.get_by_username(user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Username already registered'
        )
    
    if UserInDB.get_by_email(user.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Email already registered'
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_data = {
        'username': user.username,
        'email': user.email,
        'hashed_password': hashed_password,
        'is_active': True,
        'created_at': datetime.utcnow()
    }
    
    db_user = UserInDB.create(user_data)
    
    return db_user

@router.post('/login')
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Authenticate user
    user = UserInDB.get_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    
    # Update last login
    mongodb.update_one(
        'users',
        {'username': form_data.username},
        {'$set': {'last_login': datetime.utcnow()}}
    )
    
    # Create access token
    access_token = create_access_token(data={'sub': user.username})
    return {'access_token': access_token, 'token_type': 'bearer'}
"@

Set-Content -Path "app\auth\routes.py" -Value $routesContent

# Set PYTHONPATH to include the backend directory
Write-Host "Setting PYTHONPATH..." -ForegroundColor Green
$env:PYTHONPATH = "$PWD;$env:PYTHONPATH"

# Start the application
Write-Host "Starting the SecureCyber application..." -ForegroundColor Green
python app/main.py

# Wait for user input to exit
Read-Host "Press Enter to exit"