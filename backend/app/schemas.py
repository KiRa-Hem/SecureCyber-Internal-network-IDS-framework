from pydantic import BaseModel, EmailStr
from typing import List, Dict, Any, Optional
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class BlockIPRequest(BaseModel):
    ip: str
    reason: str
    ttl_seconds: int = 3600

class UnblockIPRequest(BaseModel):
    ip: str

class IsolateNodeRequest(BaseModel):
    node_id: str
    reason: str
    ttl_seconds: int = 3600

class RemoveIsolationRequest(BaseModel):
    node_id: str

class SimulateAttackRequest(BaseModel):
    attack_type: str
    source_ip: str
    target_ip: str
    payload: str = ""