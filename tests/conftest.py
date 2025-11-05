import pytest
import os
import sys
import tempfile
import shutil
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app
from app.db import get_db
from app.auth.models import Base

@pytest.fixture(scope="session")
def test_db():
    """Create a test database."""
    # Create temporary directory
    test_dir = tempfile.mkdtemp()
    db_path = os.path.join(test_dir, "test.db")
    
    # Create database engine
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    # Create session factory
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Override database dependency
    def override_get_db():
        try:
            db = TestingSessionLocal()
            yield db
        finally:
            db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    
    yield engine
    
    # Cleanup
    app.dependency_overrides.clear()
    shutil.rmtree(test_dir)

@pytest.fixture(scope="function")
def db_session(test_db):
    """Create a database session for a test."""
    connection = test_db.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(scope="function")
def client():
    """Create a test client."""
    return TestClient(app)

@pytest.fixture(scope="function")
def auth_headers():
    """Create authentication headers."""
    from app.auth.security import create_access_token
    token = create_access_token(data={"sub": "testuser"})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def admin_headers():
    """Create admin authentication headers."""
    from app.auth.security import create_access_token
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}