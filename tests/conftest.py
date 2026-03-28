import os
import sys

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("API_TOKEN", "test-token")
os.environ.setdefault("ADMIN_TOKEN", "test-token")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("AUTH_ALLOW_INSECURE_NO_AUTH", "false")
os.environ.setdefault("DEMO_LOGIN_USERNAME", "demo-user")
os.environ.setdefault("DEMO_LOGIN_PASSWORD", "demo-pass")
os.environ.setdefault("ENABLE_PACKET_CAPTURE", "false")

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app


@pytest.fixture(scope="session")
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)

@pytest.fixture(scope="session")
def auth_headers():
    return {"Authorization": "Bearer test-token"}
