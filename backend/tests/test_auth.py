import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import init_db
from app.auth.models import User

client = TestClient(app)

@pytest.fixture(scope="module")
def test_db():
    init_db()
    yield
    # Clean up after tests

def test_signup(test_db):
    response = client.post(
        "/auth/signup",
        json={"username": "testuser", "email": "test@example.com", "password": "testpassword"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "User created successfully"

def test_login(test_db):
    # First, create a user
    client.post(
        "/auth/signup",
        json={"username": "loginuser", "email": "login@example.com", "password": "loginpassword"}
    )
    
    # Then login
    response = client.post(
        "/auth/login",
        data={"username": "loginuser", "password": "loginpassword"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_protected_route_without_auth(test_db):
    response = client.get("/api/alerts")
    assert response.status_code == 401

def test_protected_route_with_auth(test_db):
    # Create and login a user
    client.post(
        "/auth/signup",
        json={"username": "authuser", "email": "auth@example.com", "password": "authpassword"}
    )
    
    login_response = client.post(
        "/auth/login",
        data={"username": "authuser", "password": "authpassword"}
    )
    token = login_response.json()["access_token"]
    
    # Access protected route
    response = client.get(
        "/api/alerts",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200