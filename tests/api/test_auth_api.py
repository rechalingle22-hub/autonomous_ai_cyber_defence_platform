"""API integration tests for authentication and authorization."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_user_registration_success(async_client: AsyncClient):
    """Tests registering a new user account."""
    payload = {
        "username": "soc_analyst_2",
        "email": "analyst2@cyberdefense.org",
        "password": "StrongPassword2026!",
        "role": "ANALYST",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "soc_analyst_2"
    assert data["email"] == "analyst2@cyberdefense.org"
    assert "id" in data


@pytest.mark.asyncio
async def test_duplicate_user_registration_fails(async_client: AsyncClient):
    """Tests duplicate username rejection."""
    payload = {
        "username": "test_admin",  # Pre-seeded in fixture
        "email": "other@test.org",
        "password": "Password123!",
        "role": "ANALYST",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient):
    """Tests login with valid credentials returning a signed JWT token."""
    login_payload = {
        "username": "test_admin",
        "password": "AdminPass123!",
    }
    response = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["username"] == "test_admin"
    assert data["role"] == "ADMIN"


@pytest.mark.asyncio
async def test_login_invalid_password_fails(async_client: AsyncClient):
    """Tests rejection of incorrect password."""
    login_payload = {
        "username": "test_admin",
        "password": "WrongPassword!",
    }
    response = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_profile(async_client: AsyncClient, admin_token: str):
    """Tests retrieval of authenticated user profile using Bearer token."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "test_admin"
    assert data["role"] == "ADMIN"


@pytest.mark.asyncio
async def test_profile_without_token_unauthorized(async_client: AsyncClient):
    """Verifies that accessing protected endpoints without token returns 401."""
    response = await async_client.get("/api/v1/auth/me")
    assert response.status_code == 401
