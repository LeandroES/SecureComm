import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "fakeredis://localhost/0")

from fastapi.testclient import TestClient

from securecomm_backend.main import app


def test_health_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/v1/version")
    assert response.status_code == 200
    assert "version" in response.json()