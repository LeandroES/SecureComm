from fastapi.testclient import TestClient

from securecomm_backend.main import app


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/version")
    assert response.status_code == 200
    assert "version" in response.json()