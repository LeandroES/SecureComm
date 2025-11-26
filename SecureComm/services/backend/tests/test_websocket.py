import os

import jwt
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "fakeredis://localhost/0")

from securecomm_backend.core.config import get_settings
from securecomm_backend.main import app


def test_websocket_rejects_without_token() -> None:
    with TestClient(app) as client:
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/secure") as websocket:
                websocket.receive()


def test_websocket_echoes_with_valid_token() -> None:
    client = TestClient(app)
    settings = get_settings()
    token = jwt.encode(
        {"sub": "test-user", "aud": settings.jwt_audience, "iss": settings.jwt_issuer},
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    with client.websocket_connect(f"/ws/secure?token={token}") as websocket:
        websocket.send_json({"action": "recv"})
        websocket.close()