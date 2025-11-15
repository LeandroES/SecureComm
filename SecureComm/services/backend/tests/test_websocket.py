import jwt
from fastapi.testclient import TestClient

from securecomm_backend.core.config import get_settings
from securecomm_backend.main import app


def test_websocket_rejects_without_token() -> None:
    client = TestClient(app)
    with client.websocket_connect("/ws/echo", expect_close=True) as websocket:
        data = websocket.receive()
        assert data["type"] == "websocket.close"


def test_websocket_echoes_with_valid_token() -> None:
    client = TestClient(app)
    settings = get_settings()
    token = jwt.encode(
        {"sub": "test-user", "aud": settings.jwt_audience, "iss": settings.jwt_issuer},
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    with client.websocket_connect(f"/ws/echo?token={token}") as websocket:
        websocket.send_text("hello")
        message = websocket.receive_text()
    assert message == "hello"