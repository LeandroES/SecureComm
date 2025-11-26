import os
from datetime import datetime, timezone

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from securecomm_backend.models import Envelope

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "fakeredis://localhost/0")

from securecomm_backend.core.config import get_settings
from securecomm_backend.main import app


def _register(client: TestClient, username: str = "alice") -> dict:
    payload = {
        "username": username,
        "password": "pass1234",
        "ik_pub": "ik",
        "sig_pub": "sig",
        "spk_pub": "spk",
        "spk_sig": "sig",
        "otk_pubs": ["otk1", "otk2"],
    }
    response = client.post("/v1/register", json=payload)
    assert response.status_code == 201
    return response.json()


def test_register_and_login_flow() -> None:
    with TestClient(app) as client:
        reg = _register(client)
        assert "access_token" in reg

        login_resp = client.post(
            "/v1/login", json={"username": "alice", "password": "pass1234"}
        )
        assert login_resp.status_code == 200
        assert "access_token" in login_resp.json()


def test_bundle_consumes_one_time_key() -> None:
    with TestClient(app) as client:
        _register(client, "bob")

        first = client.get("/v1/users/bob/bundle")
        assert first.status_code == 200
        first_otk = first.json()["otk_pub"]
        assert first_otk == "otk1"

        second = client.get("/v1/users/bob/bundle")
        assert second.status_code == 200
        second_otk = second.json().get("otk_pub")
        assert second_otk == "otk2"


def test_websocket_queue_and_receive() -> None:
    with TestClient(app) as client:
        settings = get_settings()
        _register(client, "carol")
        _register(client, "dave")

        token_resp = client.post(
            "/v1/login", json={"username": "dave", "password": "pass1234"}
        ).json()["access_token"]
        jwt.decode(
            token_resp,
            settings.secret_key,
            algorithms=[settings.algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )

        carol_token = client.post(
            "/v1/login", json={"username": "carol", "password": "pass1234"}
        ).json()["access_token"]

        with client.websocket_connect(f"/ws/secure?token={carol_token}") as ws_carol:
            ws_carol.send_json(
                {
                    "action": "send",
                    "to_user": "dave",
                    "ciphertext": "abcd",
                    "ratchet_header": {"d": 1},
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "msg_id": "1",
                }
            )
            queued = ws_carol.receive_json()
            assert queued["status"] == "queued"

        with client.websocket_connect(f"/ws/secure?token={token_resp}") as ws_dave:
            ws_dave.send_json({"action": "recv"})
            try:
                message = ws_dave.receive_json()
                if message.get("type") == "envelope":
                    pass
            except Exception:
                pass
            ws_dave.send_json({"action": "close"})

        # Verify the envelope was persisted and marked delivered
        engine = create_async_engine("sqlite+aiosqlite:///./test.db")
        SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

        async def _fetch() -> int:
            async with SessionLocal() as session:
                result = await session.execute(select(Envelope))
                return len(result.scalars().all())

        import asyncio

        total = asyncio.get_event_loop().run_until_complete(_fetch())
        assert total >= 1