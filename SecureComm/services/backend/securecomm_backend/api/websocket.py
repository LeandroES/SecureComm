from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import jwt
from fastapi import WebSocket, WebSocketDisconnect
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import Settings
from ..models import Device, Envelope, User


async def verify_token(token: str, settings: Settings) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )


async def _rate_limit(redis: Redis, key: str, limit: int, ttl: int) -> bool:
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, ttl)
    return count <= limit


async def _queue_pending(redis: Redis, user_id: str, envelope_id: str) -> None:
    await redis.lpush(f"pending:{user_id}", envelope_id)


async def _pull_pending(redis: Redis, user_id: str) -> list[str]:
    envelopes = await redis.lrange(f"pending:{user_id}", 0, -1)
    await redis.delete(f"pending:{user_id}")
    return envelopes


async def messaging_socket(
        websocket: WebSocket,
        settings: Settings,
        session: AsyncSession,
        redis: Redis,
) -> None:
    token = websocket.query_params.get("token") or websocket.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        await websocket.close(code=4401)
        return

    try:
        claims = await verify_token(token, settings)
    except jwt.PyJWTError:
        await websocket.close(code=4403)
        return

    user_id = claims.get("sub")
    device_id = claims.get("device")
    await websocket.accept()

    async def deliver_pending() -> None:
        ids = await _pull_pending(redis, user_id)
        if not ids:
            return
        rows = await session.execute(select(Envelope).where(Envelope.id.in_(ids)))
        for env in rows.scalars():
            await websocket.send_json(
                {
                    "type": "envelope",
                    "id": str(env.id),
                    "to_user": str(env.to_user),
                    "to_device": str(env.to_device) if env.to_device else None,
                    "ratchet_header": env.ratchet_hdr,
                    "ciphertext": env.ciphertext.hex(),
                    "ts": env.ts.isoformat(),
                }
            )
            env.delivered = True
        await session.commit()

    try:
        while True:
            try:
                payload = await websocket.receive_json()
            except WebSocketDisconnect:
                break

            action = payload.get("action")
            if action == "send":
                allowed = await _rate_limit(redis, f"send:{user_id}", limit=50, ttl=60)
                if not allowed:
                    await websocket.send_json({"error": "rate_limited"})
                    continue
                to_username = payload.get("to_user")
                to_device = payload.get("to_device")
                ciphertext = payload.get("ciphertext")
                ratchet_header = payload.get("ratchet_header")
                msg_ts = payload.get("ts")
                target_user = await session.scalar(
                    select(User).where(User.username == to_username)
                )
                if not target_user:
                    await websocket.send_json({"error": "recipient_not_found"})
                    continue
                target_device = None
                if to_device:
                    target_device = await session.get(Device, UUID(to_device))
                env = Envelope(
                    to_user=target_user.id,
                    to_device=target_device.id if target_device else None,
                    ciphertext=bytes.fromhex(ciphertext),
                    ratchet_hdr=ratchet_header or {},
                    ts=datetime.fromisoformat(msg_ts) if msg_ts else datetime.now(timezone.utc),
                    delivered=False,
                )
                session.add(env)
                await session.commit()
                await _queue_pending(redis, str(target_user.id), str(env.id))
                await websocket.send_json({"status": "queued", "id": str(env.id)})
            elif action == "recv":
                await deliver_pending()
                await websocket.send_json({"status": "idle"})
                break
            elif action == "receipt":
                env_id = payload.get("id")
                if env_id:
                    record = await session.get(Envelope, UUID(env_id))
                    if record:
                        record.delivered = True
                        await session.commit()
                await websocket.send_json({"status": "ack"})
            elif action == "close":
                break
            else:
                await websocket.send_json({"error": "unknown_action"})
    finally:
        await websocket.close()