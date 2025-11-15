import jwt
from fastapi import WebSocket, WebSocketDisconnect

from ..core.config import Settings

def verify_token(token: str, settings: Settings) -> dict[str, object]:
    return jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )


async def echo_websocket(websocket: WebSocket, settings: Settings) -> None:
    token = websocket.query_params.get("token") or websocket.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        await websocket.close(code=4401)
        return

    try:
        verify_token(token, settings)
    except jwt.PyJWTError:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_text()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        return