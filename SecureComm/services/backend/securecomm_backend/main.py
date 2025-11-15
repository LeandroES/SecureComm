from fastapi import Depends, FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router as api_router
from .api.websocket import echo_websocket
from .core.config import Settings, get_settings

settings = get_settings()

app = FastAPI(title="SecureComm Backend", version=settings.version)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.websocket("/ws/echo")
async def websocket_endpoint(
        websocket: WebSocket,
        settings: Settings = Depends(get_settings),
) -> None:
    await echo_websocket(websocket, settings)