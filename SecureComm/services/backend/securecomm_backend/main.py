from collections.abc import AsyncGenerator

from fastapi import Depends, FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router as api_router
from .api.websocket import messaging_socket
from .core.config import Settings, get_settings
from .dependencies import get_db_session, get_redis, init_models

settings = get_settings()


async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    await init_models()
    yield


app = FastAPI(title="SecureComm Backend", version=settings.version, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.websocket("/ws/secure")
async def websocket_endpoint(
    websocket: WebSocket,
    settings: Settings = Depends(get_settings),
    session=Depends(get_db_session),
):
    redis = get_redis(settings)
    await messaging_socket(websocket, settings, session, redis)