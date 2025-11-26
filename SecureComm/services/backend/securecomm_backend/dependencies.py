from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

try:  # pragma: no cover - optional for tests
    from fakeredis.aioredis import FakeRedis
except ImportError:  # pragma: no cover
    FakeRedis = None

from .core.config import Settings, get_settings
from .db import create_engine, get_session_factory
from .models import Base

_engine = create_engine(get_settings())
_session_factory = get_session_factory(_engine)
_redis_client: Redis | None = None


async def get_db_session() -> AsyncSession:
    async with _session_factory() as session:
        yield session


def get_redis(settings: Settings | None = None) -> Redis:
    global _redis_client
    settings = settings or get_settings()
    if settings.redis_url.startswith("fakeredis://") and FakeRedis is not None:
        return FakeRedis()
    if _redis_client is None:
        _redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


async def init_models() -> None:
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)