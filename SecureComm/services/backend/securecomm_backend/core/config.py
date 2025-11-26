from functools import lru_cache
from typing import Literal

from pydantic import BaseModel


class Settings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    secret_key: str = "change-me"
    version: str = "0.1.0"
    jwt_audience: str = "securecomm-clients"
    jwt_issuer: str = "securecomm-backend"
    algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = 30
    database_url: str = (
        "postgresql+psycopg://securecomm:securecomm@postgres:5432/securecomm"
    )
    redis_url: str = "redis://redis:6379/0"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    from os import getenv

    return Settings(
        host=getenv("BACKEND_HOST", "0.0.0.0"),
        port=int(getenv("BACKEND_PORT", "8000")),
        log_level=getenv("BACKEND_LOG_LEVEL", "info"),
        secret_key=getenv("BACKEND_SECRET_KEY", "change-me"),
        version=getenv("BACKEND_VERSION", "0.1.0"),
        jwt_audience=getenv("JWT_AUDIENCE", "securecomm-clients"),
        jwt_issuer=getenv("JWT_ISSUER", "securecomm-backend"),
        access_token_expire_minutes=int(
            getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
        ),
        database_url=getenv(
            "DATABASE_URL",
            "postgresql+psycopg://securecomm:securecomm@postgres:5432/securecomm",
        ),
        redis_url=getenv("REDIS_URL", "redis://redis:6379/0"),
    )