import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def reset_test_db() -> None:
    db_path = Path("test.db")
    if db_path.exists():
        db_path.unlink()
    os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    os.environ.setdefault("REDIS_URL", "fakeredis://localhost/0")

    from securecomm_backend import dependencies
    from securecomm_backend.core.config import get_settings
    from securecomm_backend.db import create_engine, get_session_factory

    get_settings.cache_clear()
    settings = get_settings()
    dependencies._engine = create_engine(settings)
    dependencies._session_factory = get_session_factory(dependencies._engine)