from fastapi import APIRouter, Depends

from ..core.config import Settings, get_settings

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/version")
def version(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    return {"version": settings.version}