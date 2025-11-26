from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import Settings, get_settings
from ..dependencies import get_db_session
from ..models import Device, OneTimePreKey, SignedPreKey, User
from ..schemas import (
    BundleResponse,
    LoginRequest,
    PreKeyUpdate,
    RegisterRequest,
    TokenResponse,
    create_access_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/v1")


DbDep = Annotated[AsyncSession, Depends(get_db_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/version")
async def version(settings: SettingsDep) -> dict[str, str]:
    return {"version": settings.version}


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
        payload: RegisterRequest,
        session: DbDep,
        settings: SettingsDep,
) -> TokenResponse:
    existing = await session.scalar(select(User).where(User.username == payload.username))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username taken")

    user = User(
        username=payload.username,
        ik_pub=payload.ik_pub,
        sig_pub=payload.sig_pub,
        password_hash=hash_password(payload.password),
    )
    device = Device(
        id=UUID(payload.device_id) if payload.device_id else None,
        user=user,
        ik_pub=payload.ik_pub,
        sig_pub=payload.sig_pub,
    )
    spk = SignedPreKey(
        device=device,
        spk_pub=payload.spk_pub,
        spk_sig=payload.spk_sig,
        valid_from=datetime.now(timezone.utc),
        active=True,
    )
    otks = [
        OneTimePreKey(device=device, otk_pub=otk, used=False)
        for otk in payload.otk_pubs
    ]
    session.add_all([user, device, spk, *otks])
    await session.commit()
    await session.refresh(user)
    token = create_access_token(str(user.id), settings, device_id=str(device.id))
    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
async def login(
        payload: LoginRequest,
        session: DbDep,
        settings: SettingsDep,
) -> TokenResponse:
    user = await session.scalar(select(User).where(User.username == payload.username))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    device = None
    if payload.device_id:
        device = await session.get(Device, UUID(payload.device_id))
    if device is None:
        device = Device(user=user, ik_pub=user.ik_pub, sig_pub=user.sig_pub)
        session.add(device)
        await session.commit()
        await session.refresh(device)
    token = create_access_token(str(user.id), settings, device_id=str(device.id))
    return TokenResponse(access_token=token)


@router.get("/users/{username}/bundle", response_model=BundleResponse)
async def fetch_bundle(username: str, session: DbDep) -> BundleResponse:
    user = await session.scalar(select(User).where(User.username == username))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    device = await session.scalar(
        select(Device).where(Device.user_id == user.id).limit(1)
    )
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no device")

    spk = await session.scalar(
        select(SignedPreKey)
        .where(SignedPreKey.device_id == device.id, SignedPreKey.active.is_(True))
        .order_by(SignedPreKey.valid_from.desc())
    )
    if not spk:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no spk")

    otk = await session.scalar(
        select(OneTimePreKey)
        .where(OneTimePreKey.device_id == device.id, OneTimePreKey.used.is_(False))
        .order_by(OneTimePreKey.created_at.asc())
    )
    otk_pub = None
    if otk:
        otk.used = True
        otk_pub = otk.otk_pub
        await session.commit()

    return BundleResponse(
        username=user.username,
        ik_pub=user.ik_pub,
        spk_pub=spk.spk_pub,
        spk_sig=spk.spk_sig,
        otk_pub=otk_pub,
        device_id=str(device.id),
    )


@router.post("/devices/{device_id}/prekeys")
async def rotate_prekeys(
        device_id: str,
        payload: PreKeyUpdate,
        session: DbDep,
) -> dict[str, str]:
    device = await session.get(Device, UUID(device_id))
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="device not found")

    await session.execute(
        update(SignedPreKey)
        .where(SignedPreKey.device_id == device.id)
        .values(active=False, valid_to=datetime.now(timezone.utc))
    )
    new_spk = SignedPreKey(
        device=device,
        spk_pub=payload.spk_pub,
        spk_sig=payload.spk_sig,
        valid_from=datetime.now(timezone.utc),
        active=True,
    )
    new_otks = [OneTimePreKey(device=device, otk_pub=otk, used=False) for otk in payload.otk_pubs]
    session.add_all([new_spk, *new_otks])
    await session.commit()
    return {"status": "rotated"}