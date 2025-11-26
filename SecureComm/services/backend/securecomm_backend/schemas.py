from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from .core.config import Settings

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(
        subject: str,
        settings: Settings,
        device_id: str | None = None,
) -> str:
    to_encode: dict[str, Any] = {
        "sub": subject,
        "aud": settings.jwt_audience,
        "iss": settings.jwt_issuer,
        "device": device_id,
        "exp": datetime.now(timezone.utc)
               + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


class RegisterRequest(BaseModel):
    username: str
    password: str
    ik_pub: str
    sig_pub: str
    spk_pub: str
    spk_sig: str
    otk_pubs: list[str] = Field(default_factory=list)
    device_id: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class BundleResponse(BaseModel):
    username: str
    ik_pub: str
    spk_pub: str
    spk_sig: str
    otk_pub: str | None = None
    device_id: str


class PreKeyUpdate(BaseModel):
    spk_pub: str
    spk_sig: str
    otk_pubs: list[str] = Field(default_factory=list)


class EnvelopeIn(BaseModel):
    to_user: str
    to_device: str | None = None
    ratchet_header: dict[str, Any]
    ciphertext: str
    msg_id: str
    ts: datetime


class EnvelopeOut(BaseModel):
    id: str
    to_user: str
    to_device: str | None
    ratchet_header: dict[str, Any]
    ciphertext: str
    ts: datetime
    delivered: bool