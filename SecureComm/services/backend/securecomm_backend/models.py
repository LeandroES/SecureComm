from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, nullable=False
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ik_pub: Mapped[str] = mapped_column(String(512), nullable=False)
    sig_pub: Mapped[str] = mapped_column(String(512), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    devices: Mapped[list[Device]] = relationship("Device", back_populates="user")


class DeviceStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    ik_pub: Mapped[str] = mapped_column(String(512), nullable=False)
    sig_pub: Mapped[str] = mapped_column(String(512), nullable=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default=DeviceStatus.ACTIVE)

    user: Mapped[User] = relationship("User", back_populates="devices")
    signed_prekeys: Mapped[list[SignedPreKey]] = relationship(
        "SignedPreKey", back_populates="device", cascade="all, delete-orphan"
    )
    one_time_prekeys: Mapped[list[OneTimePreKey]] = relationship(
        "OneTimePreKey", back_populates="device", cascade="all, delete-orphan"
    )
    envelopes: Mapped[list[Envelope]] = relationship(
        "Envelope", back_populates="device", cascade="all, delete-orphan"
    )


class SignedPreKey(Base):
    __tablename__ = "signed_prekeys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE")
    )
    spk_pub: Mapped[str] = mapped_column(String(512), nullable=False)
    spk_sig: Mapped[str] = mapped_column(String(512), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    device: Mapped[Device] = relationship("Device", back_populates="signed_prekeys")


class OneTimePreKey(Base):
    __tablename__ = "one_time_prekeys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE")
    )
    otk_pub: Mapped[str] = mapped_column(String(512), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    device: Mapped[Device] = relationship("Device", back_populates="one_time_prekeys")

    __table_args__ = (Index("idx_otk_available", "device_id", "used"),)


class Envelope(Base):
    __tablename__ = "envelopes"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, nullable=False
    )
    to_user: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    to_device: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=True
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ratchet_hdr: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    delivered: Mapped[bool] = mapped_column(Boolean, default=False)

    device: Mapped[Device | None] = relationship("Device", back_populates="envelopes")
    user: Mapped[User] = relationship("User")

    __table_args__ = (
        UniqueConstraint("id", name="uq_envelope_id"),
        Index("idx_envelope_pending", "to_user", "delivered"),
    )