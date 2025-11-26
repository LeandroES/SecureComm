from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("ik_pub", sa.String(length=512), nullable=False),
        sa.Column("sig_pub", sa.String(length=512), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("ik_pub", sa.String(length=512), nullable=False),
        sa.Column("sig_pub", sa.String(length=512), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
    )

    op.create_table(
        "signed_prekeys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE")),
        sa.Column("spk_pub", sa.String(length=512), nullable=False),
        sa.Column("spk_sig", sa.String(length=512), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True)),
        sa.Column("valid_to", sa.DateTime(timezone=True)),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.text("true")),
    )

    op.create_table(
        "one_time_prekeys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE")),
        sa.Column("otk_pub", sa.String(length=512), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_otk_available", "one_time_prekeys", ["device_id", "used"])

    op.create_table(
        "envelopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("to_user", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE")),
        sa.Column("to_device", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("ratchet_hdr", sa.JSON(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True)),
        sa.Column("delivered", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )
    op.create_index("idx_envelope_pending", "envelopes", ["to_user", "delivered"])


def downgrade() -> None:
    op.drop_index("idx_envelope_pending", table_name="envelopes")
    op.drop_table("envelopes")
    op.drop_index("idx_otk_available", table_name="one_time_prekeys")
    op.drop_table("one_time_prekeys")
    op.drop_table("signed_prekeys")
    op.drop_table("devices")
    op.drop_table("users")