import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    platform_admin = "platform_admin"
    inventory_manager = "inventory_manager"
    scan_operator = "scan_operator"
    auditor = "auditor"


class RunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ShardStatus(str, enum.Enum):
    queued = "queued"
    leased = "leased"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    dead_letter = "dead_letter"


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    subject: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    role: Mapped[Role] = mapped_column(Enum(Role))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class InventoryScope(Base):
    __tablename__ = "inventory_scopes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    cidr: Mapped[str] = mapped_column(String(43), unique=True, index=True)
    zone: Mapped[str] = mapped_column(String(64), default="default")
    approved: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    __table_args__ = (UniqueConstraint("name", "version", name="uq_profile_version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[int] = mapped_column(Integer)
    ports: Mapped[str] = mapped_column(String(512))
    arguments: Mapped[str] = mapped_column(String(512), default="-sV -n")
    max_rate: Mapped[int] = mapped_column(Integer, default=500)
    scanner_mode: Mapped[str] = mapped_column(String(32), default="nmap")
    max_concurrent_shards: Mapped[int] = mapped_column(Integer, default=4)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=1800)
    zone: Mapped[str] = mapped_column(String(64), default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    inventory_scope_id: Mapped[str] = mapped_column(ForeignKey("inventory_scopes.id"), index=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("scan_profiles.id"))
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus), default=RunStatus.queued, index=True)
    requested_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    inventory_scope_id: Mapped[str] = mapped_column(ForeignKey("inventory_scopes.id"), index=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("scan_profiles.id"))
    interval_minutes: Mapped[int] = mapped_column(Integer)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    enabled: Mapped[bool] = mapped_column(default=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanShard(Base):
    __tablename__ = "scan_shards"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    cidr: Mapped[str] = mapped_column(String(43))
    zone: Mapped[str] = mapped_column(String(64))
    status: Mapped[ShardStatus] = mapped_column(Enum(ShardStatus), default=ShardStatus.queued)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    worker_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    retry_not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    artifact_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    discovery_artifact_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class HostObservation(Base):
    __tablename__ = "host_observations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    shard_id: Mapped[str] = mapped_column(ForeignKey("scan_shards.id"), index=True)
    address: Mapped[str] = mapped_column(String(64), index=True)
    state: Mapped[str] = mapped_column(String(32))
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ServiceObservation(Base):
    __tablename__ = "service_observations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_observation_id: Mapped[str] = mapped_column(ForeignKey("host_observations.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32))
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)


class DiscoveryObservation(Base):
    __tablename__ = "discovery_observations"
    __table_args__ = (UniqueConstraint("shard_id", "address", "protocol", "port", name="uq_discovery_observation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    shard_id: Mapped[str] = mapped_column(ForeignKey("scan_shards.id"), index=True)
    address: Mapped[str] = mapped_column(String(64), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[int] = mapped_column(Integer)


class CurrentExposure(Base):
    __tablename__ = "current_exposures"
    __table_args__ = (UniqueConstraint("inventory_scope_id", "profile_id", "address", "protocol", "port", name="uq_current_exposure"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    inventory_scope_id: Mapped[str] = mapped_column(ForeignKey("inventory_scopes.id"), index=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("scan_profiles.id"), index=True)
    latest_run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    zone: Mapped[str] = mapped_column(String(64), index=True)
    address: Mapped[str] = mapped_column(String(64), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[int] = mapped_column(Integer, index=True)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    scan_count: Mapped[int] = mapped_column(Integer, default=1)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(100))
    resource_id: Mapped[str] = mapped_column(String(255))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    topic: Mapped[str] = mapped_column(String(128), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
