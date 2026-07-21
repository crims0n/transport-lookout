from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .models import Role, RunStatus, ShardStatus


class ScopeCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    cidr: str
    zone: str = Field(default="default", min_length=1, max_length=64)


class ScopeRead(ScopeCreate):
    id: str
    approved: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ProfileCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    ports: str = Field(pattern=r"^([TU]:)?\d+(-\d+)?(,([TU]:)?\d+(-\d+)?)*$")
    max_rate: int = Field(default=500, ge=1, le=10_000)
    scanner_mode: Literal["nmap", "masscan_then_nmap"] = "nmap"
    max_concurrent_shards: int = Field(default=4, ge=1, le=128)
    timeout_seconds: int = Field(default=1800, ge=30, le=14_400)
    zone: str = Field(default="default", min_length=1, max_length=64)

    @field_validator("ports")
    @classmethod
    def ports_are_nonempty(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def masscan_profiles_are_tcp_only(self):
        if self.scanner_mode == "masscan_then_nmap" and "U:" in self.ports:
            raise ValueError("masscan discovery profiles support TCP ports only")
        return self


class ProfileRead(ProfileCreate):
    id: str
    version: int
    arguments: str
    created_at: datetime

    model_config = {"from_attributes": True}


class RunCreate(BaseModel):
    inventory_scope_id: str
    profile_id: str


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    inventory_scope_id: str
    profile_id: str
    interval_minutes: int = Field(ge=15, le=10_080)
    timezone: str = "UTC"
    first_run_at: datetime | None = None


class ScheduleRead(BaseModel):
    id: str
    name: str
    inventory_scope_id: str
    profile_id: str
    interval_minutes: int
    timezone: str
    next_run_at: datetime
    enabled: bool
    created_by: str

    model_config = {"from_attributes": True}


class ShardRead(BaseModel):
    id: str
    cidr: str
    zone: str
    status: ShardStatus
    attempts: int
    artifact_key: str | None
    discovery_artifact_key: str | None
    error: str | None

    model_config = {"from_attributes": True}


class RunRead(BaseModel):
    id: str
    inventory_scope_id: str
    profile_id: str
    status: RunStatus
    requested_by: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    shards: list[ShardRead] = []


class ServiceRead(BaseModel):
    protocol: str
    port: int
    state: str
    service: str | None
    product: str | None
    version: str | None

    model_config = {"from_attributes": True}


class DiscoveryResultRead(BaseModel):
    shard_id: str
    cidr: str
    address: str
    protocol: str
    port: int


class HostRead(BaseModel):
    id: str
    address: str
    state: str
    hostname: str | None
    services: list[ServiceRead]


class UserRead(BaseModel):
    subject: str
    role: Role


class UserProvision(BaseModel):
    subject: str = Field(min_length=1, max_length=255)
    role: Role


class AuditEventRead(BaseModel):
    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    detail: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class ExposureRead(BaseModel):
    id: str
    inventory_scope_id: str
    profile_id: str
    latest_run_id: str
    zone: str
    address: str
    protocol: str
    port: int
    service: str | None
    product: str | None
    version: str | None
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = {"from_attributes": True}


class ExposureSummary(BaseModel):
    open_hosts: int
    open_services: int
    unique_ports: int
    latest_observation_at: datetime | None


class ExposureChangeRead(BaseModel):
    change_type: str
    address: str
    protocol: str | None = None
    port: int | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    previous_service: str | None = None
    previous_product: str | None = None
    previous_version: str | None = None


class ExposureDiffRead(BaseModel):
    current_run_id: str | None
    previous_run_id: str | None
    coverage_complete: bool
    coverage_note: str | None = None
    changes: list[ExposureChangeRead]
