from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANPOD_", case_sensitive=False)

    database_url: str = "sqlite:///./scanpod.db"
    amqp_url: str = "amqp://guest:guest@localhost:5672//"
    bootstrap_enabled: bool = False
    bootstrap_token: str = ""
    cors_origins: str = ""
    max_cidr_prefix: int = 16
    shard_prefix: int = 24
    max_shards_per_run: int = 4096
    inventory_import_max_rows: int = 1000
    artifact_backend: Literal["filesystem", "s3"] = "filesystem"
    artifact_root: str = "/tmp/scanpod-artifacts"
    artifact_s3_bucket: str = ""
    artifact_s3_prefix: str = "transport-lookout"
    artifact_s3_region: str = ""
    artifact_s3_endpoint_url: str = ""
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    shard_lease_seconds: int = 3600
    worker_heartbeat_seconds: int = 15
    scan_cancel_grace_seconds: int = 20
    max_shard_attempts: int = 3
    run_stale_seconds: int = 7200


settings = Settings()
