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
    artifact_root: str = "/tmp/scanpod-artifacts"
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    shard_lease_seconds: int = 3600


settings = Settings()
