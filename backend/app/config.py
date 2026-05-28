from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://ictip:ictip_secret@postgres:5432/ictip_db",
        description="Async PostgreSQL connection URL"
    )
    sync_database_url: str = Field(
        default="postgresql://ictip:ictip_secret@postgres:5432/ictip_db",
        description="Sync PostgreSQL connection URL (for Alembic)"
    )

    # Redis
    redis_url: str = Field(
        default="redis://redis:6379/0",
        description="Redis connection URL"
    )

    # Application Security
    secret_key: str = Field(
        default="super_secret_key_change_in_prod",
        description="Application secret key"
    )

    # External API Keys
    otx_api_key: Optional[str] = Field(
        default=None,
        description="OTX AlienVault API key (optional)"
    )

    # Application Settings
    environment: str = Field(default="production", description="deployment environment")
    log_level: str = Field(default="INFO", description="Logging level")

    # Scheduler intervals
    fetch_interval_minutes: int = Field(
        default=5,
        description="How often to fetch new threat data (minutes)"
    )
    stats_update_interval_minutes: int = Field(
        default=60,
        description="How often to update aggregate statistics (minutes)"
    )

    # CORS
    allowed_origins: list[str] = Field(
        default=["*"],
        description="Allowed CORS origins"
    )

    model_config = {"env_file": ".env", "case_sensitive": False}


settings = Settings()
