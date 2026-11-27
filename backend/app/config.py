"""Application configuration powered by pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and optional .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    env: str = "development"
    app_name: str = "OWASP Top 10 Developer-Experience Vulnerability Scanner"
    app_version: str = "1.0.0"
    app_port: int = 8000
    database_url: str = "sqlite:///./data/scanner.db"
    scan_allowlist: str = (
        "localhost,127.0.0.1,host.docker.internal,dvwa,juice-shop,vulnbench"
    )
    scan_rate_limit_rps: int = 10
    scan_max_requests: int = 2000
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"

    @property
    def allowlist_hosts(self) -> list[str]:
        """Return normalized allow-listed hostnames for authorized scanning."""
        return [
            host.strip().lower()
            for host in self.scan_allowlist.split(",")
            if host.strip()
        ]

    @property
    def cors_origin_list(self) -> list[str]:
        """Return configured CORS origin list."""
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()


settings = get_settings()
