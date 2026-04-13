from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # 앱 기본
    app_name: str = "LinClean Open API"
    app_version: str = "0.1.0"
    environment: Literal["local", "dev", "staging", "production"] = "local"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # 서버
    host: str = "0.0.0.0"  # noqa: S104
    port: int = 8000
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = False

    # CORS
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # DB — 절대 경로 아니면 프로젝트 루트 기준으로 해석됨.
    sqlite_path: str = "data/linclean.db"
    db_echo: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sqlite_file(self) -> Path:
        path = Path(self.sqlite_path)
        return path if path.is_absolute() else PROJECT_ROOT / path

    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.sqlite_file}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def alembic_database_url(self) -> str:
        # Alembic은 동기 실행이라 stdlib sqlite 드라이버 필요.
        return f"sqlite:///{self.sqlite_file}"

    # Google Safe Browsing
    gsb_api_key: str | None = None
    gsb_api_url: str = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    )
    gsb_client_id: str = "linclean"
    gsb_client_version: str = "0.1.0"
    gsb_timeout_seconds: float = 5.0

    # URLhaus
    urlhaus_recent_csv_url: str = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    urlhaus_online_csv_url: str = "https://urlhaus.abuse.ch/downloads/csv_online/"
    urlhaus_refresh_interval_seconds: int = 60 * 60  # 60 minutes
    urlhaus_download_timeout_seconds: float = 60.0

    # RDAP
    rdap_bootstrap_url: str = "https://rdap.org/domain/"
    rdap_timeout_seconds: float = 5.0
    rdap_cache_ttl_seconds: int = 60 * 60 * 24  # 24h
    rdap_new_domain_threshold_days: int = 30

    # 정규화
    normalizer_max_url_length: int = 1024

    # 언체이닝
    unchain_max_hops: int = 20
    unchain_timeout_seconds: float = 10.0
    unchain_per_hop_timeout_seconds: float = 5.0
    unchain_user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )

    # 점수 산정
    score_weight_gsb: int = 50
    score_weight_urlhaus: int = 50
    score_weight_rdap: int = 20
    score_malicious_threshold: int = 50

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
