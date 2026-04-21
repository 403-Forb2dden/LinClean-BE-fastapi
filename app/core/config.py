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
    gsb_api_url: str = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    gsb_client_id: str = "linclean"
    gsb_client_version: str = "0.1.0"
    gsb_timeout_seconds: float = 5.0

    # URLhaus
    urlhaus_recent_csv_url: str = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    urlhaus_online_csv_url: str = "https://urlhaus.abuse.ch/downloads/csv_online/"
    urlhaus_refresh_interval_seconds: int = 60 * 60  # 60 minutes
    urlhaus_download_timeout_seconds: float = 60.0
    # URLhaus 매칭 키: 다중 테넌트 호스트는 host+path-prefix(N 세그먼트)까지 키로 사용.
    urlhaus_multitenant_hosts: dict[str, int] = Field(
        default_factory=lambda: {
            "github.com": 2,
            "raw.githubusercontent.com": 2,
            "gist.github.com": 2,
            "gitlab.com": 2,
            "bitbucket.org": 2,
            "sites.google.com": 2,
        }
    )

    # Scheduler / URLhaus 동기화
    scheduler_enabled: bool = True
    urlhaus_sync_on_startup: bool = True

    # RDAP
    rdap_bootstrap_url: str = "https://rdap.org/domain/"
    rdap_timeout_seconds: float = 5.0
    rdap_cache_ttl_seconds: int = 60 * 60 * 24  # 24h
    rdap_new_domain_threshold_days: int = 30

    # 정규화
    normalizer_max_url_length: int = 1024

    # 언체이닝
    unchain_max_hops: int = 5
    unchain_timeout_seconds: float = 5.0
    unchain_connect_timeout_seconds: float = 3.0
    unchain_chain_timeout_seconds: float = 20.0
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

    # 도메인 휴리스틱 점수
    score_weight_ip_direct: int = 40
    score_weight_typo_domain: int = 40
    score_weight_punycode_idn: int = 35
    score_weight_no_https: int = 30
    score_weight_new_domain: int = 30
    score_weight_subdomain_overuse: int = 25
    score_weight_open_redirect_param: int = 20
    score_weight_hyphen_overuse: int = 20
    score_weight_suspicious_tld: int = 20
    score_weight_dga_like: int = 15
    score_weight_hosting_platform: int = 15

    # 휴리스틱 점수 캡 — GSB/URLhaus(각 50) high-confidence 시그널을 합산이 압도하지 않도록 클램프
    domain_heuristic_score_cap: int = 80

    # DGA 탐지 임계값 — 0.7이면 netflix/spotify/snapchat 등 긴 영어 브랜드 오탐
    dga_entropy_threshold: float = 3.5
    dga_consonant_ratio_threshold: float = 0.8

    # 서브도메인 레이블 임계값
    subdomain_label_threshold: int = 4

    # 하이픈/라벨 길이 임계값 — 20자 미만이면 standardchartered(17), samsungelectronics(18) 등 오탐
    hyphen_count_threshold: int = 3
    domain_label_length_threshold: int = 20

    # Spring 통신
    internal_api_key: str
    spring_internal_url: str = "http://localhost:8080"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
