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
            "dropbox.com": 2,
            "www.dropbox.com": 2,
            "dropboxusercontent.com": 2,
            "dl.dropboxusercontent.com": 2,
            "www.dropboxusercontent.com": 2,
        }
    )

    # Scheduler / URLhaus 동기화
    scheduler_enabled: bool = True
    urlhaus_sync_on_startup: bool = True

    # RDAP
    rdap_bootstrap_url: str = "https://rdap.org/domain/"
    rdap_timeout_seconds: float = 3.0
    rdap_cache_ttl_seconds: int = 60 * 60 * 24 * 7  # 7d
    # TTL 동안 누적될 수 있는 도메인 엔트리 상한. 무작위 도메인 트래픽이 들어와도
    # 메모리가 무한 성장하지 않도록 LRU 로 끊는다. 일 100만 URL 기준 도메인 수 5만 이하 가정.
    rdap_cache_max_entries: int = 50_000
    rdap_new_domain_threshold_days: int = 30

    # 정규화
    normalizer_max_url_length: int = 1024

    # DNS 해석 캐시 — fetch / unchain 양쪽이 같은 호스트를 반복 해석하는 비용 제거.
    # SSRF 방어선이 의존하는 결과라 TTL 은 짧게 (30초) — 공격자가 캐시 hit 동안 IP 를
    # 사설 대역으로 재해석할 가능성을 최소화. 보안 위협보다 성능 보강이 주 목적.
    dns_cache_ttl_seconds: int = 30
    dns_cache_max_entries: int = 10_000

    # 언체이닝
    unchain_max_hops: int = 5
    unchain_timeout_seconds: float = 5.0
    unchain_connect_timeout_seconds: float = 3.0
    unchain_chain_timeout_seconds: float = 6.0
    schemeless_https_probe_timeout_seconds: float = 1.0
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
    score_weight_typo_domain: int = 30
    score_weight_punycode_idn: int = 35
    score_weight_no_https: int = 20
    score_weight_new_domain: int = 25
    score_weight_subdomain_overuse: int = 20
    score_weight_open_redirect_param: int = 31
    score_weight_hyphen_overuse: int = 20
    score_weight_suspicious_tld: int = 25
    score_weight_dga_like: int = 31
    score_weight_redirect_cross_origin: int = 15
    score_weight_hosting_platform: int = 20
    score_weight_url_userinfo: int = 45
    score_weight_brand_in_url: int = 30
    score_weight_free_hosting_lure: int = 25
    score_weight_sensitive_path: int = 20
    score_weight_url_shortener: int = 25

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

    # 페이지 콘텐츠 정적 분석 (4단계)
    content_fetch_timeout_seconds: float = 3.5
    content_fetch_connect_timeout_seconds: float = 2.0
    content_fetch_max_bytes: int = 2 * 1024 * 1024  # 2MiB 이상이면 끊고 분석
    # DNS rebinding 잔여 위험은 앱 레벨 사전 해석만으로 완전히 닫을 수 없다. 운영에서 분석 전용
    # egress 프록시를 두는 경우 이 값으로 fetch 트래픽을 강제 경유시킨다.
    content_fetch_proxy_url: str | None = None
    content_user_agents: list[str] = Field(
        default_factory=lambda: [
            # 분석 엔진이 동일 UA를 반복 노출하면 쉽게 블랙리스트되므로 풀에서 라운드로빈
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.0 Safari/605.1.15"
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/130.0.0.0 Safari/537.36"
            ),
        ]
    )
    content_external_link_ratio_threshold: float = 0.8
    # BS4 파싱은 입력 본문 대비 ~10배 메모리를 점유한다. FastAPI 동시성에 곱셈으로 폭주하는
    # 걸 막기 위해 추출 단계에 글로벌 세마포어를 둔다 — 동시성 N 이 와도 피크는 이 값 * per-page.
    content_extract_concurrency: int = 8
    # 정확도 우선 slow path. 정적 HTML 로 판정이 애매하거나 SPA 셸인 경우에만 브라우저
    # 렌더링 DOM 을 추가 분석한다. Playwright 미설치 환경에서는 degraded no-op.
    content_precision_enabled: bool = True
    content_precision_min_score: int = 20
    content_render_timeout_seconds: float = 4.0
    content_render_settle_ms: int = 500
    content_render_concurrency: int = 2

    # 콘텐츠 분석 점수
    score_weight_brand_impersonation: int = 50
    score_weight_logo_alt_impersonation: int = 10
    score_weight_credential_form_external: int = 45
    score_weight_pii_collection_form: int = 20
    score_weight_sensitive_id_field: int = 30
    score_weight_financial_field: int = 25
    score_weight_risky_download_link: int = 20
    score_weight_public_agency_lure: int = 20
    score_weight_korean_lure: int = 15
    score_weight_meta_refresh: int = 20
    score_weight_external_meta_refresh: int = 25
    score_weight_external_link_overuse: int = 5
    # 도달 실패(timeout/connect_error/HTTP 5xx 등)에 대한 보수적 가산.
    # not_html(이미지·PDF), too_large(대용량 정상 페이지), unexpected_redirect(unchainer 누락)는
    # 정상 컨텐츠 또는 파이프라인 정합성 문제로 보고 점수 가산 없이 시그널만 남긴다.
    score_weight_content_fetch_failed: int = 15
    score_weight_ai_phishing: int = 45
    score_weight_ai_suspicious: int = 31
    # 4단계 단독 캡 — 컨텐츠 분석 단계 안에서만 적용된다. 전 단계 합산은 별도로 score_total_cap 에서
    # 다시 100 으로 클램프되므로, 여기를 낮춰도 합산 상한이 자동으로 같이 낮아지는 게 아니다.
    content_analysis_score_cap: int = 100

    # 1~3단계 합산이 이 임계 이상이면 콘텐츠 정적 분석(네트워크·AI 비용)을 건너뛴다.
    # README 의 danger(61+) 구간과 정합.
    score_danger_threshold: int = 61
    # caution(31~60) 구간 진입 임계. 이 값 미만이면 safe.
    score_caution_threshold: int = 31
    # 단계별 점수 합산이 100 을 넘지 않도록 종합 점수에서 캡 적용.
    score_total_cap: int = 100

    # 동기 분석 SLA. 단계별 작업은 이 총 예산 안에서만 실행되어 단일 요청이 20초를 넘기지
    # 않도록 한다. 각 stage budget 은 외부 네트워크 timeout 이 순차 누적되는 것을 막기 위한 상한.
    pipeline_total_timeout_seconds: float = 20.0
    pipeline_unchain_timeout_seconds: float = 4.0
    pipeline_reputation_timeout_seconds: float = 5.0
    pipeline_domain_timeout_seconds: float = 4.0
    pipeline_content_timeout_seconds: float = 8.0

    # 4단계 AI 프로바이더 선택.
    # auto   : OPENAI_API_KEY 있으면 OpenAIProvider, 없으면 NullAIProvider
    # openai : 강제 OpenAIProvider (키 없으면 경고 + NullAIProvider 폴백)
    # null   : 비활성 (규칙 점수만 사용)
    ai_provider: Literal["auto", "openai", "null"] = "auto"

    # OpenAI — 모델 교체는 OPENAI_MODEL 한 줄로 끝난다 (gpt-4o-mini / gpt-4o / gpt-4.1-mini).
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_timeout_seconds: float = 5.0
    openai_max_output_tokens: int = 120

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
