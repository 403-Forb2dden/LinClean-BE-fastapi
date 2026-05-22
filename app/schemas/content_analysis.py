from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ContentSignal(StrEnum):
    BRAND_IMPERSONATION_FORM = "BRAND_IMPERSONATION_FORM"
    LOGO_ALT_IMPERSONATION = "LOGO_ALT_IMPERSONATION"
    CREDENTIAL_FORM_EXTERNAL = "CREDENTIAL_FORM_EXTERNAL"
    PII_COLLECTION_FORM = "PII_COLLECTION_FORM"
    SENSITIVE_ID_FIELD = "SENSITIVE_ID_FIELD"
    FINANCIAL_FIELD = "FINANCIAL_FIELD"
    RISKY_DOWNLOAD_LINK = "RISKY_DOWNLOAD_LINK"
    PUBLIC_AGENCY_LURE = "PUBLIC_AGENCY_LURE"
    KOREAN_LURE_TEXT = "KOREAN_LURE_TEXT"
    META_REFRESH = "META_REFRESH"
    EXTERNAL_META_REFRESH = "EXTERNAL_META_REFRESH"
    EXTERNAL_LINK_OVERUSE = "EXTERNAL_LINK_OVERUSE"
    # 초기 HTML 이 JS 마운트 셸만 담고 있어 정적 추출로 input/form 판정이 불가한 상태.
    # 점수 가산 없이 판정 불가 플래그로만 사용 — AI 프롬프트에도 힌트로 전달된다.
    SPA_SHELL = "SPA_SHELL"
    FETCH_FAILED = "FETCH_FAILED"
    SKIPPED_ALREADY_DANGER = "SKIPPED_ALREADY_DANGER"


class AIVerdict(StrEnum):
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class TokenUsage(BaseModel):
    """AI 호출 1건의 토큰 사용량. 모델 비용 · 프롬프트 튜닝 관측에 쓴다."""

    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class ContentAnalysisResult(BaseModel):
    final_url: str
    fetched: bool
    status_code: int | None = Field(
        default=None,
        description="HTTP status code observed when fetching final_url for content analysis",
    )
    score: int = 0
    signals: list[ContentSignal] = Field(
        default_factory=list,
        description=(
            "분석 결과 신호 코드. fetch 실패는 FETCH_FAILED, 선행 단계 danger 로 4단계가 "
            "건너뛰어진 경우는 SKIPPED_ALREADY_DANGER 가 들어간다. 분석 결과 차원의 진실원."
        ),
    )

    title: str | None = None
    has_password_field: bool = False
    has_password_form_external_action: bool = False
    has_meta_refresh: bool = False
    has_external_meta_refresh: bool = False
    external_link_ratio: float | None = None
    brand_impersonation: bool = False
    logo_alt_impersonation: bool = False
    # JS 마운트 셸로 판단돼 정적 추출이 결정적이지 않은 상태. 여기서 has_password_field=False 는
    # "폼 없음" 이 아니라 "판정 불가" 로 읽어야 한다.
    is_spa_shell: bool = False
    body_text_snippets: list[str] = Field(default_factory=list)
    form_field_summaries: list[str] = Field(default_factory=list)
    cta_texts: list[str] = Field(default_factory=list)
    download_links: list[str] = Field(default_factory=list)
    sensitive_field_types: list[str] = Field(default_factory=list)
    korean_lure_keywords: list[str] = Field(default_factory=list)
    public_agency_keywords: list[str] = Field(default_factory=list)

    ai_verdict: AIVerdict | None = None
    ai_reason: str | None = None
    reason: str | None = Field(
        default=None,
        description=(
            "AI 여부와 무관한 사용자 표시용 설명. 예: http_error_404 는 "
            "'페이지를 찾을 수 없습니다.' 로 내려간다."
        ),
    )
    ai_error: str | None = Field(
        default=None,
        description=(
            "AI 호출 실패/비활성 사유. "
            "ai_unavailable=API 호출 실패, provider_misconfigured=설정 강제 openai 인데 키 누락, "
            "None=정상 호출 또는 NullProvider 정상 동작."
        ),
    )
    # 실제로 응답한 모델 id — 설정 변경/폴백 상황에서도 추적 가능하도록 응답에 싣는다.
    ai_model: str | None = None
    ai_token_usage: TokenUsage | None = None

    error: str | None = Field(
        default=None,
        description=(
            "페치/스킵 사유 코드 — fetch 레이어의 진실원. "
            "timeout/connect_error/http_error_*/not_html/too_large/unexpected_redirect/"
            "blocked_host/unexpected/skipped_already_danger 중 하나. "
            "signals 와 동시에 채워질 수 있으나 의미는 다르다 (signals=결과 차원, error=원인 코드)."
        ),
    )


class FetchStatusView(BaseModel):
    ok: bool
    status_code: int | None = None
    html_length: int = 0
    error: str | None = None


class ExtractedFeaturesView(BaseModel):
    title: str | None = None
    has_password_field: bool = False
    has_password_form_external_action: bool = False
    has_meta_refresh: bool = False
    has_external_meta_refresh: bool = False
    external_link_ratio: float | None = None
    image_alts: list[str] = Field(default_factory=list)
    is_spa_shell: bool = False
    body_text_snippets: list[str] = Field(default_factory=list)
    form_field_summaries: list[str] = Field(default_factory=list)
    cta_texts: list[str] = Field(default_factory=list)
    download_links: list[str] = Field(default_factory=list)
    sensitive_field_types: list[str] = Field(default_factory=list)
    korean_lure_keywords: list[str] = Field(default_factory=list)
    public_agency_keywords: list[str] = Field(default_factory=list)


class FetchExtractResponse(BaseModel):
    """fetch 단계 상태 + 파싱 결과 + HTML preview."""

    url: str
    fetch: FetchStatusView
    features: ExtractedFeaturesView | None = None
    html_preview: str | None = Field(
        default=None,
        description="HTML 본문 앞부분(최대 2KB) — 파싱 원본 확인용",
    )
