"""AI 피싱 추론 어댑터 — 모델을 나중에 갈아끼울 수 있게 Protocol 로 분리.

모델 미정 상태에서는 NullAIProvider 로 동작. 실제 모델 연동은
set_ai_provider() 로 부팅 시 런타임에 교체한다 (Spring 측과의 호환성 유지용).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.schemas.content_analysis import AIVerdict, TokenUsage


@dataclass(frozen=True)
class AIPromptContext:
    final_url: str
    title: str | None
    has_password_field: bool
    has_meta_refresh: bool
    # frozen 데이터클래스는 deep-freeze 가 아니므로 mutable list 를 두면 type 계약과 어긋난다.
    # tuple 로 받아 호출 측이 의도치 않게 mutate 하는 경로를 차단.
    image_alts: tuple[str, ...]
    external_link_ratio: float | None
    # True 면 정적 추출이 결정적이지 않음 — has_password_field=False 를
    # "폼 없음" 으로 단정하면 안 된다.
    is_spa_shell: bool = False
    has_password_form_external_action: bool = False
    has_external_meta_refresh: bool = False
    # 상위 단계(도메인 휴리스틱·threat_db)에서 이미 잡힌 시그널 코드 목록.
    # AI 가 페이지 피처 단독으로는 결론 내기 약한 케이스에 사전 정보로 활용한다.
    # 예: TYPO_DOMAIN + 브랜드 title + 비밀번호 폼이면 단독 페이지 분석보다 강한 phishing 신호.
    upstream_signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class AIInference:
    verdict: AIVerdict
    reason: str
    # 어떤 모델이 응답했는지 + 토큰 사용량. 응답에 그대로 실어 비용/성능 관측에 쓴다.
    # 과거 호환 & 테스트 편의를 위해 옵셔널로 둔다 — 실제 프로바이더는 채워서 돌려준다.
    model: str | None = None
    token_usage: TokenUsage | None = None


class AIProvider(Protocol):
    async def infer(self, ctx: AIPromptContext) -> AIInference | None: ...


class NullAIProvider:
    """모델이 설정되지 않았을 때의 기본 구현. 추론을 시도하지 않고 None 반환.

    `fallback_reason` 이 None 이 아니면 "정상 NullProvider" 가 아니라 다른 프로바이더가
    부팅 시 폴백된 상태라는 뜻이다. analyze.py 가 이 값을 읽어 응답의 `ai_error` 로
    노출해 운영자가 NullProvider 정상 동작과 misconfigured 폴백을 구분할 수 있게 한다.
    """

    def __init__(self, *, fallback_reason: str | None = None) -> None:
        self.fallback_reason = fallback_reason

    async def infer(self, ctx: AIPromptContext) -> AIInference | None:
        return None


_provider: AIProvider = NullAIProvider()


def get_ai_provider() -> AIProvider:
    return _provider


def set_ai_provider(provider: AIProvider) -> None:
    """앱 부팅 시점에만 호출 — 파이프라인 실행 중 교체하면 race 위험."""
    global _provider
    _provider = provider
