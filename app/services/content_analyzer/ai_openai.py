"""OpenAI Chat Completions 기반 피싱 추론 어댑터.

Structured Outputs (`response_format=json_schema`, `strict=True`) 로 JSON 포맷을
모델 측에서 강제한다. 클라이언트 측 파싱은 최소한으로 유지하고, 스키마 위반·
API 오류는 전부 None 으로 떨어뜨려 상위 analyze 에서 `ai_error` 로 기록한다.
asyncio.CancelledError 만 예외적으로 re-raise — 취소 신호를 삼키지 않는다.

모델 교체는 생성자 파라미터 또는 `settings.openai_model` 환경변수로 한다.
OpenAI 채팅 모델(gpt-4o-mini / gpt-4o / gpt-4.1-mini 등)은 전부 같은 코드로 돌아간다.
"""

from __future__ import annotations

import asyncio
import json

from openai import AsyncOpenAI
from openai.types.chat import (
    ChatCompletionMessageParam,
    ChatCompletionSystemMessageParam,
    ChatCompletionUserMessageParam,
)
from openai.types.shared_params import ResponseFormatJSONSchema
from openai.types.shared_params.response_format_json_schema import JSONSchema

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.content_analysis import AIVerdict, TokenUsage
from app.services.content_analyzer.ai import AIInference, AIPromptContext

logger = get_logger(__name__)

_VERDICT_SCHEMA: JSONSchema = {
    "name": "phishing_verdict",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": [v.value for v in AIVerdict],
            },
            "reason": {"type": "string"},
        },
        "required": ["verdict", "reason"],
        "additionalProperties": False,
    },
}

_RESPONSE_FORMAT: ResponseFormatJSONSchema = {
    "type": "json_schema",
    "json_schema": _VERDICT_SCHEMA,
}

_SYSTEM_PROMPT = (
    "당신은 웹 페이지 피싱 여부를 판정하는 보안 엔진이다. "
    "입력은 이미 크롤러가 뽑아놓은 구조화된 피처(title, 비밀번호 필드 유무, "
    "meta refresh 유무, 외부 링크 비율, 이미지 alt 텍스트, 최종 URL, spa_shell 플래그)와 "
    "선행 단계(도메인 휴리스틱·위협 DB)에서 이미 잡힌 시그널 코드 배열 upstream_signals 다. "
    "규칙 기반 점수는 이미 상위 레이어에서 계산되고 있으므로, 당신은 "
    "'이 페이지가 특정 브랜드를 사칭하거나 자격증명을 탈취하려 하는지' 를 "
    "뉘앙스 기반으로만 판정한다. "
    "upstream_signals 는 도메인/네트워크 레이어의 사전 정보다 — 단독 시그널이 아니라 "
    "페이지 피처와 결합해 판정을 강화하는 데 쓴다. 예: TYPO_DOMAIN + 브랜드 title + "
    "비밀번호 폼이면 단독 페이지 분석보다 강한 phishing 신호다. NEW_DOMAIN/IP_DIRECT 도 "
    "동일한 맥락에서 가중하되, 페이지 측 증거 없이 upstream_signals 만으로 phishing 을 "
    "확정하지는 않는다. "
    "spa_shell=true 이면 초기 HTML 이 JS 마운트 셸뿐이라 has_password_field=false 는 "
    "'폼이 없다' 가 아니라 '정적 추출로는 판정 불가' 를 의미한다. 이 경우 남은 단서"
    "(title/URL/이미지 alt/upstream_signals 등)만으로 단정하지 말고 suspicious 또는 benign 을 "
    "보수적으로 선택한다. "
    "verdict 는 phishing / suspicious / benign 중 하나. reason 은 한국어 1~2문장. "
    "확증이 없으면 benign 또는 suspicious 를 쓰고 phishing 은 보수적으로만 사용한다."
)


def _build_user_prompt(ctx: AIPromptContext) -> str:
    # 토큰 절약 차원에서 짧은 JSON 으로 직렬화. 중요 필드만 추려서 모델이 노이즈에 끌리지 않게 한다.
    payload = {
        "final_url": ctx.final_url,
        "title": ctx.title,
        "has_password_field": ctx.has_password_field,
        "has_meta_refresh": ctx.has_meta_refresh,
        "external_link_ratio": ctx.external_link_ratio,
        "spa_shell": ctx.is_spa_shell,
        # 과도하게 긴 alt 리스트는 비용만 늘리고 판정에 도움 안 됨
        "image_alts": list(ctx.image_alts[:10]),
        # 선행 단계 시그널 — 빈 배열이면 단독 페이지 분석과 동일.
        "upstream_signals": list(ctx.upstream_signals),
    }
    return json.dumps(payload, ensure_ascii=False)


def _extract_token_usage(completion: object) -> TokenUsage | None:
    # completion.usage 는 OpenAI SDK 가 채워주지만 스트리밍/에러 응답 등에선 비어있을 수 있다.
    usage = getattr(completion, "usage", None)
    if usage is None:
        return None
    prompt = getattr(usage, "prompt_tokens", None)
    completion_tokens = getattr(usage, "completion_tokens", None)
    total = getattr(usage, "total_tokens", None)
    if prompt is None or completion_tokens is None or total is None:
        return None
    return TokenUsage(
        prompt_tokens=int(prompt),
        completion_tokens=int(completion_tokens),
        total_tokens=int(total),
    )


def _parse_verdict(
    raw: str | None,
    *,
    model: str,
    token_usage: TokenUsage | None,
) -> AIInference | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("openai_ai.parse_error", raw=raw[:200])
        return None

    verdict_str = data.get("verdict")
    reason = data.get("reason")
    if not isinstance(verdict_str, str) or not isinstance(reason, str):
        return None

    try:
        verdict = AIVerdict(verdict_str)
    except ValueError:
        logger.warning("openai_ai.unknown_verdict", verdict=verdict_str)
        return None

    return AIInference(
        verdict=verdict,
        reason=reason,
        model=model,
        token_usage=token_usage,
    )


class OpenAIProvider:
    """OpenAI Chat Completions 기반 AIProvider 구현.

    - 모델/타임아웃/최대 출력 토큰은 생성자에서 오버라이드 가능. 미지정 시 settings 값을 사용.
      같은 클래스로 gpt-4o-mini, gpt-4o, gpt-4.1 등 OpenAI 계열 모델을 바로 스왑할 수 있다.
    - API 키가 비어있으면 infer() 는 즉시 None (NullAIProvider 와 동일 동작).
    - 요청 실패·파싱 실패는 전부 None 으로 흡수 → 파이프라인은 계속 돈다.
    - `asyncio.CancelledError` 는 re-raise.
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        timeout_seconds: float | None = None,
        max_output_tokens: int | None = None,
    ) -> None:
        # 생성자 인자가 우선, 없으면 settings 기본값. 인스턴스 생성 후에는 불변으로 본다.
        self._model = model if model is not None else settings.openai_model
        self._timeout = (
            timeout_seconds if timeout_seconds is not None else settings.openai_timeout_seconds
        )
        self._max_output_tokens = (
            max_output_tokens
            if max_output_tokens is not None
            else settings.openai_max_output_tokens
        )
        # 클라이언트는 호출 시점에 지연 생성 — 키가 없으면 아예 만들지 않는다.
        self._client: AsyncOpenAI | None = None
        # aclose() 후 재사용 방지. 더블 콜은 no-op, 이후 infer() 는 None 반환.
        self._closed: bool = False

    @property
    def model(self) -> str:
        return self._model

    def _get_client(self) -> AsyncOpenAI | None:
        if self._closed:
            # 정상 시나리오에선 lifespan 종료 후 호출이 없어야 한다. 호출이 들리면
            # provider 재바인딩이 누락된 신호이므로 silent 폴백 대신 한 번 경고로 남긴다.
            logger.warning("openai_ai.called_after_close", model=self._model)
            return None
        if not settings.openai_api_key:
            return None
        if self._client is None:
            self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        return self._client

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def infer(self, ctx: AIPromptContext) -> AIInference | None:
        client = self._get_client()
        if client is None:
            return None

        messages: list[ChatCompletionMessageParam] = [
            ChatCompletionSystemMessageParam(role="system", content=_SYSTEM_PROMPT),
            ChatCompletionUserMessageParam(role="user", content=_build_user_prompt(ctx)),
        ]
        try:
            completion = await client.chat.completions.create(
                model=self._model,
                messages=messages,
                response_format=_RESPONSE_FORMAT,
                max_tokens=self._max_output_tokens,
                temperature=0,
                timeout=self._timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "openai_ai.request_failed",
                error=str(exc),
                error_type=type(exc).__name__,
                model=self._model,
            )
            return None

        try:
            raw = completion.choices[0].message.content
        except (AttributeError, IndexError) as exc:
            logger.warning("openai_ai.unexpected_shape", error=str(exc))
            return None

        token_usage = _extract_token_usage(completion)
        return _parse_verdict(raw, model=self._model, token_usage=token_usage)
