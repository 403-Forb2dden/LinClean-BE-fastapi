"""run_pipeline 통합 회귀 — stage 추가 시 응답 스키마/순서 검증."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from app.core.config import settings
from app.schemas.content_analysis import ContentAnalysisResult, ContentSignal
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import PipelineFailure, PipelineStage, PipelineSuccess, Verdict
from app.schemas.threat_db import GSBMatch, GSBResult, ThreatDbResult, URLhausResult
from app.schemas.unchain import UnchainResult
from app.services.pipeline import run_pipeline

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _make_unchain(final_url: str) -> UnchainResult:
    return UnchainResult(input_url=final_url, final_url=final_url, hops=[], hop_count=0, signals=[])


def _make_threat(final_url: str) -> ThreatDbResult:
    return ThreatDbResult(
        final_url=final_url,
        is_malicious=False,
        sources_checked=2,
        gsb=GSBResult(checked=True),
        urlhaus=URLhausResult(checked=True),
    )


def _make_heuristic(domain: str) -> DomainHeuristicResult:
    return DomainHeuristicResult(
        domain=domain,
        score=15,
        signals=[DomainHeuristicSignal.HOSTING_PLATFORM],
        rdap=None,
        rdap_error="not_found",
    )


def _make_content(final_url: str, *, score: int = 0) -> ContentAnalysisResult:
    return ContentAnalysisResult(final_url=final_url, fetched=True, score=score, signals=[])


async def _run_with_scores(
    async_session: AsyncSession,
    *,
    final_url: str,
    threat: ThreatDbResult,
    heuristic_score: int,
    content_score: int = 0,
) -> PipelineSuccess:
    """verdict 매핑만 보고 싶을 때 쓰는 헬퍼 — stage 결과는 점수 외엔 의미 없음."""
    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = threat
        mock_heuristic.return_value = _heuristic_with_score(heuristic_score)
        mock_content.return_value = _make_content(final_url, score=content_score)

        result = await run_pipeline("aid-verdict", final_url, async_session)
    assert isinstance(result, PipelineSuccess)
    return result


@pytest.mark.asyncio
async def test_run_pipeline_includes_domain_heuristic_stage(async_session: AsyncSession) -> None:
    """domain_heuristic stage 추가가 응답 스키마에 정상 반영되는지 검증."""
    final_url = "https://example.com/"

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = _make_threat(final_url)
        mock_heuristic.return_value = _make_heuristic("example.com")
        mock_content.return_value = _make_content(final_url)

        result = await run_pipeline("aid-1", final_url, async_session)

    assert isinstance(result, PipelineSuccess)
    assert result.analysis_id == "aid-1"
    assert result.final_url == final_url
    assert result.stages.domain_heuristic.domain == "example.com"
    assert result.stages.domain_heuristic.signals == [DomainHeuristicSignal.HOSTING_PLATFORM]
    assert result.stages.content_analysis.final_url == final_url
    assert result.stages.content_analysis.fetched is True
    assert result.timings is not None
    assert result.timings.total_seconds >= 0
    assert result.timings.stages.normalize is not None
    assert result.timings.stages.unchain is not None
    assert result.timings.stages.threat_db is not None
    assert result.timings.stages.domain_heuristic is not None
    assert result.timings.stages.content_analysis is not None
    # threat_db → domain_heuristic → content_analysis 순서 — 모두 unchain.final_url 기준
    mock_heuristic.assert_awaited_once_with(final_url)
    mock_content.assert_awaited_once()
    args, kwargs = mock_content.await_args
    assert args == (final_url,)
    # _make_heuristic 가 HOSTING_PLATFORM 시그널을 가지므로 그대로 전달돼야 한다
    assert kwargs["upstream_signals"] == ("HOSTING_PLATFORM",)


@pytest.mark.asyncio
async def test_run_pipeline_normalize_failure_skips_heuristic(
    async_session: AsyncSession,
) -> None:
    """normalize 단계 실패 시 후속 단계가 호출되지 않아야 한다."""
    from app.core.exceptions import NormalizationError

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock) as mock_h,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_c,
    ):
        mock_norm.side_effect = NormalizationError("invalid")

        result = await run_pipeline("aid-2", "not a url", async_session)

    assert isinstance(result, PipelineFailure)
    assert result.failed_at_stage == PipelineStage.NORMALIZE
    assert result.timings is not None
    assert result.timings.total_seconds >= 0
    assert result.timings.stages.normalize is not None
    assert result.timings.stages.unchain is None
    assert result.timings.stages.threat_db is None
    assert result.timings.stages.domain_heuristic is None
    assert result.timings.stages.content_analysis is None
    mock_h.assert_not_awaited()
    mock_c.assert_not_awaited()


def _malicious_threat(final_url: str) -> ThreatDbResult:
    return ThreatDbResult(
        final_url=final_url,
        is_malicious=True,
        sources_checked=2,
        gsb=GSBResult(checked=True, is_threat=True, matches=[GSBMatch(threat_type="MALWARE")]),
        urlhaus=URLhausResult(checked=True, is_threat=False),
        threat_types=["MALWARE"],
    )


def _heuristic_with_score(score: int) -> DomainHeuristicResult:
    return DomainHeuristicResult(
        domain="example.com",
        score=score,
        signals=[],
        rdap=None,
        rdap_error=None,
    )


@pytest.mark.asyncio
async def test_run_pipeline_skips_content_when_gsb_malicious(
    async_session: AsyncSession,
) -> None:
    """GSB 매치로 is_malicious=True 면 heuristic 점수와 무관하게 4단계를 skip 한다."""
    final_url = "https://evil.test/"

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = _malicious_threat(final_url)
        # GSB(+50) + heuristic(20) = 70 >= 61 → 건너뜀
        mock_heuristic.return_value = _heuristic_with_score(20)

        result = await run_pipeline("aid-skip", final_url, async_session)

    assert isinstance(result, PipelineSuccess)
    # 네트워크·AI 비용을 아끼기 위해 analyze_content 는 호출되지 않아야 한다
    mock_content.assert_not_awaited()
    content = result.stages.content_analysis
    assert content.fetched is False
    assert content.error == "skipped_already_danger"
    assert ContentSignal.SKIPPED_ALREADY_DANGER in content.signals
    assert content.score == 0


@pytest.mark.asyncio
async def test_run_pipeline_runs_content_when_below_danger(
    async_session: AsyncSession,
) -> None:
    final_url = "https://ok.test/"

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = _make_threat(final_url)
        # heuristic 점수만으로 임계 미달 → 콘텐츠 분석 정상 수행
        mock_heuristic.return_value = _heuristic_with_score(10)
        mock_content.return_value = _make_content(final_url)

        await run_pipeline("aid-run", final_url, async_session)

    # heuristic 시그널 없는 경우 upstream_signals 는 빈 튜플로 전달돼야 한다
    mock_content.assert_awaited_once_with(final_url, upstream_signals=())


class TestVerdictAndScore:
    """PipelineSuccess.verdict / score 매핑 회귀."""

    async def test_safe_when_all_clean(self, async_session: AsyncSession) -> None:
        final_url = "https://clean.test/"
        result = await _run_with_scores(
            async_session,
            final_url=final_url,
            threat=_make_threat(final_url),
            heuristic_score=0,
            content_score=0,
        )
        assert result.verdict == Verdict.SAFE
        assert result.score == 0

    async def test_caution_in_middle_band(self, async_session: AsyncSession) -> None:
        """heuristic 35 단독 — caution(31~60) 구간."""
        final_url = "https://mid.test/"
        result = await _run_with_scores(
            async_session,
            final_url=final_url,
            threat=_make_threat(final_url),
            heuristic_score=35,
            content_score=0,
        )
        assert result.verdict == Verdict.CAUTION
        assert result.score == 35

    async def test_danger_by_score_alone(self, async_session: AsyncSession) -> None:
        """blacklist 미스라도 합산 점수가 임계(61) 이상이면 danger."""
        final_url = "https://heur-heavy.test/"
        result = await _run_with_scores(
            async_session,
            final_url=final_url,
            threat=_make_threat(final_url),
            heuristic_score=65,
            content_score=0,
        )
        assert result.verdict == Verdict.DANGER
        assert result.score == 65

    async def test_score_capped_at_100(self, async_session: AsyncSession) -> None:
        """단계별 점수 합이 100 을 넘으면 cap. preceding 임계 미만 → 4단계 합산까지 진입."""
        final_url = "https://overflow.test/"
        result = await _run_with_scores(
            async_session,
            final_url=final_url,
            threat=_make_threat(final_url),
            heuristic_score=10,
            content_score=95,
        )
        assert result.score == 100
        assert result.verdict == Verdict.DANGER

    async def test_danger_when_threat_matches_even_below_threshold(
        self, async_session: AsyncSession
    ) -> None:
        """GSB 매치 시 합산 점수가 임계 미만이어도 verdict 는 강제로 danger."""
        final_url = "https://blacklist.test/"
        # short-circuit 경로 — heuristic 은 placeholder, content skip
        with (
            patch("app.services.pipeline.normalize_url") as mock_norm,
            patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
            patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
            patch(
                "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
            ) as mock_heuristic,
            patch("app.services.pipeline.analyze_content", new_callable=AsyncMock),
        ):
            mock_norm.return_value = NormalizeResult(
                original_url=final_url, normalized_url=final_url
            )
            mock_unchain.return_value = _make_unchain(final_url)
            mock_threat.return_value = _malicious_threat(final_url)
            mock_heuristic.return_value = _heuristic_with_score(0)

            result = await run_pipeline("aid-blk", final_url, async_session)

        assert isinstance(result, PipelineSuccess)
        # GSB +50 만 합산되고 임계 61 미달이지만 is_malicious=True 라 verdict=danger
        assert result.score == 50
        assert result.verdict == Verdict.DANGER

    async def test_verdict_score_appear_before_stages_in_response(
        self, async_session: AsyncSession
    ) -> None:
        """직렬화 시 verdict/score 가 stages 보다 앞에 나와 클라이언트가 상단에서 바로 읽도록."""
        final_url = "https://order.test/"
        result = await _run_with_scores(
            async_session,
            final_url=final_url,
            threat=_make_threat(final_url),
            heuristic_score=10,
        )
        keys = list(result.model_dump().keys())
        assert keys.index("verdict") < keys.index("stages")
        assert keys.index("score") < keys.index("stages")


@pytest.mark.asyncio
async def test_run_pipeline_passes_upstream_signals_to_content_analysis(
    async_session: AsyncSession,
) -> None:
    """heuristic 시그널 + threat 매치 플래그가 analyze_content 의 upstream_signals 로 전달된다."""
    final_url = "https://typo-naverr.test/"

    weak_threat = ThreatDbResult(
        final_url=final_url,
        is_malicious=False,
        sources_checked=2,
        # 매치 자체는 False 라 short-circuit 안 일어나지만, 미래에 약한 매치만 있을 케이스 대비
        gsb=GSBResult(checked=True, is_threat=False),
        urlhaus=URLhausResult(checked=True, is_threat=False),
    )
    heuristic = DomainHeuristicResult(
        domain="typo-naverr.test",
        score=20,
        signals=[DomainHeuristicSignal.TYPO_DOMAIN, DomainHeuristicSignal.NEW_DOMAIN],
        rdap=None,
        rdap_error=None,
    )

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = weak_threat
        mock_heuristic.return_value = heuristic
        mock_content.return_value = _make_content(final_url)

        await run_pipeline("aid-up", final_url, async_session)

    mock_content.assert_awaited_once()
    args, kwargs = mock_content.await_args
    assert args == (final_url,)
    assert kwargs["upstream_signals"] == ("TYPO_DOMAIN", "NEW_DOMAIN")


@pytest.mark.asyncio
async def test_run_pipeline_runs_threat_and_heuristic_in_parallel(
    async_session: AsyncSession,
) -> None:
    """2·3단계는 서로 독립이므로 gather 로 동시에 진입해야 한다.

    각 stub 을 상대방의 Event 를 기다리게 만들어서, 순차 실행이면 데드락 →
    wait_for 타임아웃으로 실패하도록 유도한다. 병렬이면 둘 다 진입 후 통과.
    """
    final_url = "https://ok.test/"

    threat_started = asyncio.Event()
    heuristic_started = asyncio.Event()

    async def fake_threat_db(_session: AsyncSession, _url: str) -> ThreatDbResult:
        threat_started.set()
        await asyncio.wait_for(heuristic_started.wait(), timeout=1.0)
        return _make_threat(final_url)

    async def fake_heuristic(_url: str) -> DomainHeuristicResult:
        heuristic_started.set()
        await asyncio.wait_for(threat_started.wait(), timeout=1.0)
        return _heuristic_with_score(10)

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", side_effect=fake_threat_db),
        patch("app.services.pipeline.check_domain_heuristic", side_effect=fake_heuristic),
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_content.return_value = _make_content(final_url)

        result = await run_pipeline("aid-parallel", final_url, async_session)

    assert isinstance(result, PipelineSuccess)
    # 둘 다 실행됐고 4단계까지 이어졌는지 확인
    assert threat_started.is_set() and heuristic_started.is_set()
    mock_content.assert_awaited_once()
    args, _ = mock_content.await_args
    assert args == (final_url,)


@pytest.mark.asyncio
async def test_run_pipeline_cancelled_error_propagates_from_parallel_stage(
    async_session: AsyncSession,
) -> None:
    """병렬 단계 중 하나에서 CancelledError 가 나면 degraded 흡수 없이 상위로 올라가야 한다."""
    final_url = "https://ok.test/"

    async def cancelled_threat(_session: AsyncSession, _url: str) -> ThreatDbResult:
        raise asyncio.CancelledError

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", side_effect=cancelled_threat),
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_heuristic.return_value = _heuristic_with_score(10)

        with pytest.raises(asyncio.CancelledError):
            await run_pipeline("aid-cancel", final_url, async_session)


@pytest.mark.asyncio
async def test_run_pipeline_short_circuits_on_gsb_match_and_cancels_heuristic(
    async_session: AsyncSession,
) -> None:
    """GSB 매치 시: threat_db 결과가 나오자마자 heuristic 을 cancel 하고
    4단계도 skip 한 채 즉시 종료해야 한다. verdict 가 이미 danger 로 확정이므로.

    placeholder heuristic 의 domain 은 등록 가능 도메인(파이프라인 정상 경로와 동일)이어야
    하지 full host 가 들어가면 안 된다 — 다운스트림 버킷팅이 어긋난다.
    """
    final_url = "https://signin.evil.example.com/login"

    heuristic_finished = asyncio.Event()

    async def slow_heuristic(_url: str) -> DomainHeuristicResult:
        # RDAP 대기로 수 초 떠 있는 상황을 흉내낸다. cancel 되지 않으면 이벤트가 set 되어
        # 테스트가 그 사실을 검출한다.
        try:
            await asyncio.sleep(5.0)
        except asyncio.CancelledError:
            raise
        heuristic_finished.set()
        return _heuristic_with_score(10)

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch("app.services.pipeline.check_domain_heuristic", side_effect=slow_heuristic),
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = _malicious_threat(final_url)

        result = await run_pipeline("aid-sc", final_url, async_session)

    assert isinstance(result, PipelineSuccess)
    # heuristic 은 cancel 되어 본문이 끝까지 돌지 않았어야 한다
    assert heuristic_finished.is_set() is False
    # 4단계 분석은 skip
    mock_content.assert_not_awaited()
    content = result.stages.content_analysis
    assert content.fetched is False
    assert content.error == "skipped_already_danger"
    assert ContentSignal.SKIPPED_ALREADY_DANGER in content.signals
    # heuristic placeholder 가 채워져 스키마 유지 — domain 은 registrable domain
    heur = result.stages.domain_heuristic
    assert heur.score == 0
    assert heur.rdap_error is None
    assert heur.skipped_reason == "threat_matched"
    assert heur.domain == "example.com"


@pytest.mark.asyncio
async def test_short_circuit_uses_placeholder_even_when_heuristic_finishes_first(
    async_session: AsyncSession,
) -> None:
    """heuristic 이 먼저 끝났더라도 threat malicious 면 heuristic 점수는 placeholder(0).

    종전엔 task 종료 순서에 따라 heuristic 점수가 placeholder ↔ 실제 점수로 갈려
    동일 입력에 응답 score 가 비결정적이었다. 두 분기 모두 placeholder 로 통일하는
    회귀를 박는다 — verdict 는 DANGER 강제라 사용자 영향이 없지만 옵저버빌리티 보호.
    """
    final_url = "https://heur-fast-threat-mal.test/"

    async def slow_threat(_session: AsyncSession, _url: str) -> ThreatDbResult:
        # heuristic 보다 늦게 끝나도록 인위적 지연 — wait FIRST_COMPLETED 분기를 강제.
        await asyncio.sleep(0.05)
        return _malicious_threat(final_url)

    async def fast_heuristic(_url: str) -> DomainHeuristicResult:
        # heuristic 이 먼저 끝남 — 실제 점수가 있는 결과를 반환
        return _heuristic_with_score(40)

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", side_effect=slow_threat),
        patch("app.services.pipeline.check_domain_heuristic", side_effect=fast_heuristic),
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(
            original_url=final_url, normalized_url=final_url
        )
        mock_unchain.return_value = _make_unchain(final_url)

        result = await run_pipeline("aid-race", final_url, async_session)

    assert isinstance(result, PipelineSuccess)
    # heuristic 이 실제 점수(40) 를 가졌어도 placeholder 로 갈아치워져야 한다.
    assert result.stages.domain_heuristic.score == 0
    assert result.stages.domain_heuristic.rdap_error is None
    assert result.stages.domain_heuristic.skipped_reason == "threat_matched"
    # GSB(+50) + heuristic placeholder(0) + content skip(0) = 50, verdict 는 DANGER 강제.
    assert result.score == 50
    assert result.verdict == Verdict.DANGER
    mock_content.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_pipeline_short_circuits_on_urlhaus_match(
    async_session: AsyncSession,
) -> None:
    """URLhaus 단독 매치도 동일하게 조기 종료 — threat_db.is_malicious 가 True 이기 때문."""
    final_url = "https://urlhaus-hit.test/"

    urlhaus_only = ThreatDbResult(
        final_url=final_url,
        is_malicious=True,
        sources_checked=2,
        gsb=GSBResult(checked=True, is_threat=False),
        urlhaus=URLhausResult(checked=True, is_threat=True),
    )

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = urlhaus_only
        mock_heuristic.return_value = _heuristic_with_score(0)

        result = await run_pipeline("aid-urlhaus", final_url, async_session)

    assert isinstance(result, PipelineSuccess)
    mock_content.assert_not_awaited()
    assert result.stages.content_analysis.error == "skipped_already_danger"


@pytest.mark.asyncio
async def test_run_pipeline_skips_content_when_heuristic_alone_exceeds_threshold(
    async_session: AsyncSession,
) -> None:
    """위협 DB 미매치여도 휴리스틱만으로 danger 구간이면 건너뛴다."""
    final_url = "https://typo-naverr.test/"

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
        patch("app.services.pipeline.analyze_content", new_callable=AsyncMock) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = _make_threat(final_url)
        mock_heuristic.return_value = _heuristic_with_score(settings.score_danger_threshold)

        await run_pipeline("aid-heur", final_url, async_session)

    mock_content.assert_not_awaited()
