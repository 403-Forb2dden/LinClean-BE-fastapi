"""unchain_url 단위 테스트.

httpx.AsyncClient를 모킹해서 네트워크 요청 없이 리다이렉트 체인 로직을 검증.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
from app.services.unchainer.unchain import unchain_url


def _make_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """테스트용 httpx.Response 생성."""
    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        request=httpx.Request("HEAD", "https://example.com"),
    )


class TestBasicChain:
    """리다이렉트 없는 경우 / 단일·다중 hop 체인."""

    async def test_no_redirect(self) -> None:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://example.com/")

        assert result.final_url == "https://example.com/"
        assert result.hop_count == 1
        assert result.hops[0].status_code == 200
        assert result.error is None
        assert not result.signals

    async def test_single_redirect(self) -> None:
        responses = [
            _make_response(301, {"location": "https://example.com/new"}),
            _make_response(200),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://example.com/old")

        assert result.final_url == "https://example.com/new"
        assert result.hop_count == 2
        assert result.hops[0].status_code == 301
        assert result.hops[0].location == "https://example.com/new"
        assert result.hops[1].status_code == 200

    async def test_multi_hop_chain(self) -> None:
        responses = [
            _make_response(302, {"location": "https://a.com/2"}),
            _make_response(302, {"location": "https://a.com/3"}),
            _make_response(302, {"location": "https://a.com/final"}),
            _make_response(200),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://a.com/1")

        assert result.final_url == "https://a.com/final"
        assert result.hop_count == 4


class TestRedirectLoop:
    """무한 루프 감지."""

    async def test_loop_detected(self) -> None:
        """A → B → A 루프 감지 시 redirect_loop 신호."""
        responses = [
            _make_response(302, {"location": "https://b.com/"}),
            _make_response(302, {"location": "https://a.com/"}),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://a.com/")

        assert "redirect_loop" in result.signals
        assert result.hop_count == 2


class TestMaxHops:
    """hop 수 제한."""

    async def test_max_hops_reached(self) -> None:
        def _redirect(request: httpx.Request) -> httpx.Response:
            return _make_response(302, {"location": "https://example.com/next"})

        # 무한 리다이렉트지만 URL이 매번 같으므로 루프 감지가 먼저 발동됨.
        # URL을 매 hop마다 다르게 생성해야 max_hops 테스트 가능.
        hop_count = 0

        def _side_effect(*args: object, **kwargs: object) -> httpx.Response:
            nonlocal hop_count
            hop_count += 1
            return _make_response(
                302, {"location": f"https://example.com/{hop_count}"},
            )

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=_side_effect)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client),
            patch("app.services.unchainer.unchain.settings") as mock_settings,
        ):
            mock_settings.unchain_max_hops = 5
            mock_settings.unchain_timeout_seconds = 10.0
            mock_settings.unchain_per_hop_timeout_seconds = 5.0
            mock_settings.unchain_user_agent = "test-agent"
            result = await unchain_url("https://example.com/start")

        assert "max_hops_reached" in result.signals
        assert result.hop_count == 5


class TestSchemeDowngrade:
    """https → http 스킴 다운그레이드 감지."""

    async def test_scheme_downgrade_signal(self) -> None:
        responses = [
            _make_response(302, {"location": "http://example.com/insecure"}),
            _make_response(200),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://example.com/")

        assert "scheme_downgrade" in result.signals

    async def test_no_signal_on_http_to_https(self) -> None:
        responses = [
            _make_response(302, {"location": "https://example.com/secure"}),
            _make_response(200),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("http://example.com/")

        assert "scheme_downgrade" not in result.signals


class TestCrossOrigin:
    """크로스 오리진 호스트 변화 감지."""

    async def test_cross_origin_signal(self) -> None:
        responses = [
            _make_response(302, {"location": "https://evil.com/phish"}),
            _make_response(200),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://safe.com/link")

        assert any(s.startswith("cross_origin:") for s in result.signals)
        assert "cross_origin:safe.com->evil.com" in result.signals


class TestRelativeLocation:
    """상대 경로 Location 해석."""

    async def test_relative_path_resolved(self) -> None:
        responses = [
            _make_response(302, {"location": "/new-path"}),
            _make_response(200),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://example.com/old-path")

        assert result.final_url == "https://example.com/new-path"
        assert result.hops[0].location == "https://example.com/new-path"


class TestHeadFallback:
    """HEAD 실패 시 GET 폴백."""

    async def test_head_405_falls_back_to_get(self) -> None:
        responses = [
            _make_response(405),  # HEAD 실패
            _make_response(200),  # GET 성공
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://example.com/")

        assert result.hop_count == 1
        assert result.hops[0].method == "GET"
        assert result.error is None


class TestErrorHandling:
    """네트워크·서버 에러 처리."""

    async def test_timeout_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.ReadTimeout("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://slow.example.com/")

        assert result.timed_out is True
        assert result.error == "timeout"

    async def test_dns_failure_via_connect_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            side_effect=httpx.ConnectError(
                "[Errno -2] Name or service not known",
            ),
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://nonexistent.invalid/")

        assert result.error == "dns_failure"

    async def test_connection_refused(self) -> None:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused"),
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://refused.example.com/")

        assert result.error is not None
        assert "connection_refused" in result.error

    async def test_server_error_5xx(self) -> None:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(503))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://down.example.com/")

        assert result.error == "server_error_503"
        assert result.hop_count == 1
        assert result.hops[0].status_code == 503

    async def test_missing_location_header(self) -> None:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(302))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://broken.example.com/")

        assert result.error == "missing_location_header"


class TestHopRecording:
    """hop 기록 정확성."""

    async def test_hop_records_method_and_url(self) -> None:
        responses = [
            _make_response(302, {"location": "https://b.com/"}),
            _make_response(200),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.unchainer.unchain.httpx.AsyncClient", return_value=mock_client):
            result = await unchain_url("https://a.com/")

        assert result.hops[0].url == "https://a.com/"
        assert result.hops[0].method == "HEAD"
        assert result.hops[1].url == "https://b.com/"

    async def test_all_redirect_status_codes(self) -> None:
        """301, 302, 303, 307, 308 모두 리다이렉트로 처리."""
        for code in (301, 302, 303, 307, 308):
            responses = [
                _make_response(code, {"location": "https://example.com/dest"}),
                _make_response(200),
            ]
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=responses)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            with patch(
                "app.services.unchainer.unchain.httpx.AsyncClient",
                return_value=mock_client,
            ):
                result = await unchain_url("https://example.com/src")

            assert result.hops[0].status_code == code, f"Failed for status {code}"
            assert result.final_url == "https://example.com/dest"
