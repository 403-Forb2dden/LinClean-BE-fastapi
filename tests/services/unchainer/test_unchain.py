"""unchain_url 단위 테스트.

httpx.AsyncClient를 모킹해서 네트워크 요청 없이 리다이렉트 체인 로직을 검증.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from app.services.unchainer.unchain import unchain_url


def _make_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """테스트용 httpx.Response 생성."""
    resp = httpx.Response(
        status_code=status_code,
        headers=headers or {},
        request=httpx.Request("HEAD", "https://example.com"),
    )
    resp.aclose = AsyncMock()  # 스트리밍 close 호출 안전하게 처리
    return resp


def _mock_client(
    responses: list[httpx.Response] | None = None,
    *,
    side_effect=None,
) -> AsyncMock:
    """httpx.AsyncClient mock 생성. 반복되는 보일러플레이트 제거용.

    build_request + send(stream=True) 방식에 맞춰 mock 구성.
    side_effect 함수는 기존과 동일하게 (method, *args, **kwargs) 시그니처.
    """
    mock = AsyncMock()

    # build_request는 동기 메서드 — 실제 httpx.Request 반환
    mock.build_request = lambda method, url, **kw: httpx.Request(method, url, **kw)

    if side_effect is not None:
        if isinstance(side_effect, BaseException):
            mock.send = AsyncMock(side_effect=side_effect)
        else:
            _original = side_effect

            async def _send_wrapper(req, **kwargs):
                if asyncio.iscoroutinefunction(_original):
                    return await _original(req.method, str(req.url))
                return _original(req.method, str(req.url))

            mock.send = AsyncMock(side_effect=_send_wrapper)
    elif responses is not None:
        mock.send = AsyncMock(side_effect=responses)
    else:
        mock.send = AsyncMock(return_value=_make_response(200))

    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


_PATCH_TARGET = "app.services.unchainer.unchain.httpx.AsyncClient"


@pytest.fixture(autouse=True)
def _bypass_host_safety(monkeypatch):
    """기본적으로 SSRF 검사를 우회 — SSRF 전용 테스트에서만 직접 패치.

    unchain 의 모듈 싱글턴 _client 도 매 테스트에서 None 으로 리셋해, 패치된
    httpx.AsyncClient 가 새로 호출되어 mock client 가 _client 에 박히도록 보장한다.
    """
    from app.services.unchainer import unchain as unchain_module

    monkeypatch.setattr(
        "app.services.unchainer.unchain._check_host_safety",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(unchain_module, "_client", None)


class TestBasicChain:
    """리다이렉트 없는 경우 / 단일·다중 hop 체인."""

    @pytest.mark.asyncio
    async def test_no_redirect(self) -> None:
        client = _mock_client([_make_response(200)])

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/")

        assert result.final_url == "https://example.com/"
        assert result.hop_count == 1
        assert result.hops[0].status_code == 200
        assert result.error is None
        assert not result.signals

    @pytest.mark.asyncio
    async def test_single_redirect(self) -> None:
        responses = [
            _make_response(301, {"location": "https://example.com/new"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/old")

        assert result.final_url == "https://example.com/new"
        assert result.hop_count == 2
        assert result.hops[0].status_code == 301
        assert result.hops[0].location == "https://example.com/new"
        assert result.hops[1].status_code == 200

    @pytest.mark.asyncio
    async def test_multi_hop_chain(self) -> None:
        responses = [
            _make_response(302, {"location": "https://a.com/2"}),
            _make_response(302, {"location": "https://a.com/3"}),
            _make_response(302, {"location": "https://a.com/final"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://a.com/1")

        assert result.final_url == "https://a.com/final"
        assert result.hop_count == 4


class TestRedirectLoop:
    """무한 루프 감지."""

    @pytest.mark.asyncio
    async def test_loop_detected(self) -> None:
        """A → B → A 루프 감지 시 redirect_loop 신호."""
        responses = [
            _make_response(302, {"location": "https://b.com/"}),
            _make_response(302, {"location": "https://a.com/"}),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://a.com/")

        assert "redirect_loop" in result.signals
        assert result.hop_count == 2


class TestMaxHops:
    """hop 수 제한."""

    @pytest.mark.asyncio
    async def test_max_hops_reached(self) -> None:
        hop_count = 0

        def _side_effect(*args: object, **kwargs: object) -> httpx.Response:
            nonlocal hop_count
            hop_count += 1
            return _make_response(
                302,
                {"location": f"https://example.com/{hop_count}"},
            )

        client = _mock_client(side_effect=_side_effect)

        with (
            patch(_PATCH_TARGET, return_value=client),
            patch("app.services.unchainer.unchain.settings") as mock_settings,
        ):
            mock_settings.unchain_max_hops = 5
            mock_settings.unchain_timeout_seconds = 5.0
            mock_settings.unchain_connect_timeout_seconds = 3.0
            mock_settings.unchain_chain_timeout_seconds = 20.0
            mock_settings.unchain_user_agent = "test-agent"
            result = await unchain_url("https://example.com/start")

        assert "max_hops_reached" in result.signals
        assert result.hop_count == 5


class TestSchemeDowngrade:
    """https → http 스킴 다운그레이드 감지."""

    @pytest.mark.asyncio
    async def test_scheme_downgrade_signal(self) -> None:
        responses = [
            _make_response(302, {"location": "http://example.com/insecure"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/")

        assert "scheme_downgrade" in result.signals

    @pytest.mark.asyncio
    async def test_no_signal_on_http_to_https(self) -> None:
        responses = [
            _make_response(302, {"location": "https://example.com/secure"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("http://example.com/")

        assert "scheme_downgrade" not in result.signals


class TestCrossOrigin:
    """크로스 오리진 호스트 변화 감지."""

    @pytest.mark.asyncio
    async def test_cross_origin_signal(self) -> None:
        responses = [
            _make_response(302, {"location": "https://evil.com/phish"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://safe.com/link")

        assert any(s.startswith("cross_origin:") for s in result.signals)
        assert "cross_origin:safe.com->evil.com" in result.signals


class TestRelativeLocation:
    """상대 경로 Location 해석."""

    @pytest.mark.asyncio
    async def test_relative_path_resolved(self) -> None:
        responses = [
            _make_response(302, {"location": "/new-path"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/old-path")

        assert result.final_url == "https://example.com/new-path"
        assert result.hops[0].location == "https://example.com/new-path"

    @pytest.mark.asyncio
    async def test_raw_location_preserved(self) -> None:
        """상대 경로 원본 값이 raw_location에 보존되는지 확인."""
        responses = [
            _make_response(302, {"location": "/new-path"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/old-path")

        assert result.hops[0].raw_location == "/new-path"
        assert result.hops[0].location == "https://example.com/new-path"


class TestHeadFallback:
    """HEAD 실패 시 GET 폴백."""

    @pytest.mark.asyncio
    async def test_head_405_falls_back_to_get(self) -> None:
        responses = [
            _make_response(405),  # HEAD 실패
            _make_response(200),  # GET 성공
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/")

        assert result.hop_count == 1
        assert result.hops[0].method == "GET"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_head_timeout_falls_back_to_get(self) -> None:
        """HEAD에서 타임아웃 → GET으로 폴백해서 성공."""
        call_count = 0

        def _side_effect(method: str, *args: object, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if method == "HEAD":
                raise httpx.ReadTimeout("timed out")
            return _make_response(200)

        client = _mock_client(side_effect=_side_effect)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/")

        assert result.hop_count == 1
        assert result.hops[0].method == "GET"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_head_redirect_without_location_falls_back_to_get(self) -> None:
        """HEAD가 리다이렉트인데 Location 누락 → GET으로 폴백해서 체인 추적."""

        def _side_effect(method: str, url: str) -> httpx.Response:
            if url == "https://example.com/start":
                # HEAD는 301인데 Location 헤더 생략, GET은 정상 응답
                if method == "HEAD":
                    return _make_response(301)
                return _make_response(301, {"location": "https://example.com/final"})
            return _make_response(200)

        client = _mock_client(side_effect=_side_effect)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/start")

        assert result.error is None
        assert result.final_url == "https://example.com/final"
        assert result.hops[0].method == "GET"
        assert result.hops[0].status_code == 301

    @pytest.mark.asyncio
    async def test_head_connect_error_falls_back_to_get(self) -> None:
        """HEAD에서 ConnectError → GET으로 폴백해서 성공."""

        def _side_effect(method: str, *args: object, **kwargs: object) -> httpx.Response:
            if method == "HEAD":
                raise httpx.ConnectError("Connection refused")
            return _make_response(200)

        client = _mock_client(side_effect=_side_effect)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/")

        assert result.hop_count == 1
        assert result.hops[0].method == "GET"
        assert result.error is None


class TestErrorHandling:
    """네트워크·서버 에러 처리."""

    @pytest.mark.asyncio
    async def test_timeout_error(self) -> None:
        """HEAD·GET 모두 타임아웃이면 최종 에러."""
        client = _mock_client(side_effect=httpx.ReadTimeout("timed out"))

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://slow.example.com/")

        assert result.timed_out is True
        assert result.error == "timeout"

    @pytest.mark.asyncio
    async def test_dns_failure_via_connect_error(self) -> None:
        client = _mock_client(
            side_effect=httpx.ConnectError("[Errno -2] Name or service not known"),
        )

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://nonexistent.invalid/")

        assert result.error == "dns_failure"

    @pytest.mark.asyncio
    async def test_connection_refused(self) -> None:
        client = _mock_client(
            side_effect=httpx.ConnectError("Connection refused"),
        )

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://refused.example.com/")

        assert result.error is not None
        assert "connection_refused" in result.error

    @pytest.mark.asyncio
    async def test_server_error_5xx(self) -> None:
        client = _mock_client([_make_response(503)])

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://down.example.com/")

        assert result.error == "server_error_503"
        assert result.hop_count == 1
        assert result.hops[0].status_code == 503

    @pytest.mark.asyncio
    async def test_missing_location_header(self) -> None:
        # HEAD·GET 모두 Location 헤더 누락 — 최종적으로 missing_location_header
        client = _mock_client([_make_response(302), _make_response(302)])

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://broken.example.com/")

        assert result.error == "missing_location_header"


class TestChainTimeout:
    """전체 체인 총 timeout."""

    @pytest.mark.asyncio
    async def test_chain_timeout(self) -> None:
        """hop별로는 안 터지지만 전체 체인이 총 timeout을 초과하면 중단."""

        async def _slow_request(*args: object, **kwargs: object) -> httpx.Response:
            await asyncio.sleep(10)
            return _make_response(302, {"location": "https://example.com/next"})

        client = _mock_client(side_effect=_slow_request)

        with (
            patch(_PATCH_TARGET, return_value=client),
            patch("app.services.unchainer.unchain.settings") as mock_settings,
        ):
            mock_settings.unchain_max_hops = 20
            mock_settings.unchain_timeout_seconds = 5.0
            mock_settings.unchain_connect_timeout_seconds = 3.0
            mock_settings.unchain_chain_timeout_seconds = 0.1
            mock_settings.unchain_user_agent = "test-agent"
            result = await unchain_url("https://example.com/start")

        assert result.timed_out is True
        assert result.error == "chain_timeout"


class TestUnsafeScheme:
    """javascript:, data: 등 비허용 스킴 리다이렉트 차단."""

    @pytest.mark.asyncio
    async def test_javascript_scheme_blocked(self) -> None:
        responses = [
            _make_response(302, {"location": "javascript:alert(1)"}),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/")

        assert result.error == "unsafe_redirect_scheme:javascript"
        assert "unsafe_scheme:javascript" in result.signals

    @pytest.mark.asyncio
    async def test_data_scheme_blocked(self) -> None:
        responses = [
            _make_response(302, {"location": "data:text/html,<h1>phish</h1>"}),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://example.com/")

        assert result.error == "unsafe_redirect_scheme:data"
        assert "unsafe_scheme:data" in result.signals


class TestHopRecording:
    """hop 기록 정확성."""

    @pytest.mark.asyncio
    async def test_hop_records_method_and_url(self) -> None:
        responses = [
            _make_response(302, {"location": "https://b.com/"}),
            _make_response(200),
        ]
        client = _mock_client(responses)

        with patch(_PATCH_TARGET, return_value=client):
            result = await unchain_url("https://a.com/")

        assert result.hops[0].url == "https://a.com/"
        assert result.hops[0].method == "HEAD"
        assert result.hops[1].url == "https://b.com/"

    @pytest.mark.asyncio
    async def test_all_redirect_status_codes(self) -> None:
        """301, 302, 303, 307, 308 모두 리다이렉트로 처리."""
        from app.services.unchainer import unchain as unchain_module

        for code in (301, 302, 303, 307, 308):
            responses = [
                _make_response(code, {"location": "https://example.com/dest"}),
                _make_response(200),
            ]
            client = _mock_client(responses)

            # 모듈 싱글턴 — iteration 마다 None 으로 리셋해 새 mock client 가 박히도록.
            unchain_module._client = None
            with patch(_PATCH_TARGET, return_value=client):
                result = await unchain_url("https://example.com/src")

            assert result.hops[0].status_code == code, f"Failed for status {code}"
            assert result.final_url == "https://example.com/dest"


class TestSsrfProtection:
    """SSRF·DNS Rebinding 방어."""

    @pytest.mark.asyncio
    async def test_loopback_blocked(self) -> None:
        """127.0.0.1 등 루프백 주소 차단."""
        with patch(
            "app.services.unchainer.unchain._check_host_safety",
            new_callable=AsyncMock,
            return_value="ssrf_blocked",
        ):
            result = await unchain_url("http://127.0.0.1/admin")

        assert result.error == "ssrf_blocked"
        assert "ssrf_blocked" in result.signals
        assert result.hop_count == 0

    @pytest.mark.asyncio
    async def test_private_ip_blocked(self) -> None:
        """사설 IP 대역(10.x, 172.16.x, 192.168.x) 차단."""
        for url in (
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
        ):
            with patch(
                "app.services.unchainer.unchain._check_host_safety",
                new_callable=AsyncMock,
                return_value="ssrf_blocked",
            ):
                result = await unchain_url(url)

            assert result.error == "ssrf_blocked", f"Failed for {url}"
            assert "ssrf_blocked" in result.signals

    @pytest.mark.asyncio
    async def test_metadata_endpoint_blocked(self) -> None:
        """클라우드 메타데이터 엔드포인트(169.254.169.254) 차단."""
        with patch(
            "app.services.unchainer.unchain._check_host_safety",
            new_callable=AsyncMock,
            return_value="ssrf_blocked",
        ):
            result = await unchain_url("http://169.254.169.254/latest/meta-data/")

        assert result.error == "ssrf_blocked"
        assert "ssrf_blocked" in result.signals

    @pytest.mark.asyncio
    async def test_redirect_to_internal_blocked(self) -> None:
        """외부 URL이 내부 IP로 리다이렉트할 때 두 번째 hop에서 차단."""
        safety_call_count = 0

        async def _safety_per_hop(url: str) -> str | None:
            nonlocal safety_call_count
            safety_call_count += 1
            # 첫 번째 hop은 통과, 두 번째(내부 IP)는 차단
            if "internal" in url or "127.0.0.1" in url:
                return "ssrf_blocked"
            return None

        responses = [
            _make_response(302, {"location": "http://127.0.0.1/secret"}),
        ]
        client = _mock_client(responses)

        with (
            patch(_PATCH_TARGET, return_value=client),
            patch(
                "app.services.unchainer.unchain._check_host_safety",
                side_effect=_safety_per_hop,
            ),
        ):
            result = await unchain_url("https://evil.com/redirect")

        assert result.error == "ssrf_blocked"
        assert "ssrf_blocked" in result.signals

    @pytest.mark.asyncio
    async def test_public_url_passes(self) -> None:
        """공개 IP는 정상 통과."""
        client = _mock_client([_make_response(200)])

        with (
            patch(_PATCH_TARGET, return_value=client),
            patch(
                "app.services.unchainer.unchain._check_host_safety",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await unchain_url("https://example.com/")

        assert result.error is None
        assert "ssrf_blocked" not in result.signals


class TestIsPrivateIp:
    """_is_private_ip 단위 테스트."""

    def test_loopback(self) -> None:
        from app.services.unchainer.unchain import _is_private_ip

        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("::1") is True

    def test_private_ranges(self) -> None:
        from app.services.unchainer.unchain import _is_private_ip

        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("192.168.1.1") is True

    def test_link_local(self) -> None:
        from app.services.unchainer.unchain import _is_private_ip

        assert _is_private_ip("169.254.169.254") is True

    def test_public_ip(self) -> None:
        from app.services.unchainer.unchain import _is_private_ip

        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False

    def test_invalid_ip(self) -> None:
        from app.services.unchainer.unchain import _is_private_ip

        assert _is_private_ip("not-an-ip") is True
