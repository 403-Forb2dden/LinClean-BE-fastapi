"""fetch_page — httpx 기반 페이지 본문 취득."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from app.core.config import settings
from app.services.content_analyzer import fetch as fetch_module
from app.services.content_analyzer.fetch import fetch_page


@pytest.fixture(autouse=True)
def _reset_singleton_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """매 테스트마다 모듈 싱글턴 클라이언트를 리셋 — 테스트 간 mock 누수 방지."""
    fetch_module._client = None
    # SSRF DNS 2선이 unit 테스트에서 실제 외부 해석을 시도하면 느려지고 비결정적이 된다.
    # 명시적으로 false 반환하도록 패치하고, 해당 동작은 별도 케이스에서 검증한다.

    async def _no_block(_host: str) -> bool:
        return False

    monkeypatch.setattr(
        "app.services.content_analyzer.fetch._resolved_addrs_blocked", _no_block
    )
    yield
    fetch_module._client = None


def _make_stream_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> AsyncMock:
    """httpx.Response 스트림 mock — aiter_bytes + headers + status_code."""
    resp = AsyncMock()
    resp.status_code = status_code
    resp.headers = headers or {"content-type": "text/html; charset=utf-8"}
    resp.charset_encoding = "utf-8"

    async def _aiter_bytes() -> object:
        yield body

    resp.aiter_bytes = _aiter_bytes
    resp.aclose = AsyncMock()
    resp.aread = AsyncMock(return_value=body)
    return resp


def _patch_client(send_return: object | None = None, *, send_side_effect: object = None):
    """모듈 싱글턴 _get_client 를 mock 으로 갈아끼운다 — send/build_request 만 노출."""
    mock_client = AsyncMock()
    mock_client.build_request = lambda method, url, **kw: httpx.Request(method, url, **kw)
    if send_side_effect is not None:
        mock_client.send = AsyncMock(side_effect=send_side_effect)
    else:
        mock_client.send = AsyncMock(return_value=send_return)
    return patch(
        "app.services.content_analyzer.fetch._get_client", return_value=mock_client
    )


async def test_fetch_success_returns_html() -> None:
    body = b"<html><head><title>X</title></head><body>hi</body></html>"
    resp = _make_stream_response(200, body=body)
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")

    assert result.ok is True
    assert result.status_code == 200
    assert "<title>X</title>" in result.html
    assert result.error is None


async def test_fetch_timeout() -> None:
    with _patch_client(send_side_effect=httpx.TimeoutException("too slow")):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error == "timeout"
    assert result.html == ""


async def test_fetch_connect_error() -> None:
    with _patch_client(send_side_effect=httpx.ConnectError("dns")):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error == "connect_error"


async def test_fetch_http_4xx() -> None:
    resp = _make_stream_response(404, body=b"not found")
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error is not None
    assert result.error.startswith("http_error")
    assert result.status_code == 404


async def test_fetch_http_5xx() -> None:
    resp = _make_stream_response(502, body=b"")
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error is not None
    assert result.error.startswith("http_error")


async def test_fetch_rejects_redirect_status() -> None:
    """follow_redirects=False 이므로 3xx 을 받으면 에러로 처리."""
    resp = _make_stream_response(302, headers={"location": "https://other.test/"})
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error == "unexpected_redirect"


async def test_fetch_rejects_content_length_over_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "content_fetch_max_bytes", 1024)
    resp = _make_stream_response(
        200,
        headers={"content-type": "text/html", "content-length": "999999"},
    )
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error == "too_large"


async def test_fetch_rejects_when_stream_exceeds_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Content-Length 헤더가 없어도 스트림 누적량이 cap 을 넘으면 too_large 로 거절한다."""
    monkeypatch.setattr(settings, "content_fetch_max_bytes", 64)

    resp = AsyncMock()
    resp.status_code = 200
    resp.headers = {"content-type": "text/html"}
    resp.charset_encoding = "utf-8"

    async def _aiter_bytes() -> object:
        yield b"a" * 100
        yield b"b" * 100  # cap 초과 — 두 번째 청크는 무시되어야 함

    resp.aiter_bytes = _aiter_bytes
    resp.aclose = AsyncMock()

    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")

    assert result.ok is False
    assert result.error == "too_large"


async def test_fetch_rejects_non_html_content_type() -> None:
    resp = _make_stream_response(200, headers={"content-type": "image/png"}, body=b"\x89PNG")
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error == "not_html"


async def test_fetch_rejects_xhtml() -> None:
    """application/xhtml+xml 은 XXE 회색지대라 본 분석에서는 입력 단에서 잘라낸다."""
    resp = _make_stream_response(
        200,
        headers={"content-type": "application/xhtml+xml"},
        body=b"<html><title>x</title></html>",
    )
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")
    assert result.ok is False
    assert result.error == "not_html"


async def test_fetch_sets_user_agent_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """요청 헤더에 content_user_agents 풀에서 뽑은 UA 가 들어가야 한다."""
    monkeypatch.setattr(settings, "content_user_agents", ["TestUA/1.0"])
    sent_requests: list[httpx.Request] = []

    async def _capture_send(req: httpx.Request, **_kw: object) -> object:
        sent_requests.append(req)
        return _make_stream_response(200, body=b"<html></html>")

    mock_client = AsyncMock()
    mock_client.build_request = lambda method, url, **kw: httpx.Request(method, url, **kw)
    mock_client.send = _capture_send

    with patch(
        "app.services.content_analyzer.fetch._get_client", return_value=mock_client
    ):
        await fetch_page("https://example.test/")

    assert len(sent_requests) == 1
    assert sent_requests[0].headers["user-agent"] == "TestUA/1.0"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
        "http://[::1]/",
        "http://metadata.google.internal/",
    ],
)
async def test_fetch_rejects_internal_targets(url: str) -> None:
    """SSRF 1선 — 사설/loopback/link-local IP 와 잘 알려진 내부 호스트네임은 connect 전에 차단."""
    with patch(
        "app.services.content_analyzer.fetch._get_client"
    ) as get_client:
        result = await fetch_page(url)
    assert result.ok is False
    assert result.error == "blocked_host"
    # 호스트가 차단되면 클라이언트 자체를 가져오지 않는다.
    get_client.assert_not_called()


async def test_fetch_allows_public_host() -> None:
    """공인 IP/도메인은 통과 — 정상 경로 회귀 방지."""
    resp = _make_stream_response(200, body=b"<html></html>")
    with _patch_client(send_return=resp):
        result = await fetch_page("https://example.test/")
    assert result.ok is True


async def test_fetch_no_follow_redirects_config() -> None:
    """모듈 싱글턴 빌더가 follow_redirects=False 로 AsyncClient 를 생성하는지 확인."""
    with patch(
        "app.services.content_analyzer.fetch.httpx.AsyncClient"
    ) as client_class:
        fetch_module._build_client()
        kwargs = client_class.call_args.kwargs
        assert kwargs.get("follow_redirects") is False
        assert kwargs.get("verify") is True
        assert kwargs.get("trust_env") is False


def test_fetch_client_uses_configured_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """운영 egress 프록시를 설정하면 분석 fetch 가 그 경로를 사용해야 한다."""
    monkeypatch.setattr(settings, "content_fetch_proxy_url", "http://proxy.local:8080")
    with patch("app.services.content_analyzer.fetch.httpx.AsyncClient") as client_class:
        fetch_module._build_client()
        kwargs = client_class.call_args.kwargs
        assert kwargs.get("proxy") == "http://proxy.local:8080"


class TestSingletonClient:
    async def test_get_client_reuses_instance(self) -> None:
        """동일 프로세스 안에서 _get_client 는 같은 인스턴스를 돌려줘야 한다 — 풀 재사용 핵심."""
        client = AsyncMock()
        client.aclose = AsyncMock()
        with patch("app.services.content_analyzer.fetch._build_client", return_value=client):
            c1 = fetch_module._get_client()
            c2 = fetch_module._get_client()
            assert c1 is c2
            await fetch_module.aclose_client()

    async def test_aclose_client_resets_singleton(self) -> None:
        """aclose 후 _get_client 는 새 인스턴스를 만든다 — lifespan 재시작 시나리오 보호."""
        client1 = AsyncMock()
        client1.aclose = AsyncMock()
        client2 = AsyncMock()
        client2.aclose = AsyncMock()
        with patch(
            "app.services.content_analyzer.fetch._build_client",
            side_effect=[client1, client2],
        ):
            c1 = fetch_module._get_client()
            await fetch_module.aclose_client()
            assert fetch_module._client is None
            c2 = fetch_module._get_client()
            assert c2 is not c1
            await fetch_module.aclose_client()

    async def test_aclose_client_idempotent(self) -> None:
        await fetch_module.aclose_client()
        await fetch_module.aclose_client()


class TestDnsRebindGuard:
    """SSRF 2선 — 호스트네임이 사설 IP 로 풀리면 connect 전에 차단."""

    async def test_blocks_host_resolving_to_private_ip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _resolves_to_private(_host: str) -> bool:
            return True

        monkeypatch.setattr(
            "app.services.content_analyzer.fetch._resolved_addrs_blocked",
            _resolves_to_private,
        )
        # 클라이언트 측 send 가 호출되면 검증 실패 — 사전 차단되어야 한다
        with patch(
            "app.services.content_analyzer.fetch._get_client"
        ) as get_client:
            result = await fetch_page("https://evil-public.test/")
        assert result.ok is False
        assert result.error == "blocked_host"
        get_client.assert_not_called()

    async def test_passes_when_resolved_ips_public(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _resolves_public(_host: str) -> bool:
            return False

        monkeypatch.setattr(
            "app.services.content_analyzer.fetch._resolved_addrs_blocked",
            _resolves_public,
        )
        resp = _make_stream_response(200, body=b"<html></html>")
        with _patch_client(send_return=resp):
            result = await fetch_page("https://example.test/")
        assert result.ok is True

    async def test_dns_resolution_failure_does_not_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """getaddrinfo OSError 는 block 으로 격상하지 않는다 — connect 단계에서 자연 처리."""

        async def _raises(_host: str) -> bool:
            raise OSError("dns down")

        monkeypatch.setattr(
            "app.services.content_analyzer.fetch._resolved_addrs_blocked",
            _raises,
        )
        with _patch_client(send_side_effect=httpx.ConnectError("dns")):
            result = await fetch_page("https://example.test/")
        assert result.error == "connect_error"

    async def test_skips_resolution_for_ip_literal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """공인 IP 리터럴은 1선에서 통과 — 같은 IP 를 다시 해석할 필요 없으므로 2선을 건너뛴다."""
        called: list[str] = []

        async def _track(host: str) -> bool:
            called.append(host)
            return False

        monkeypatch.setattr(
            "app.services.content_analyzer.fetch._resolved_addrs_blocked",
            _track,
        )
        resp = _make_stream_response(200, body=b"<html></html>")
        with _patch_client(send_return=resp):
            await fetch_page("https://8.8.8.8/")
        assert called == []


def test_pick_user_agent_raises_on_empty_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    """UA 풀이 비면 침묵 폴백 대신 명시적으로 raise — 운영자가 misconfiguration 을 발견하게."""
    monkeypatch.setattr(settings, "content_user_agents", [])
    with pytest.raises(RuntimeError, match="content_user_agents"):
        fetch_module._pick_user_agent()
