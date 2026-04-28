"""HTML 페이지에서 피싱 신호 후보 필드를 추출한다.

여기서는 "위험하다"는 판단을 하지 않는다. 단순 추출만 담당하고,
점수화·브랜드 비교는 signals.py 가 맡는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

# href 가 상대 경로(빈 scheme)이면 base_url 과 urljoin 후 http(s) 로 정규화되므로
# 여기서 검사 시점엔 이 둘만 보면 충분하다.
_NAV_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# 주류 프레임워크의 마운트 컨테이너. 번들이 로드돼야 실제 DOM 이 생긴다.
# - root      : React (CRA, Vite React)
# - app       : Vue 2/3 CLI 기본
# - __next    : Next.js (SSR 없이 빌드된 경우)
# - __nuxt    : Nuxt
# - __layout  : SvelteKit 구버전
# - svelte    : Svelte/SvelteKit
# - q-app     : Quasar/Qwik
_SPA_MOUNT_IDS: frozenset[str] = frozenset(
    {"root", "app", "__next", "__nuxt", "__layout", "svelte", "q-app"}
)

# Angular 는 id 가 아니라 커스텀 요소 태그로 마운트한다.
_SPA_MOUNT_TAGS: frozenset[str] = frozenset({"app-root", "ng-app"})

# alt 무제한 수집 시 alt 수만 개를 박은 페이지에서 signals 의 브랜드 매칭 비용이 선형으로 증폭.
# AI 프롬프트도 어차피 [:10] 으로 자르니 추출 단계에서 상한으로 막아둔다.
_MAX_IMAGE_ALTS = 200


@dataclass
class ExtractedFeatures:
    title: str | None = None
    has_password_field: bool = False
    has_meta_refresh: bool = False
    external_link_ratio: float | None = None
    image_alts: list[str] = field(default_factory=list)
    is_spa_shell: bool = False


def _normalize_host(host: str | None) -> str:
    if not host:
        return ""
    host = host.lower()
    return host.removeprefix("www.")


def _compute_external_link_ratio(soup: BeautifulSoup, base_url: str) -> float | None:
    base_host = _normalize_host(urlparse(base_url).hostname)
    total = 0
    external = 0
    for a in soup.find_all("a"):
        href = a.get("href")
        if not href or not isinstance(href, str):
            continue
        joined = urljoin(base_url, href.strip())
        parsed = urlparse(joined)
        if parsed.scheme not in _NAV_SCHEMES:
            # mailto: / tel: / javascript: 등 네비게이션이 아닌 링크는 비율 분모에서 제외
            continue
        total += 1
        if _normalize_host(parsed.hostname) != base_host:
            external += 1

    if total == 0:
        return None
    return external / total


def _extract_title(soup: BeautifulSoup) -> str | None:
    if soup.title is None or soup.title.string is None:
        return None
    text = soup.title.string.strip()
    return text or None


def _has_password_field(soup: BeautifulSoup) -> bool:
    for inp in soup.find_all("input"):
        t = inp.get("type")
        if isinstance(t, str) and t.lower() == "password":
            return True
    return False


def _has_meta_refresh(soup: BeautifulSoup) -> bool:
    # http-equiv=refresh 만 보고 단정하면 헤더만 무의미하게 박힌 페이지가 잘못 매치된다.
    # 실제 자동 리다이렉트 의도가 있으려면 content 도 비어있지 않아야 한다.
    for meta in soup.find_all("meta"):
        http_equiv = meta.get("http-equiv")
        if not (isinstance(http_equiv, str) and http_equiv.lower() == "refresh"):
            continue
        content = meta.get("content")
        if isinstance(content, str) and content.strip():
            return True
    return False


_SPA_MOUNT_ID_SELECTOR: str = ", ".join(f'div[id="{i}"]' for i in _SPA_MOUNT_IDS)


def _detect_spa_shell(soup: BeautifulSoup) -> bool:
    """초기 HTML 이 JS 마운트 셸만 담고 있는지 여부.
    form/input 이 이미 있으면 SSR 됐거나 완전 정적 페이지이므로 판정 불가 대상 아님.
    그 상태에서 주요 프레임워크 마운트 컨테이너(id/태그)가 있으면 SPA 셸로 본다.

    div 마운트 검사는 CSS 셀렉터로 한 번에 — 모든 div 를 순회하지 않는다.
    HTML5 의 id 매칭이 case-sensitive 라 셀렉터로는 정확 매치만 잡고, 대문자 ID 도
    수용하던 종전 동작은 fallback 루프로 유지한다.
    """
    if soup.find("form") is not None or soup.find("input") is not None:
        return False
    if soup.select_one(_SPA_MOUNT_ID_SELECTOR) is not None:
        return True
    for div in soup.find_all("div"):
        div_id = div.get("id")
        if isinstance(div_id, str) and div_id.lower() in _SPA_MOUNT_IDS:
            return True
    return any(soup.find(tag_name) is not None for tag_name in _SPA_MOUNT_TAGS)


def _collect_image_alts(soup: BeautifulSoup) -> list[str]:
    alts: list[str] = []
    for img in soup.find_all("img"):
        if len(alts) >= _MAX_IMAGE_ALTS:
            break
        alt = img.get("alt")
        if not isinstance(alt, str):
            continue
        alt = alt.strip()
        if alt:
            alts.append(alt)
    return alts


def extract_features(html: str, base_url: str) -> ExtractedFeatures:
    soup = BeautifulSoup(html or "", "html.parser")
    return ExtractedFeatures(
        title=_extract_title(soup),
        has_password_field=_has_password_field(soup),
        has_meta_refresh=_has_meta_refresh(soup),
        external_link_ratio=_compute_external_link_ratio(soup, base_url),
        image_alts=_collect_image_alts(soup),
        is_spa_shell=_detect_spa_shell(soup),
    )
