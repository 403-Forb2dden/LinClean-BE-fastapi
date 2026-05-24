"""HTML 페이지에서 피싱 신호 후보 필드를 추출한다.

여기서는 "위험하다"는 판단을 하지 않는다. 단순 추출만 담당하고,
점수화·브랜드 비교는 signals.py 가 맡는다.

파서는 lxml. 순수 파이썬 html.parser 대비 속도·메모리 모두 유리해서 단건 비용을 줄인다.
대신 BS4 가 모든 노드를 Tag 래퍼로 감싸는 비용은 그대로라 동시성 N 에 곱셈으로 폭주할 수 있어,
extract_features_async() 에 글로벌 세마포어 + to_thread 를 둬 피크 메모리에 천장을 박았다.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from bs4.element import Tag

from app.core.config import settings

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

# anchor / input / meta / div 등 일반 태그 순회 상한. fetch 단의 max_bytes(2MiB) 로 파싱
# 입력은 이미 캡 됐지만, 그 안에서도 노드를 압축적으로 쌓은 페이지(예: <a> 만 50만 개)에서
# find_all 의 매칭 비용이 폭주하지 않도록 두 번째 방어선을 둔다.
_MAX_NODES_PER_TAG = 1000
_MAX_TEXT_SNIPPETS = 40
_MAX_TEXT_CHARS = 180
_MAX_FORM_FIELD_SUMMARIES = 80
_MAX_CTA_TEXTS = 40
_MAX_DOWNLOAD_LINKS = 40
_RISKY_DOWNLOAD_EXTENSIONS: frozenset[str] = frozenset(
    {".apk", ".ipa", ".exe", ".msi", ".dmg", ".scr", ".bat", ".cmd", ".js", ".vbs"}
)

_KOREAN_LURE_KEYWORDS: tuple[str, ...] = (
    "지원금",
    "환급금",
    "택배",
    "부고",
    "청첩장",
    "과태료",
    "건강보험",
    "정부기관",
    "카카오톡",
    "인증번호",
    "otp",
)

_PUBLIC_AGENCY_KEYWORDS: tuple[str, ...] = (
    "국민건강보험",
    "건강보험공단",
    "건강보험",
    "정부24",
    "정부",
    "공단",
    "국세청",
    "관세청",
    "경찰청",
    "검찰청",
    "고용노동부",
    "보건복지부",
    "행정안전부",
)

_SENSITIVE_FIELD_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("resident_registration_number", ("resident_registration", "rrn", "주민등록", "주민번호")),
    ("phone", ("mobile", "phone", "tel", "휴대폰", "전화번호")),
    ("card", ("card_number", "credit_card", "creditcard", "카드번호", "카드")),
    ("cvc", ("cvc", "cvv")),
    ("account", ("account", "bank", "계좌", "은행")),
    ("otp", ("otp", "auth_code", "verification_code", "인증번호", "인증")),
)


@dataclass
class ExtractedFeatures:
    title: str | None = None
    has_password_field: bool = False
    has_password_form_external_action: bool = False
    has_meta_refresh: bool = False
    has_external_meta_refresh: bool = False
    external_link_ratio: float | None = None
    image_alts: list[str] = field(default_factory=list)
    is_spa_shell: bool = False
    body_text_snippets: list[str] = field(default_factory=list)
    form_field_summaries: list[str] = field(default_factory=list)
    cta_texts: list[str] = field(default_factory=list)
    download_links: list[str] = field(default_factory=list)
    sensitive_field_types: list[str] = field(default_factory=list)
    korean_lure_keywords: list[str] = field(default_factory=list)
    public_agency_keywords: list[str] = field(default_factory=list)


def _normalize_host(host: str | None) -> str:
    if not host:
        return ""
    host = host.lower()
    return host.removeprefix("www.")


def _is_external_nav_url(raw_url: str, base_url: str) -> bool:
    joined = urljoin(base_url, raw_url.strip())
    parsed = urlparse(joined)
    if parsed.scheme not in _NAV_SCHEMES:
        return False
    base_host = _normalize_host(urlparse(base_url).hostname)
    return _normalize_host(parsed.hostname) != base_host


def _compute_external_link_ratio(soup: BeautifulSoup, base_url: str) -> float | None:
    base_host = _normalize_host(urlparse(base_url).hostname)
    total = 0
    external = 0
    for a in soup.find_all("a", limit=_MAX_NODES_PER_TAG):
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
    return soup.find("input", attrs={"type": _is_password_type}) is not None


def _is_password_type(value: object) -> bool:
    return isinstance(value, str) and value.lower() == "password"


def _has_password_form_external_action(soup: BeautifulSoup, base_url: str) -> bool:
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": _is_password_type}) is None:
            continue
        action = form.get("action")
        if isinstance(action, str) and action.strip():
            return _is_external_nav_url(action, base_url)
    return False


_META_REFRESH_URL_RE = re.compile(r"(?:^|;)\s*url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)


def _meta_refresh_target(content: str) -> str | None:
    match = _META_REFRESH_URL_RE.search(content)
    if match is None:
        return None
    target = match.group(1).strip()
    return target or None


def _meta_refresh_info(soup: BeautifulSoup, base_url: str) -> tuple[bool, bool]:
    # http-equiv=refresh 만 보고 단정하면 헤더만 무의미하게 박힌 페이지가 잘못 매치된다.
    # 실제 자동 리다이렉트 의도가 있으려면 content 도 비어있지 않아야 한다.
    has_refresh = False
    has_external = False
    for meta in soup.find_all("meta", limit=_MAX_NODES_PER_TAG):
        http_equiv = meta.get("http-equiv")
        if not (isinstance(http_equiv, str) and http_equiv.lower() == "refresh"):
            continue
        content = meta.get("content")
        if not (isinstance(content, str) and content.strip()):
            continue
        has_refresh = True
        target = _meta_refresh_target(content)
        if target is not None and _is_external_nav_url(target, base_url):
            has_external = True
    return has_refresh, has_external


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
    for div in soup.find_all("div", limit=_MAX_NODES_PER_TAG):
        div_id = div.get("id")
        if isinstance(div_id, str) and div_id.lower() in _SPA_MOUNT_IDS:
            return True
    return any(soup.find(tag_name) is not None for tag_name in _SPA_MOUNT_TAGS)


def _collect_image_alts(soup: BeautifulSoup) -> list[str]:
    alts: list[str] = []
    # find_all 자체에 limit 을 박아 매칭 비용까지 끊어둔다 — 백만 개 <img> 페이지에서
    # _MAX_IMAGE_ALTS 만큼 쌓일 때까지 alts 길이만 검사하던 종전 동작은 매칭 비용이 살아 있었다.
    for img in soup.find_all("img", limit=_MAX_IMAGE_ALTS):
        alt = img.get("alt")
        if not isinstance(alt, str):
            continue
        alt = alt.strip()
        if alt:
            alts.append(alt)
    return alts


def _trim_text(text: str, *, max_chars: int = _MAX_TEXT_CHARS) -> str:
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip()


def _append_unique(items: list[str], value: str, *, limit: int) -> None:
    value = _trim_text(value)
    if value and value not in items and len(items) < limit:
        items.append(value)


def _collect_body_text_snippets(soup: BeautifulSoup) -> list[str]:
    snippets: list[str] = []
    body = soup.body or soup
    for text in body.stripped_strings:
        _append_unique(snippets, text, limit=_MAX_TEXT_SNIPPETS)
        if len(snippets) >= _MAX_TEXT_SNIPPETS:
            break
    return snippets


def _label_texts_by_for(soup: BeautifulSoup) -> dict[str, str]:
    labels: dict[str, str] = {}
    for label in soup.find_all("label", limit=_MAX_NODES_PER_TAG):
        if not isinstance(label, Tag):
            continue
        target = label.get("for")
        if isinstance(target, str) and target.strip():
            text = label.get_text(" ", strip=True)
            if text:
                labels[target.strip()] = _trim_text(text)
    return labels


def _attr_text(tag: Tag, name: str) -> str | None:
    value = tag.get(name)
    if isinstance(value, str):
        value = _trim_text(value)
        return value or None
    return None


def _field_label(control: Tag, labels_by_for: dict[str, str]) -> str | None:
    control_id = _attr_text(control, "id")
    if control_id and control_id in labels_by_for:
        return labels_by_for[control_id]
    parent_label = control.find_parent("label")
    if isinstance(parent_label, Tag):
        text = parent_label.get_text(" ", strip=True)
        return _trim_text(text) if text else None
    return None


def _collect_form_field_summaries(soup: BeautifulSoup) -> list[str]:
    labels_by_for = _label_texts_by_for(soup)
    summaries: list[str] = []
    for control in soup.find_all(["input", "textarea", "select"], limit=_MAX_NODES_PER_TAG):
        if not isinstance(control, Tag):
            continue
        parts: list[str] = []
        label = _field_label(control, labels_by_for)
        if label:
            parts.append(f"label={label}")
        for attr in ("name", "type", "placeholder", "id", "title", "aria-label"):
            value = _attr_text(control, attr)
            if value:
                parts.append(f"{attr}={value}")
        if parts:
            _append_unique(summaries, " ".join(parts), limit=_MAX_FORM_FIELD_SUMMARIES)
        if len(summaries) >= _MAX_FORM_FIELD_SUMMARIES:
            break
    return summaries


def _collect_cta_texts(soup: BeautifulSoup) -> list[str]:
    texts: list[str] = []
    for tag in soup.find_all(["button", "a", "input"], limit=_MAX_NODES_PER_TAG):
        if not isinstance(tag, Tag):
            continue
        text: str | None = None
        if tag.name == "input":
            input_type = (_attr_text(tag, "type") or "").lower()
            if input_type not in {"submit", "button", "reset"}:
                continue
            text = _attr_text(tag, "value")
        else:
            text = tag.get_text(" ", strip=True)
        if text:
            _append_unique(texts, text, limit=_MAX_CTA_TEXTS)
        if len(texts) >= _MAX_CTA_TEXTS:
            break
    return texts


def _is_risky_download_url(raw_url: str, base_url: str) -> str | None:
    joined = urljoin(base_url, raw_url.strip())
    parsed = urlparse(joined)
    if parsed.scheme not in _NAV_SCHEMES:
        return None
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in _RISKY_DOWNLOAD_EXTENSIONS):
        return joined
    return None


def _collect_download_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    links: list[str] = []
    for anchor in soup.find_all("a", limit=_MAX_NODES_PER_TAG):
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        resolved = _is_risky_download_url(href, base_url)
        if resolved is not None:
            _append_unique(links, resolved, limit=_MAX_DOWNLOAD_LINKS)
        if len(links) >= _MAX_DOWNLOAD_LINKS:
            break
    return links


def _collect_sensitive_field_types(form_field_summaries: list[str]) -> list[str]:
    found: list[str] = []
    haystack = "\n".join(form_field_summaries).lower()
    for field_type, keywords in _SENSITIVE_FIELD_KEYWORDS:
        if any(keyword.lower() in haystack for keyword in keywords):
            found.append(field_type)
    return found


def _collect_keywords(texts: list[str], keywords: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    haystack = "\n".join(texts).lower()
    for keyword in keywords:
        if keyword.lower() in haystack and keyword not in found:
            found.append(keyword)
    return found


def extract_features(html: str, base_url: str) -> ExtractedFeatures:
    soup = BeautifulSoup(html or "", "lxml")
    has_meta_refresh, has_external_meta_refresh = _meta_refresh_info(soup, base_url)
    body_text_snippets = _collect_body_text_snippets(soup)
    form_field_summaries = _collect_form_field_summaries(soup)
    cta_texts = _collect_cta_texts(soup)
    image_alts = _collect_image_alts(soup)
    download_links = _collect_download_links(soup, base_url)
    keyword_texts = [
        item
        for item in [
            _extract_title(soup) or "",
            *body_text_snippets,
            *form_field_summaries,
            *cta_texts,
            *image_alts,
        ]
        if item
    ]
    return ExtractedFeatures(
        title=_extract_title(soup),
        has_password_field=_has_password_field(soup),
        has_password_form_external_action=_has_password_form_external_action(soup, base_url),
        has_meta_refresh=has_meta_refresh,
        has_external_meta_refresh=has_external_meta_refresh,
        external_link_ratio=_compute_external_link_ratio(soup, base_url),
        image_alts=image_alts,
        is_spa_shell=_detect_spa_shell(soup),
        body_text_snippets=body_text_snippets,
        form_field_summaries=form_field_summaries,
        cta_texts=cta_texts,
        download_links=download_links,
        sensitive_field_types=_collect_sensitive_field_types(form_field_summaries),
        korean_lure_keywords=_collect_keywords(keyword_texts, _KOREAN_LURE_KEYWORDS),
        public_agency_keywords=_collect_keywords(keyword_texts, _PUBLIC_AGENCY_KEYWORDS),
    )


# 모듈 로드 시점이 아닌 첫 호출 때 만든다 — settings 가 환경변수로 동적으로 결정되는 경로를
# 막지 않기 위함. 3.10+ 부터 Semaphore 는 특정 루프에 묶이지 않으므로 이대로 안전하다.
_extract_semaphore: asyncio.Semaphore | None = None


def _get_extract_semaphore() -> asyncio.Semaphore:
    global _extract_semaphore
    if _extract_semaphore is None:
        _extract_semaphore = asyncio.Semaphore(settings.content_extract_concurrency)
    return _extract_semaphore


async def extract_features_async(html: str, base_url: str) -> ExtractedFeatures:
    """비동기 파이프라인용 진입점.

    BS4 파싱은 동기 CPU 작업이라 이벤트 루프를 블록한다. to_thread 로 오프로드해
    fetch·AI 호출 같은 IO 가 그동안 진행될 수 있게 한다. 동시에, BS4 트리는 본문 대비 ~10배로
    부풀므로 incoming concurrency 가 폭주하면 메모리도 같이 폭주한다 — 글로벌 세마포어로
    피크에 천장을 박아 운영 메모리 안에 가둔다.
    """
    sem = _get_extract_semaphore()
    async with sem:
        return await asyncio.to_thread(extract_features, html, base_url)
