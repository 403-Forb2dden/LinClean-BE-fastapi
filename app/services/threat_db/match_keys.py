"""URLhaus 조회·동기화에 쓰는 매칭 키 생성.

host 한 개가 기본이지만 GitHub/GitLab/Dropbox 같은 다중 테넌트 호스트는
계정/리포/공유 파일 레벨에서 악성 여부가 갈리므로 host+path-prefix 키만 사용한다.
"""

from __future__ import annotations

from urllib.parse import urlparse

from app.core.config import settings


def derive_keys(url: str) -> list[str]:
    """URL 에서 매칭 키 후보를 더 구체적인 순서로 반환.

    반환: [host_path] 또는 [host]
    host 추출 실패 시 빈 리스트.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return []

    required = settings.urlhaus_multitenant_hosts.get(host)
    if required is None or required <= 0:
        return [host]

    segments = [seg for seg in parsed.path.split("/") if seg]
    if len(segments) < required:
        return []

    prefix = "/".join(segments[:required])
    host_path = f"{host}/{prefix}"
    return [host_path]
