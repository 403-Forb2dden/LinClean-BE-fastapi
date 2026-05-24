from __future__ import annotations

import tldextract

_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def extract_url_parts(url: str) -> tldextract.ExtractResult:
    return _EXTRACTOR(url)
