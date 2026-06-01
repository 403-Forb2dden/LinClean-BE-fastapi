from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "ac.kr",
        "co.in",
        "co.jp",
        "co.kr",
        "co.uk",
        "com.au",
        "com.br",
        "com.cn",
        "com.hk",
        "com.mx",
        "com.my",
        "com.sg",
        "com.tr",
        "com.tw",
        "edu.au",
        "go.kr",
        "gov.au",
        "gov.uk",
        "ne.kr",
        "net.cn",
        "or.kr",
        "org.cn",
        "re.kr",
        # Private hosting suffixes that phishing kits commonly abuse.
        "amazonaws.com",
        "azurewebsites.net",
        "backblazeb2.com",
        "duckdns.org",
        "firebaseapp.com",
        "fly.dev",
        "free.nf",
        "github.io",
        "gitlab.io",
        "glitch.me",
        "godaddysites.com",
        "herokuapp.com",
        "my.id",
        "netlify.app",
        "pages.dev",
        "railway.app",
        "render.com",
        "replit.app",
        "surge.sh",
        "vercel.app",
        "wasmer.app",
        "web.app",
        "workers.dev",
    }
)


@dataclass(frozen=True)
class ExtractResult:
    subdomain: str
    domain: str
    suffix: str

    @property
    def top_domain_under_public_suffix(self) -> str:
        if not self.domain or not self.suffix:
            return ""
        return f"{self.domain}.{self.suffix}"


def _hostname(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").strip(".").lower()


def extract_url_parts(url: str) -> ExtractResult:
    host = _hostname(url)
    if not host:
        return ExtractResult(subdomain="", domain="", suffix="")

    labels = [label for label in host.split(".") if label]
    if len(labels) == 1:
        return ExtractResult(subdomain="", domain=labels[0], suffix="")

    suffix_len = 1
    for size in range(min(3, len(labels) - 1), 1, -1):
        candidate = ".".join(labels[-size:])
        if candidate in _MULTI_LABEL_SUFFIXES:
            suffix_len = size
            break

    suffix = ".".join(labels[-suffix_len:])
    domain_index = len(labels) - suffix_len - 1
    if domain_index < 0:
        return ExtractResult(subdomain="", domain="", suffix=suffix)

    domain = labels[domain_index]
    subdomain = ".".join(labels[:domain_index])
    return ExtractResult(subdomain=subdomain, domain=domain, suffix=suffix)
