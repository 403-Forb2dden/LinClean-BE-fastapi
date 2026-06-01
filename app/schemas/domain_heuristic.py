from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class RdapInfo(BaseModel):
    domain: str
    registrar: str | None
    created_date: datetime | None
    expiry_date: datetime | None
    domain_age_days: int | None
    is_new_domain: bool


class DomainHeuristicSignal(StrEnum):
    IP_DIRECT = "IP_DIRECT"
    TYPO_DOMAIN = "TYPO_DOMAIN"
    PUNYCODE_IDN = "PUNYCODE_IDN"
    NEW_DOMAIN = "NEW_DOMAIN"
    SUBDOMAIN_OVERUSE = "SUBDOMAIN_OVERUSE"
    NO_HTTPS = "NO_HTTPS"
    OPEN_REDIRECT_PARAM = "OPEN_REDIRECT_PARAM"
    HYPHEN_OVERUSE = "HYPHEN_OVERUSE"
    SUSPICIOUS_TLD = "SUSPICIOUS_TLD"
    DGA_LIKE = "DGA_LIKE"
    HOSTING_PLATFORM = "HOSTING_PLATFORM"
    URL_USERINFO = "URL_USERINFO"
    BRAND_IN_URL = "BRAND_IN_URL"
    FREE_HOSTING_LURE = "FREE_HOSTING_LURE"
    SENSITIVE_PATH = "SENSITIVE_PATH"
    URL_SHORTENER = "URL_SHORTENER"
    REDIRECT_CROSS_ORIGIN = "REDIRECT_CROSS_ORIGIN"


class DomainHeuristicSkippedReason(StrEnum):
    THREAT_MATCHED = "threat_matched"


class DomainHeuristicResult(BaseModel):
    domain: str
    score: int
    signals: list[DomainHeuristicSignal]
    rdap: RdapInfo | None = None
    rdap_error: str | None = None
    skipped_reason: DomainHeuristicSkippedReason | None = None
