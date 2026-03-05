from __future__ import annotations

import os
import re
from urllib.parse import urlparse

IOC_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IOC_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = sorted(set(IOC_URL_PATTERN.findall(text)))
    ips = sorted(set(IOC_IP_PATTERN.findall(text)))
    domains = sorted(set(IOC_DOMAIN_PATTERN.findall(text)))
    for url in urls:
        host = urlparse(url).hostname
        if host:
            domains.append(host)
    return {
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "urls": urls,
    }


def _csv_env(var_name: str) -> set[str]:
    raw = os.getenv(var_name, "")
    return {v.strip().lower() for v in raw.split(",") if v.strip()}


def is_allowlisted_domain(domain: str) -> bool:
    allowlist = _csv_env("ALLOWLIST_DOMAINS")
    return domain.lower() in allowlist


def is_denylisted_domain(domain: str) -> bool:
    denylist = _csv_env("DENYLIST_DOMAINS")
    return domain.lower() in denylist
