"""Detect what kind of IOC a raw string is (ip / domain / url / hash)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .models import IOC, IOCType

# md5 = 32, sha1 = 40, sha256 = 64 hex chars
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

# A permissive domain check: labels of letters/digits/hyphens separated by dots,
# ending in a TLD of at least two letters.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,}$"
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def detect(value: str) -> IOC:
    """Classify a raw input string into an IOC.

    Order matters: hashes and IPs are unambiguous, so check them first. A string
    with a URL scheme (http://, ftp://, ...) is a URL. Everything left that looks
    like a hostname is a domain; otherwise UNKNOWN.
    """
    raw = value.strip()

    if not raw:
        return IOC(value=value, type=IOCType.UNKNOWN)

    # Hash: pure hex of a known length.
    if _HASH_RE.match(raw):
        return IOC(value=raw, type=IOCType.HASH)

    # IP address (v4 or v6), bare — no scheme.
    if _is_ip(raw):
        return IOC(value=raw, type=IOCType.IP)

    # URL: has a scheme and a network location.
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return IOC(value=raw, type=IOCType.URL)

    # Domain: hostname-like, no scheme/path.
    if _DOMAIN_RE.match(raw):
        return IOC(value=raw, type=IOCType.DOMAIN)

    return IOC(value=raw, type=IOCType.UNKNOWN)
