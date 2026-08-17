"""Core data structures shared across the app."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    """A single indicator of compromise."""

    value: str
    type: IOCType


@dataclass
class ProviderResult:
    """What one provider returns about one IOC."""

    provider: str
    ioc: IOC
    success: bool
    # 0.0 = clean, 1.0 = definitely malicious. None if provider had no opinion.
    score: float | None = None
    summary: str = ""
    raw: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class Report:
    """Aggregated result for one IOC across all providers."""

    ioc: IOC
    verdict: Verdict
    score: float
    results: list[ProviderResult] = field(default_factory=list)
