"""AbuseIPDB provider — requires ABUSEIPDB_API_KEY. IP only.

Score is abuseConfidenceScore (0-100) normalized to 0.0-1.0.
"""

from __future__ import annotations

import os

import httpx

from ..models import IOC, IOCType, ProviderResult
from .base import BaseProvider

_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 15.0


class AbuseIPDBProvider(BaseProvider):
    name = "abuseipdb"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.IP

    def query(self, ioc: IOC) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=False,
                error="ABUSEIPDB_API_KEY not set",
            )

        try:
            resp = httpx.get(
                _URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ioc.value, "maxAgeInDays": 90},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=False, error=str(exc)
            )

        data = payload.get("data", {})
        confidence = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=True,
            score=confidence / 100.0,
            summary=f"Abuse confidence {confidence}% ({reports} reports)",
            raw=payload,
        )
