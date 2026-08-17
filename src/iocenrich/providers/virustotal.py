"""VirusTotal provider — requires VIRUSTOTAL_API_KEY.

Uses the VT v3 API. The score is the fraction of AV engines that flagged the
IOC as malicious or suspicious (last_analysis_stats).
"""

from __future__ import annotations

import base64
import os

import httpx

from ..models import IOC, IOCType, ProviderResult
from .base import BaseProvider

_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15.0


class VirusTotalProvider(BaseProvider):
    name = "virustotal"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH}

    def _path_for(self, ioc: IOC) -> str | None:
        if ioc.type == IOCType.IP:
            return f"ip_addresses/{ioc.value}"
        if ioc.type == IOCType.DOMAIN:
            return f"domains/{ioc.value}"
        if ioc.type == IOCType.HASH:
            return f"files/{ioc.value}"
        if ioc.type == IOCType.URL:
            # VT identifies URLs by a base64url of the URL, no padding.
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
            return f"urls/{url_id}"
        return None

    def query(self, ioc: IOC) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                success=False,
                error="VIRUSTOTAL_API_KEY not set",
            )

        path = self._path_for(ioc)
        if path is None:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=False,
                error=f"virustotal does not handle {ioc.type.value}",
            )

        try:
            resp = httpx.get(
                f"{_BASE}/{path}",
                headers={"x-apikey": self.api_key},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 404:
                return ProviderResult(
                    provider=self.name, ioc=ioc, success=True, score=0.0,
                    summary="Not found in VirusTotal",
                )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=False, error=str(exc)
            )

        return self._parse(ioc, payload)

    def _parse(self, ioc: IOC, payload: dict) -> ProviderResult:
        stats = (
            payload.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 0

        if total == 0:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=True, score=0.0,
                summary="No analysis data", raw=payload,
            )

        score = (malicious + suspicious) / total
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=True,
            score=score,
            summary=f"{malicious}/{total} engines flagged malicious",
            raw=payload,
        )
