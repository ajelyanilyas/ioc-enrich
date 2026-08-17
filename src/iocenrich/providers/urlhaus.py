"""URLhaus (abuse.ch) provider.

URLhaus tracks URLs, domains/IPs, and file hashes involved in malware
distribution. abuse.ch now asks API users to authenticate with a free
Auth-Key; if ABUSE_CH_API_KEY is set we send it, otherwise we still try
(and report a clear error if the API rejects the request).
"""

from __future__ import annotations

import os

import httpx

from ..models import IOC, IOCType, ProviderResult
from .base import BaseProvider

_BASE = "https://urlhaus-api.abuse.ch/v1"
_TIMEOUT = 10.0


class URLhausProvider(BaseProvider):
    name = "urlhaus"

    def __init__(self, api_key: str | None = None) -> None:
        # Fall back to the environment so callers don't have to pass it.
        self.api_key = api_key or os.getenv("ABUSE_CH_API_KEY")

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {IOCType.URL, IOCType.DOMAIN, IOCType.IP, IOCType.HASH}

    def query(self, ioc: IOC) -> ProviderResult:
        endpoint, data = self._request_for(ioc)
        if endpoint is None:
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                success=False,
                error=f"urlhaus does not handle {ioc.type.value}",
            )

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            resp = httpx.post(
                f"{_BASE}/{endpoint}/",
                data=data,
                headers=headers,
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=False, error=str(exc)
            )

        return self._parse(ioc, payload)

    def _request_for(self, ioc: IOC) -> tuple[str | None, dict]:
        """Pick the right URLhaus endpoint and POST body for this IOC."""
        if ioc.type == IOCType.URL:
            return "url", {"url": ioc.value}
        if ioc.type in {IOCType.DOMAIN, IOCType.IP}:
            return "host", {"host": ioc.value}
        if ioc.type == IOCType.HASH:
            key = "sha256_hash" if len(ioc.value) == 64 else "md5_hash"
            return "payload", {key: ioc.value}
        return None, {}

    def _parse(self, ioc: IOC, payload: dict) -> ProviderResult:
        status = payload.get("query_status")

        # Known-clean: abuse.ch has simply never seen it.
        if status == "no_results":
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                success=True,
                score=0.0,
                summary="Not listed in URLhaus",
                raw=payload,
            )

        # Anything other than a clean "ok" is an API-level problem.
        if status != "ok":
            return ProviderResult(
                provider=self.name,
                ioc=ioc,
                success=False,
                error=f"URLhaus query_status={status}",
                raw=payload,
            )

        # Listed in URLhaus -> malware-related. Online threats score highest.
        threat = payload.get("threat") or payload.get("signature") or "malware"
        online = payload.get("url_status") == "online"
        url_count = payload.get("url_count")

        score = 1.0 if online else 0.85
        if url_count:
            summary = f"Listed in URLhaus: {threat} ({url_count} URLs)"
        else:
            state = payload.get("url_status", "listed")
            summary = f"Listed in URLhaus: {threat} ({state})"

        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=True,
            score=score,
            summary=summary,
            raw=payload,
        )
