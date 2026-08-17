"""Orchestrates: query supporting providers -> score -> Report."""

from __future__ import annotations

from . import scoring
from .models import IOC, ProviderResult, Report
from .providers.base import BaseProvider


class Engine:
    def __init__(self, providers: list[BaseProvider]) -> None:
        self.providers = providers

    def enrich(self, ioc: IOC) -> Report:
        """Ask every provider that supports this IOC, then aggregate a verdict.

        A provider that raises is caught and recorded as a failed result, so one
        broken/offline provider never crashes the whole run.
        """
        results: list[ProviderResult] = []
        for provider in self.providers:
            if not provider.supports(ioc.type):
                continue
            try:
                results.append(provider.query(ioc))
            except Exception as exc:  # noqa: BLE001 - defensive: isolate provider failures
                results.append(
                    ProviderResult(
                        provider=provider.name,
                        ioc=ioc,
                        success=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )

        return scoring.aggregate(ioc, results)
