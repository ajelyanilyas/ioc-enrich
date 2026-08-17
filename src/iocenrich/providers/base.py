"""Abstract provider interface. Every intel source implements this."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import IOC, IOCType, ProviderResult


class BaseProvider(ABC):
    name: str = "base"

    @abstractmethod
    def supports(self, ioc_type: IOCType) -> bool:
        """Return True if this provider can handle the given IOC type."""

    @abstractmethod
    def query(self, ioc: IOC) -> ProviderResult:
        """Look up the IOC and return a normalized ProviderResult."""
