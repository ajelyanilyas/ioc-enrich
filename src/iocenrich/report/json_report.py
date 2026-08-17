"""Render a Report as JSON."""

from __future__ import annotations

import json

from ..models import Report


def to_dict(report: Report) -> dict:
    """Convert a Report into plain JSON-serializable data."""
    return {
        "ioc": report.ioc.value,
        "type": report.ioc.type.value,
        "verdict": report.verdict.value,
        "score": round(report.score, 3),
        "providers": [
            {
                "provider": r.provider,
                "success": r.success,
                "score": r.score,
                "summary": r.summary,
                "error": r.error,
            }
            for r in report.results
        ],
    }


def render(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2)
