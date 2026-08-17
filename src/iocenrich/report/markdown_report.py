"""Render a Report as Markdown."""

from __future__ import annotations

from ..models import Report

_EMOJI = {
    "clean": "✅",
    "suspicious": "⚠️",
    "malicious": "🛑",
    "unknown": "❔",
}


def render(report: Report) -> str:
    ioc = report.ioc
    verdict = report.verdict.value
    emoji = _EMOJI.get(verdict, "")

    lines = [
        f"# IOC Report: `{ioc.value}`",
        "",
        f"- **Type:** {ioc.type.value}",
        f"- **Verdict:** {emoji} **{verdict.upper()}**",
        f"- **Score:** {report.score:.2f}",
        "",
        "## Providers",
        "",
        "| Provider | Score | Detail |",
        "| --- | --- | --- |",
    ]

    for r in report.results:
        if r.success:
            score = "-" if r.score is None else f"{r.score:.2f}"
            detail = r.summary or "-"
        else:
            score = "error"
            detail = r.error or "-"
        lines.append(f"| {r.provider} | {score} | {detail} |")

    return "\n".join(lines) + "\n"
