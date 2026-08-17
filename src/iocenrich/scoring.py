"""Combine provider results into a single, explainable verdict.

The model has two parts:

1. **Weighted average** — providers are not equally trustworthy. URLhaus only
   lists confirmed malware distribution, so a hit there is high-signal; AbuseIPDB
   is crowd-sourced and noisier. Each provider's score is weighted accordingly.

2. **Escalation rule** — a plain average can bury one very confident source under
   several quiet ones. So if *any* provider is highly confident (score >=
   HIGH_CONFIDENCE), the verdict is forced to at least SUSPICIOUS, even if the
   weighted average alone would read CLEAN. This favors "don't miss a real
   threat" over "keep the average tidy."
"""

from __future__ import annotations

from .models import IOC, ProviderResult, Report, Verdict

# Thresholds on the weighted score (0.0 = clean, 1.0 = malicious).
SUSPICIOUS_AT = 0.2
MALICIOUS_AT = 0.6

# A single provider at or above this is treated as a strong signal on its own.
HIGH_CONFIDENCE = 0.8

# How much each provider's opinion counts. Unlisted providers default to 1.0.
PROVIDER_WEIGHTS = {
    "urlhaus": 1.5,     # confirmed malware distribution — high signal
    "virustotal": 1.2,  # many AV engines — fairly trustworthy
    "abuseipdb": 1.0,   # crowd-sourced reports — noisier baseline
}


def score_to_verdict(score: float) -> Verdict:
    """Map a combined 0.0-1.0 score to a human-readable verdict."""
    if score >= MALICIOUS_AT:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def _weight(provider: str) -> float:
    return PROVIDER_WEIGHTS.get(provider, 1.0)


def aggregate(ioc: IOC, results: list[ProviderResult]) -> Report:
    """Turn multiple provider signals into one weighted, escalated verdict.

    Only successful results that expressed an opinion (score is not None) count.
    If nobody had an opinion, the verdict is UNKNOWN. The per-provider results
    stay attached to the Report so the verdict is always explainable.
    """
    opinions = [(r.provider, r.score) for r in results if r.success and r.score is not None]

    if not opinions:
        return Report(ioc=ioc, verdict=Verdict.UNKNOWN, score=0.0, results=results)

    total_weight = sum(_weight(p) for p, _ in opinions)
    weighted = sum(score * _weight(p) for p, score in opinions) / total_weight

    verdict = score_to_verdict(weighted)

    # Escalation: a single high-confidence hit guarantees at least SUSPICIOUS.
    if verdict == Verdict.CLEAN and any(score >= HIGH_CONFIDENCE for _, score in opinions):
        verdict = Verdict.SUSPICIOUS

    return Report(ioc=ioc, verdict=verdict, score=weighted, results=results)
