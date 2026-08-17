"""Tests for the scoring/aggregation logic."""

from iocenrich.models import IOC, IOCType, ProviderResult, Verdict
from iocenrich.scoring import aggregate


def _ip_results(scores: dict[str, float | None]) -> list[ProviderResult]:
    ioc = IOC("1.2.3.4", IOCType.IP)
    return [
        ProviderResult(name, ioc, success=True, score=score)
        for name, score in scores.items()
    ]


def test_all_clean_is_clean():
    ioc = IOC("8.8.8.8", IOCType.IP)
    results = [ProviderResult("vt", ioc, success=True, score=0.0)]
    report = aggregate(ioc, results)
    assert report.verdict == Verdict.CLEAN


def test_high_score_is_malicious():
    ioc = IOC("evil.com", IOCType.DOMAIN)
    results = [ProviderResult("vt", ioc, success=True, score=0.9)]
    report = aggregate(ioc, results)
    assert report.verdict == Verdict.MALICIOUS


def test_no_opinions_is_unknown():
    ioc = IOC("1.2.3.4", IOCType.IP)
    results = [ProviderResult("vt", ioc, success=False, error="key not set")]
    report = aggregate(ioc, results)
    assert report.verdict == Verdict.UNKNOWN


def test_urlhaus_is_weighted_higher_than_abuseipdb():
    # Same two scores, swapped between providers. URLhaus carries more weight,
    # so the run where URLhaus holds the high score must score higher overall.
    urlhaus_high = aggregate(
        IOC("1.2.3.4", IOCType.IP), _ip_results({"urlhaus": 0.8, "abuseipdb": 0.2})
    )
    abuseipdb_high = aggregate(
        IOC("1.2.3.4", IOCType.IP), _ip_results({"urlhaus": 0.2, "abuseipdb": 0.8})
    )
    assert urlhaus_high.score > abuseipdb_high.score


def test_single_high_confidence_hit_escalates_from_clean():
    # One loud source (0.85) drowned out by many quiet ones: the weighted
    # average lands below the CLEAN cutoff, but the escalation rule must still
    # force at least SUSPICIOUS because one provider is highly confident.
    results = _ip_results(
        {"urlhaus": 0.85, "q1": 0.0, "q2": 0.0, "q3": 0.0, "q4": 0.0, "q5": 0.0}
    )
    report = aggregate(IOC("1.2.3.4", IOCType.IP), results)
    assert report.score < 0.2  # would read CLEAN on the average alone
    assert report.verdict == Verdict.SUSPICIOUS  # escalated
