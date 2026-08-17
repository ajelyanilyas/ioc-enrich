"""Tests for the JSON and Markdown report renderers."""

import json

from iocenrich.models import IOC, IOCType, ProviderResult, Report, Verdict
from iocenrich.report import json_report, markdown_report


def _sample_report() -> Report:
    ioc = IOC("123.14.127.32", IOCType.IP)
    results = [
        ProviderResult("urlhaus", ioc, success=True, score=0.85, summary="Listed"),
        ProviderResult("abuseipdb", ioc, success=False, error="key not set"),
    ]
    return Report(ioc=ioc, verdict=Verdict.MALICIOUS, score=0.85, results=results)


def test_json_report_is_valid_json():
    data = json.loads(json_report.render(_sample_report()))
    assert data["verdict"] == "malicious"
    assert data["type"] == "ip"
    assert len(data["providers"]) == 2


def test_markdown_report_has_headers_and_verdict():
    md = markdown_report.render(_sample_report())
    assert "# IOC Report" in md
    assert "MALICIOUS" in md
    assert "| urlhaus |" in md
