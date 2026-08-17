"""Provider tests — HTTP is mocked so CI never hits live APIs."""

import httpx
import respx

from iocenrich.detector import detect
from iocenrich.models import IOCType
from iocenrich.providers.urlhaus import URLhausProvider


def test_urlhaus_supports():
    p = URLhausProvider()
    assert p.supports(IOCType.URL)
    assert p.supports(IOCType.IP)
    assert p.supports(IOCType.HASH)


@respx.mock
def test_urlhaus_listed_url_is_malicious():
    # Pretend URLhaus knows this URL and it's an online threat.
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200,
            json={"query_status": "ok", "threat": "malware_download", "url_status": "online"},
        )
    )

    result = URLhausProvider().query(detect("http://evil.example/bad.exe"))

    assert result.success
    assert result.score == 1.0
    assert "malware_download" in result.summary


@respx.mock
def test_urlhaus_unknown_host_is_clean():
    # Pretend URLhaus has never seen this host.
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )

    result = URLhausProvider().query(detect("example.com"))

    assert result.success
    assert result.score == 0.0
