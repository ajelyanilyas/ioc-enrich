"""Tests for IOC type detection. Write these first — they drive detector.py."""

import pytest

from iocenrich.detector import detect
from iocenrich.models import IOCType


@pytest.mark.parametrize(
    "value, expected",
    [
        ("8.8.8.8", IOCType.IP),
        ("example.com", IOCType.DOMAIN),
        ("https://example.com/path", IOCType.URL),
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.HASH),  # md5
    ],
)
def test_detect(value, expected):
    assert detect(value).type == expected
