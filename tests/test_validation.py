import pytest

from custom_components.headscale_monitor.validation import normalize_url


def test_normalize_url_rejects_embedded_credentials() -> None:
    with pytest.raises(ValueError, match="credentials"):
        normalize_url("https://user:pass@headscale.example")


def test_normalize_url_requires_https() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        normalize_url("http://headscale.example")
