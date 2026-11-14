import pytest

from custom_components.headscale_monitor.validation import normalize_url, validate_entry_transport


def test_normalize_url_rejects_embedded_credentials() -> None:
    with pytest.raises(ValueError, match="credentials"):
        normalize_url("https://user:pass@headscale.example")


def test_normalize_url_requires_https() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        normalize_url("http://headscale.example")


def test_existing_entry_transport_rejects_legacy_insecure_values() -> None:
    assert validate_entry_transport({"url": "https://hs.example"}) == "https://hs.example"
    with pytest.raises(ValueError, match="HTTPS"):
        validate_entry_transport({"url": "http://hs.example"})
    with pytest.raises(ValueError, match="certificate verification"):
        validate_entry_transport({"url": "https://hs.example", "verify_tls": False})
