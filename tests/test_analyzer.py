
import pytest
from app.analyzer import extract_features


def test_ip_address_host():
    result = extract_features("http://192.0.2.1/login")

    assert result["hostname"] == "192.0.2.1"
    assert result["has_ip_host"] is True
    assert result["uses_https"] is False
    assert result["subdomain_count"] == 0


def test_https_domain():
    result = extract_features("https://www.python.org/")

    assert result["hostname"] == "www.python.org"
    assert result["uses_https"] is True
    assert result["has_ip_host"] is False
    assert result["subdomain_count"] == 1


def test_missing_scheme():
    result = extract_features("example.com")

    assert result["hostname"] == "example.com"
    assert result["uses_https"] is True


def test_empty_url():
    with pytest.raises(ValueError):
        extract_features("")


def test_at_symbol():
    result = extract_features(
        "https://example.com@evil.example/login"
    )

    assert result["hostname"] == "evil.example"
    assert result["has_at_symbol"] is True

import pytest
from app.analyzer import extract_features


def test_rejects_empty_url():
    with pytest.raises(ValueError, match="empty"):
        extract_features("")


def test_rejects_whitespace_only_url():
    with pytest.raises(ValueError, match="empty"):
        extract_features("   ")


def test_rejects_url_without_hostname():
    with pytest.raises(ValueError, match="hostname"):
        extract_features("https:///")


def test_rejects_unsupported_scheme():
    import pytest
    from app.analyzer import extract_features

    with pytest.raises(ValueError):
        extract_features("ftp://example.com")


def test_rejects_missing_hostname():
    import pytest
    from app.analyzer import extract_features

    with pytest.raises(ValueError):
        extract_features("https://")

def test_hostname_with_whitespace_is_rejected():
    import pytest
    from app.analyzer import extract_features

    with pytest.raises(ValueError, match="whitespace"):
        extract_features("https://exa mple.com")


def test_hostname_label_starting_with_hyphen_is_rejected():
    import pytest
    from app.analyzer import extract_features

    with pytest.raises(ValueError, match="hyphen"):
        extract_features("https://-example.com")
def test_empty_hostname_label_is_rejected():
    import pytest
    from app.analyzer import extract_features

    with pytest.raises(ValueError, match="empty label"):
        extract_features("https://example..com")