
from app.detector import analyze_url


def test_ip_host_and_http_trigger_findings():
    report = analyze_url("http://192.0.2.1/login")

    assert report["risk_score"] == 35

    rules = [item["rule"] for item in report["findings"]]

    assert "IP_ADDRESS_HOST" in rules
    assert "NO_HTTPS" in rules


def test_https_domain_has_no_findings():
    report = analyze_url("https://www.python.org/")

    assert report["risk_score"] == 0
    assert report["findings"] == []


def test_at_symbol_triggers_finding():
    report = analyze_url(
        "https://example.com@evil.example/login"
    )

    rules = [item["rule"] for item in report["findings"]]

    assert "AT_SYMBOL" in rules


def test_many_subdomains_triggers_finding():
    report = analyze_url(
        "https://login.verify.account.example.com/signin"
    )

    rule_names = [
        finding["rule"]
        for finding in report["findings"]
    ]

    assert "MANY_SUBDOMAINS" in rule_names
    
def test_url_shortener_triggers_finding():
    report = analyze_url("https://bit.ly/example")

    rules = [item["rule"] for item in report["findings"]]

    assert "URL_SHORTENER" in rules

