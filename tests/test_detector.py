
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

def test_report_contains_expected_fields():
    report = analyze_url("https://paypal.com@evil.example/login")

    assert report["url"] == "https://paypal.com@evil.example/login"
    assert report["risk_score"] == 20
    assert report["features"]["hostname"] == "evil.example"
    assert report["features"]["has_at_symbol"] is True
    assert report["findings"][0]["rule"] == "AT_SYMBOL"
    assert "not a probability" in report["note"]

def test_suspicious_keyword_triggers_finding():
    report = analyze_url(
        "https://example.com/verify-account"
    )

    rules = [item["rule"] for item in report["findings"]]

    assert "SUSPICIOUS_KEYWORD" in rules
    assert report["risk_score"] == 5

def test_punycode_hostname_triggers_finding():
    report = analyze_url("https://xn--e1afmkfd.example/login")

    rules = [item["rule"] for item in report["findings"]]

    assert "PUNYCODE_HOST" in rules
    assert report["risk_score"] == 5

