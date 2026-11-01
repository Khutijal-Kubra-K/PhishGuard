
import csv
import io

from app.detector import analyze_url
from app.report_export import generate_csv_report


EXPECTED_HEADERS = [
    "URL",
    "Risk Score",
    "Threat Intelligence Status",
    "Threat Types",
    "Threat Intelligence Message",
    "Rule",
    "Severity",
    "Reason",
]


def parse_csv(csv_text):
    return list(csv.reader(io.StringIO(csv_text)))


def test_csv_report_contains_finding():
    report = analyze_url("https://example.com@evil.example/login")

    csv_text = generate_csv_report(report)
    rows = parse_csv(csv_text)

    assert rows[0] == EXPECTED_HEADERS
    assert rows[1][0] == report["url"]
    assert rows[1][1] == "20"
    assert rows[1][2] == "not_checked"
    assert rows[1][5] == "AT_SYMBOL"
    assert rows[1][6] == "medium"


def test_csv_report_handles_no_findings():
    report = analyze_url("https://www.python.org/")

    csv_text = generate_csv_report(report)
    rows = parse_csv(csv_text)

    assert len(rows) == 2
    assert rows[0] == EXPECTED_HEADERS
    assert rows[1][1] == "0"
    assert rows[1][5] == "NONE"
    assert rows[1][6] == "none"


def test_csv_report_includes_reputation_details():
    report = analyze_url("https://example.com/")
    report["reputation"] = {
        "status": "unsafe",
        "message": "Google Safe Browsing identified a known threat.",
        "threat_types": ["SOCIAL_ENGINEERING", "MALWARE"],
    }

    rows = parse_csv(generate_csv_report(report))

    assert rows[0] == EXPECTED_HEADERS
    assert rows[1][2] == "unsafe"
    assert rows[1][3] == "SOCIAL_ENGINEERING, MALWARE"
    assert rows[1][4] == (
        "Google Safe Browsing identified a known threat."
    )


def test_csv_report_handles_reputation_error():
    report = analyze_url("https://example.com/")
    report["reputation"] = {
        "status": "error",
        "message": "Threat intelligence unavailable.",
        "threat_types": [],
    }

    rows = parse_csv(generate_csv_report(report))

    assert rows[1][2] == "error"
    assert rows[1][3] == ""
    assert rows[1][4] == "Threat intelligence unavailable."
