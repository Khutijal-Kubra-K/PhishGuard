
import csv
import io

from app.detector import analyze_url
from app.report_export import generate_csv_report


def test_csv_report_contains_finding():
    report = analyze_url(
        "https://example.com@evil.example/login"
    )

    csv_text = generate_csv_report(report)
    rows = list(csv.reader(io.StringIO(csv_text)))

    assert rows[0] == [
        "URL",
        "Risk Score",
        "Rule",
        "Severity",
        "Reason",
    ]

    assert rows[1][1] == "20"
    assert rows[1][2] == "AT_SYMBOL"
    assert rows[1][3] == "medium"


def test_csv_report_handles_no_findings():
    report = analyze_url("https://www.python.org/")

    csv_text = generate_csv_report(report)
    rows = list(csv.reader(io.StringIO(csv_text)))

    assert len(rows) == 2
    assert rows[1][1] == "0"
    assert rows[1][2] == "NONE"
    assert rows[1][3] == "none"

