
import csv
import io


def generate_csv_report(report: dict) -> str:
    """Convert a PhishGuard analysis report into CSV text."""

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)

    writer.writerow([
        "URL",
        "Risk Score",
        "Rule",
        "Severity",
        "Reason",
    ])

    if report["findings"]:
        for finding in report["findings"]:
            writer.writerow([
                report["url"],
                report["risk_score"],
                finding["rule"],
                finding["severity"],
                finding["reason"],
            ])
    else:
        writer.writerow([
            report["url"],
            report["risk_score"],
            "NONE",
            "none",
            "No current rules were triggered.",
        ])

    return csv_buffer.getvalue()
