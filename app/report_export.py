
import csv
import io


def generate_csv_report(report: dict) -> str:
    """Convert a PhishGuard analysis report into CSV text."""

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)

    reputation = report.get("reputation", {})
    reputation_status = reputation.get("status", "not_checked")
    reputation_message = reputation.get(
        "message",
        "Threat intelligence was not checked.",
    )
    threat_types = ", ".join(reputation.get("threat_types", []))

    writer.writerow([
        "URL",
        "Risk Score",
        "Threat Intelligence Status",
        "Threat Types",
        "Threat Intelligence Message",
        "Rule",
        "Severity",
        "Reason",
    ])

    common_fields = [
        report["url"],
        report["risk_score"],
        reputation_status,
        threat_types,
        reputation_message,
    ]

    if report["findings"]:
        for finding in report["findings"]:
            writer.writerow(
                common_fields + [
                    finding["rule"],
                    finding["severity"],
                    finding["reason"],
                ]
            )
    else:
        writer.writerow(
            common_fields + [
                "NONE",
                "none",
                "No current rules were triggered.",
            ]
        )

    return csv_buffer.getvalue()
